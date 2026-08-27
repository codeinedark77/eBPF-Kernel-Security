// Package novelty implements compression-based novelty detection.
//
// Core idea: score how much of an event's own complexity survives after
// the compressor is given the recent baseline as context, using a real
// compressor as a stand-in for the (uncomputable) Kolmogorov complexity
// of "payload given baseline":
//
//	score(payload | baseline) = C_dict(payload | baseline) / C(payload)
//
// where C(payload) is payload's compressed size alone, and
// C_dict(payload | baseline) is payload's compressed size when the
// compressor is given baseline as a raw prefix dictionary (zstd's
// "initial history" mechanism) -- a single compression pass, not two
// buffers diffed against each other. If payload is redundant with the
// baseline, the dictionary lets the compressor reference it almost for
// free, so C_dict is small relative to C(payload) alone -> score near 0.
// If payload is genuinely novel, the dictionary doesn't help -> C_dict
// approaches C(payload) -> score near 1.
//
// REVISION HISTORY (both real bugs, found and fixed during testing, kept
// here because the failure modes are instructive):
//
//  1. First version used textbook symmetric NCD, (C(xy)-min(C(x),C(y)))
//     / max(C(x),C(y)), comparing the single payload directly against the
//     whole concatenated baseline. Since baseline (up to ~128 events) is
//     far bigger than any single payload, using C(baseline) as the
//     denominator made scores drift toward 1 purely as the window filled,
//     independent of actual similarity.
//
//  2. Second version fixed #1 by dividing marginal cost -- C(baseline+
//     payload) - C(baseline) -- by C(payload) instead. That fixed the
//     drift, but introduced a subtler problem: computing marginal cost by
//     diffing two *separately compressed* buffers of different sizes is
//     noisy, because zstd's block splitting and entropy table boundaries
//     shift as the baseline grows, and that shift doesn't scale to zero
//     as marginal cost shrinks. A controlled test with intentionally
//     redundant, stationary traffic showed the "novelty" score drifting
//     from a mean of 0.53 to 0.87 over 100 events with no change in the
//     actual data distribution -- i.e. the noise floor was comparable to
//     the signal we were trying to measure.
//
// This version (#3) replaces the two-buffer diff with a single dict-
// assisted compression, which a standalone experiment confirmed stays
// flat (normal ~0.22-0.25, synthetic anomaly ~0.61-0.63) across a baseline
// growing from 2KB to 14KB -- no drift, because there's no diff of two
// independently-compressed buffers to introduce block-boundary noise.
package novelty

import (
	"bytes"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Scorer maintains a rolling baseline window and scores new events
// against it via dictionary-assisted compression. It is safe for
// concurrent use.
type Scorer struct {
	mu sync.Mutex

	window     [][]byte // ring buffer of recent raw event payloads
	windowSize int      // max events retained in the baseline window
	cursor     int
	filled     bool

	baseline []byte // concatenated snapshot of the window, rebuilt lazily
	dirty    bool

	plainEncoder *zstd.Encoder // no dictionary -- for C(payload) alone
}

// Config controls scorer behavior.
type Config struct {
	// WindowSize is how many recent events form the "normal" baseline.
	// Larger = slower drift to detect long-run behavior change, smaller =
	// more sensitive to recent-only context. 64-256 is a reasonable start.
	WindowSize int
}

func NewScorer(cfg Config) (*Scorer, error) {
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 128
	}
	plain, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		return nil, err
	}
	return &Scorer{
		window:       make([][]byte, cfg.WindowSize),
		windowSize:   cfg.WindowSize,
		plainEncoder: plain,
	}, nil
}

func (s *Scorer) Close() error {
	return s.plainEncoder.Close()
}

// Score returns the novelty of payload against the current baseline
// window, in [0, 1] (clamped -- dict-assisted compression can very
// rarely come out a byte or two above the solo size on tiny inputs due
// to dictionary-id framing overhead). It does NOT mutate the window --
// call Observe separately, or use ScoreAndObserve for the common case.
func (s *Scorer) Score(payload []byte) float64 {
	s.mu.Lock()
	baseline := s.snapshotLocked()
	s.mu.Unlock()

	cAlone := len(s.plainEncoder.EncodeAll(payload, nil))
	if cAlone == 0 {
		return 0
	}
	if len(baseline) == 0 {
		// No baseline yet: first event is definitionally novel.
		return 1.0
	}

	// Fresh encoder per call: the dictionary (baseline) changes every
	// event, and this library's dict is fixed at encoder-construction
	// time. Baseline is capped at WindowSize events (~tens of KB in
	// practice), so this allocation is cheap relative to a network round
	// trip; not worth the complexity of a pooled/reused encoder yet.
	dictEnc, err := zstd.NewWriter(nil,
		zstd.WithEncoderDictRaw(1, baseline),
		zstd.WithEncoderLevel(zstd.SpeedBestCompression),
	)
	if err != nil {
		// Shouldn't happen with valid options; fail safe by treating the
		// event as fully novel rather than silently under-scoring it.
		return 1.0
	}
	defer dictEnc.Close()

	cWithDict := len(dictEnc.EncodeAll(payload, nil))

	score := float64(cWithDict) / float64(cAlone)
	if score > 1 {
		score = 1
	}
	if score < 0 {
		score = 0
	}
	return score
}

// Observe adds payload to the rolling baseline window, evicting the oldest
// entry once full (ring buffer semantics).
func (s *Scorer) Observe(payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observeLocked(payload)
}

func (s *Scorer) observeLocked(payload []byte) {
	cp := make([]byte, len(payload))
	copy(cp, payload)

	s.window[s.cursor] = cp
	s.cursor = (s.cursor + 1) % s.windowSize
	if s.cursor == 0 {
		s.filled = true
	}
	s.dirty = true
}

// snapshotLocked rebuilds the concatenated baseline buffer if stale.
// Caller must hold s.mu.
func (s *Scorer) snapshotLocked() []byte {
	if !s.dirty && s.baseline != nil {
		return s.baseline
	}
	n := s.cursor
	if s.filled {
		n = s.windowSize
	}
	var buf bytes.Buffer
	for i := 0; i < n; i++ {
		if s.window[i] != nil {
			buf.Write(s.window[i])
			buf.WriteByte('\n')
		}
	}
	s.baseline = buf.Bytes()
	s.dirty = false
	return s.baseline
}

// ScoreAndObserve is the typical hot-path call: score against current
// baseline, then fold the event into the baseline for future comparisons.
func (s *Scorer) ScoreAndObserve(payload []byte) float64 {
	score := s.Score(payload)
	s.Observe(payload)
	return score
}
