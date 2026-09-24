// Package novelty's primary detection mechanism is dictionary-assisted
// zstd compression (see ncd.go). This file adds a SEPARATE, independent
// secondary measurement using compress/flate (DEFLATE) instead, as a
// cross-check -- not a replacement.
//
// WHY A SECOND COMPRESSOR AT ALL: zstd and DEFLATE are both LZ77-family
// compressors, but differ enough in match-finding and entropy coding
// (zstd: larger practical window, FSE/tANS entropy coding; DEFLATE: hard
// 32KB window, static/dynamic Huffman) that they don't always agree on
// how novel a given payload is. Confirmed empirically before building
// this, not assumed: on the same synthetic redundant-vs-anomalous pair
// used throughout this project's testing, zstd separated the two by
// 0.380 (0.245 -> 0.625) while DEFLATE separated them by 0.429 (0.130 ->
// 0.559) -- same direction, meaningfully different magnitude. That gap
// is exactly the kind of thing a single-compressor system can't see:
// disagreement between two independent measurements is itself a signal,
// not just noise to average away.
//
// WHY A SEPARATE IMPLEMENTATION rather than refactoring Scorer into a
// pluggable-compressor interface: Scorer has real bugs found and fixed
// across three separate revisions (see ncd.go's package doc), each
// caught only after significant testing investment. Refactoring working,
// hard-won code into a generic interface for an optional secondary
// feature risks disturbing that correctness for marginal architectural
// elegance. Some duplication between this file and ncd.go is the
// deliberate, safer tradeoff.
//
// CAVEAT, documented rather than hidden: DEFLATE's dictionary window is
// hard-capped at 32KB by the format itself -- compress/flate silently
// uses only the last 32KB of a longer dict, with no error. At the
// default WindowSize (128 events, ~13-14KB of baseline observed in
// testing), this never matters. A much larger WindowSize could exceed
// it, silently truncating older baseline content from THIS scorer's
// perspective only -- the primary zstd-based Scorer has no such limit,
// so the two scorers' effective baselines could diverge under an
// aggressively large WindowSize configuration. Not a concern at the
// shipped default.
package novelty

import (
	"bytes"
	"compress/flate"
	"sync"
)

// SecondaryScorer mirrors Scorer's dict-assisted ratio mechanism
// (compress payload alone vs. with the baseline as a raw dictionary),
// backed by DEFLATE instead of zstd. Safe for concurrent use.
type SecondaryScorer struct {
	mu sync.Mutex

	window     [][]byte
	windowSize int
	cursor     int
	filled     bool

	baseline []byte
	dirty    bool
}

func NewSecondaryScorer(cfg Config) *SecondaryScorer {
	windowSize := cfg.WindowSize
	if windowSize <= 0 {
		windowSize = 128
	}
	return &SecondaryScorer{
		window:     make([][]byte, windowSize),
		windowSize: windowSize,
	}
}

func deflateCompress(payload, dict []byte) int {
	var buf bytes.Buffer
	var w *flate.Writer
	if dict != nil {
		w, _ = flate.NewWriterDict(&buf, flate.BestCompression, dict)
	} else {
		w, _ = flate.NewWriter(&buf, flate.BestCompression)
	}
	w.Write(payload)
	w.Close()
	return buf.Len()
}

// Score returns this scorer's independent novelty ratio for payload
// against its own baseline window. Same [0,1]-ish semantics as Scorer.Score
// (clamped), but computed via an entirely separate DEFLATE-based baseline
// -- NOT sharing state with the primary zstd-based Scorer for the same
// source, by design, so the two measurements are genuinely independent
// rather than two views into the same internal window.
func (s *SecondaryScorer) Score(payload []byte) float64 {
	s.mu.Lock()
	baseline := s.snapshotLocked()
	s.mu.Unlock()

	cAlone := deflateCompress(payload, nil)
	if cAlone == 0 {
		return 0
	}
	if len(baseline) == 0 {
		return 1.0
	}

	cWithDict := deflateCompress(payload, baseline)
	score := float64(cWithDict) / float64(cAlone)
	if score > 1 {
		score = 1
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (s *SecondaryScorer) Observe(payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(payload))
	copy(cp, payload)
	s.window[s.cursor] = cp
	s.cursor = (s.cursor + 1) % s.windowSize
	if s.cursor == 0 {
		s.filled = true
	}
	s.dirty = true
}

func (s *SecondaryScorer) snapshotLocked() []byte {
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

// SecondaryManager mirrors Manager, keyed the same way (callers should
// use the SAME source keys as the primary Manager -- e.g. ingest.ScoringKey
// -- so the two scorers see the same event stream per source, just
// through independent windows/compressors).
type SecondaryManager struct {
	mu      sync.RWMutex
	scorers map[string]*SecondaryScorer
	cfg     Config
}

func NewSecondaryManager(cfg Config) *SecondaryManager {
	return &SecondaryManager{
		scorers: make(map[string]*SecondaryScorer),
		cfg:     cfg,
	}
}

func (m *SecondaryManager) getOrCreate(source string) *SecondaryScorer {
	m.mu.RLock()
	s, ok := m.scorers[source]
	m.mu.RUnlock()
	if ok {
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.scorers[source]; ok {
		return s
	}
	s = NewSecondaryScorer(m.cfg)
	m.scorers[source] = s
	return s
}

func (m *SecondaryManager) PeekScore(source string, payload []byte) float64 {
	return m.getOrCreate(source).Score(payload)
}

func (m *SecondaryManager) Observe(source string, payload []byte) {
	m.getOrCreate(source).Observe(payload)
}
