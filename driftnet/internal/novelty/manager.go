package novelty

import "sync"

// Manager keeps one Scorer per source key (typically "device:app", e.g.
// "oneplus9r:com.example.bank"). Mixing multiple apps' traffic into one
// baseline would wash out the signal — a chat app's normal traffic looks
// wildly novel against a banking app's baseline and vice versa.
type Manager struct {
	mu      sync.RWMutex
	scorers map[string]*Scorer
	cfg     Config
}

func NewManager(cfg Config) *Manager {
	return &Manager{
		scorers: make(map[string]*Scorer),
		cfg:     cfg,
	}
}

func (m *Manager) getOrCreate(source string) (*Scorer, error) {
	m.mu.RLock()
	s, ok := m.scorers[source]
	m.mu.RUnlock()
	if ok {
		return s, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.scorers[source]; ok {
		return s, nil
	}
	s, err := NewScorer(m.cfg)
	if err != nil {
		return nil, err
	}
	m.scorers[source] = s
	return s, nil
}

// ScoreEvent scores payload against the baseline for the given source key
// and folds it into that baseline. Returns the NCD novelty score.
//
// This is a convenience wrapper around PeekScore + Observe for callers
// that don't need to do anything (like field attribution) in between the
// two steps. The real ingest path does NOT use this -- see PeekScore's
// doc for why the split matters.
func (m *Manager) ScoreEvent(source string, payload []byte) (float64, error) {
	score, err := m.PeekScore(source, payload)
	if err != nil {
		return 0, err
	}
	return score, m.Observe(source, payload)
}

// PeekScore scores payload against source's CURRENT baseline WITHOUT
// folding it in. Creates a scorer for a never-seen source (returning 1.0,
// same as a first-ever event always has), matching ScoreEvent's behavior
// for that case.
//
// CRITICAL, learned from a real bug: this must be called BEFORE the real
// event is folded into the baseline, and any attribution/what-if scoring
// derived from it must also happen before that fold -- not lazily,
// seconds later, after other events may have already been observed. An
// earlier version computed field attribution on-demand via a separate API
// call, using whatever the baseline happened to be AT REQUEST TIME. By
// then, the real ingest pipeline had already folded in the very event
// being explained (plus whatever arrived after it), so every masked
// variant was being compared against a baseline that already contained
// an exact copy of the original -- collapsing all fields' deltas toward
// the same small, meaningless number instead of isolating the one field
// that actually mattered. Caught by re-running the full smoke test
// end-to-end and noticing the top-attributed field was "transport" (a
// field that is byte-identical in every single event, baseline and
// anomaly alike) instead of "host" -- a result that should have been an
// immediate red flag rather than something to rationalize.
//
// The fix: score, decide whether to flag, and (if flagged) compute
// attribution -- all against this SAME pre-fold snapshot -- THEN call
// Observe once, in the ingest path itself (see internal/ingest). This
// method's name changed meaning slightly as part of that fix: it used to
// refuse unseen sources (on the theory that ad-hoc attribution queries
// only make sense with real history); now that attribution is computed
// eagerly at the correct moment instead of queried later, that
// restriction no longer serves a purpose and would just make this
// unusable as the ingest path's primary scoring call.
func (m *Manager) PeekScore(source string, payload []byte) (float64, error) {
	s, err := m.getOrCreate(source)
	if err != nil {
		return 0, err
	}
	return s.Score(payload), nil
}

// Observe folds payload into source's baseline without scoring it. Pairs
// with PeekScore so a caller can score, do something with that score
// (evaluate rules, compute attribution), and only then commit payload to
// the baseline -- see PeekScore's doc for why the ordering matters.
func (m *Manager) Observe(source string, payload []byte) error {
	s, err := m.getOrCreate(source)
	if err != nil {
		return err
	}
	s.Observe(payload)
	return nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for _, s := range m.scorers {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Sources returns the currently tracked source keys (for dashboard/debug).
func (m *Manager) Sources() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.scorers))
	for k := range m.scorers {
		out = append(out, k)
	}
	return out
}
