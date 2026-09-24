package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/yash/driftnet/internal/novelty"
	"github.com/yash/driftnet/internal/store"
)

func mkEvent(seq uint64, ncd float64, ruleMatches []string) *store.Event {
	return &store.Event{
		Seq:         seq,
		Device:      "phone1",
		App:         "com.example.app",
		Kind:        "network",
		Detail:      json.RawMessage(`{"host":"api.example.com"}`),
		NCDScore:    ncd,
		RuleMatches: ruleMatches,
	}
}

func decodeEvents(t *testing.T, rec *httptest.ResponseRecorder) []*store.Event {
	t.Helper()
	var out []*store.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rec.Body.String())
	}
	return out
}

func TestRecentEvents_ReturnsNewestFirst(t *testing.T) {
	h := NewHandlers(novelty.NewManager(novelty.Config{}), 500, 0.5)
	h.Push(mkEvent(1, 0.1, nil))
	h.Push(mkEvent(2, 0.1, nil))
	h.Push(mkEvent(3, 0.1, nil))

	rec := httptest.NewRecorder()
	h.RecentEvents(rec, httptest.NewRequest(http.MethodGet, "/api/events/recent", nil))

	events := decodeEvents(t, rec)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[0].Seq != 3 || events[1].Seq != 2 || events[2].Seq != 1 {
		t.Fatalf("expected newest-first order [3,2,1], got [%d,%d,%d]", events[0].Seq, events[1].Seq, events[2].Seq)
	}
}

func TestRecentEvents_EvictsOldestBeyondMaxKeep(t *testing.T) {
	h := NewHandlers(novelty.NewManager(novelty.Config{}), 3, 0.5)
	for i := uint64(1); i <= 5; i++ {
		h.Push(mkEvent(i, 0.1, nil))
	}

	rec := httptest.NewRecorder()
	h.RecentEvents(rec, httptest.NewRequest(http.MethodGet, "/api/events/recent", nil))

	events := decodeEvents(t, rec)
	if len(events) != 3 {
		t.Fatalf("maxKeep=3 should cap the ring at 3 events, got %d", len(events))
	}
	// Should have kept seq 3,4,5 (oldest two evicted), newest-first.
	if events[0].Seq != 5 || events[1].Seq != 4 || events[2].Seq != 3 {
		t.Fatalf("expected surviving events [5,4,3], got [%d,%d,%d]", events[0].Seq, events[1].Seq, events[2].Seq)
	}
}

func TestFlaggedEvents_IncludesHighNCDScore(t *testing.T) {
	h := NewHandlers(novelty.NewManager(novelty.Config{}), 500, 0.5)
	h.Push(mkEvent(1, 0.9, nil)) // above threshold, no rule match
	h.Push(mkEvent(2, 0.1, nil)) // below threshold, no rule match

	rec := httptest.NewRecorder()
	h.FlaggedEvents(rec, httptest.NewRequest(http.MethodGet, "/api/events/flagged", nil))

	events := decodeEvents(t, rec)
	if len(events) != 1 || events[0].Seq != 1 {
		t.Fatalf("expected only seq 1 (NCD 0.9 >= threshold 0.5) flagged, got %+v", events)
	}
}

func TestFlaggedEvents_IncludesRuleMatchEvenBelowNCDThreshold(t *testing.T) {
	// This is the exact shape of the real bug found in testing: an event
	// with a low NCD score (because it's no longer "novel" -- it's
	// become the baseline) but a rule match (which has no concept of
	// novelty) must still show up as flagged.
	h := NewHandlers(novelty.NewManager(novelty.Config{}), 500, 0.5)
	h.Push(mkEvent(1, 0.05, []string{"weak_cipher"}))

	rec := httptest.NewRecorder()
	h.FlaggedEvents(rec, httptest.NewRequest(http.MethodGet, "/api/events/flagged", nil))

	events := decodeEvents(t, rec)
	if len(events) != 1 || events[0].Seq != 1 {
		t.Fatalf("expected seq 1 flagged via rule match despite low NCD score, got %+v", events)
	}
}

func TestFlaggedEvents_ThresholdIsConfiguredNotHardcoded(t *testing.T) {
	// Regression test for the real drift bug: this handler previously
	// hardcoded 0.55 independently of ingest.NoveltyThreshold. Verify the
	// threshold actually comes from the constructor argument, not a
	// baked-in constant, by configuring two different thresholds and
	// checking they produce different flagged sets for the same data.
	ev := mkEvent(1, 0.52, nil)

	strict := NewHandlers(novelty.NewManager(novelty.Config{}), 500, 0.6)
	strict.Push(ev)
	recStrict := httptest.NewRecorder()
	strict.FlaggedEvents(recStrict, httptest.NewRequest(http.MethodGet, "/api/events/flagged", nil))
	if got := decodeEvents(t, recStrict); len(got) != 0 {
		t.Fatalf("threshold=0.6 should NOT flag a 0.52 event, got %d flagged", len(got))
	}

	lenient := NewHandlers(novelty.NewManager(novelty.Config{}), 500, 0.5)
	lenient.Push(ev)
	recLenient := httptest.NewRecorder()
	lenient.FlaggedEvents(recLenient, httptest.NewRequest(http.MethodGet, "/api/events/flagged", nil))
	if got := decodeEvents(t, recLenient); len(got) != 1 {
		t.Fatalf("threshold=0.5 SHOULD flag a 0.52 event, got %d flagged", len(got))
	}
}

func TestSources_ReflectsScorerManager(t *testing.T) {
	// Production always keys novelty.Manager by device:app:kind (see
	// ingest.ScoringKey), never bare device:app -- Sources() must dedupe
	// that back down for the dashboard sidebar. Score two DIFFERENT kinds
	// for the same app to actually exercise the dedup, not just the
	// pass-through case a single key wouldn't distinguish.
	mgr := novelty.NewManager(novelty.Config{})
	defer mgr.Close()
	if _, err := mgr.ScoreEvent("phone1:com.example.app:network", []byte(`{"host":"api.example.com"}`)); err != nil {
		t.Fatalf("ScoreEvent (network): %v", err)
	}
	if _, err := mgr.ScoreEvent("phone1:com.example.app:crypto", []byte(`{"transformation":"AES/GCM"}`)); err != nil {
		t.Fatalf("ScoreEvent (crypto): %v", err)
	}

	h := NewHandlers(mgr, 500, 0.5)
	rec := httptest.NewRecorder()
	h.Sources(rec, httptest.NewRequest(http.MethodGet, "/api/sources", nil))

	var body struct {
		Sources []string `json:"sources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Sources) != 1 || body.Sources[0] != "phone1:com.example.app" {
		t.Fatalf("expected exactly one deduped source [phone1:com.example.app] despite 2 kind-qualified scorer keys, got %v", body.Sources)
	}
}

// TestSetTriage_ConcurrentWithReadsIsRaceFree is a regression test for a
// real data race found during a manual code review, not a hypothetical.
// An earlier version of main.go's OnFlagged callback mutated
// `ev.Triage = note` directly on a *store.Event pointer already sitting
// in h.recent -- with zero synchronization against RecentEvents/
// FlaggedEvents concurrently reading that same field while iterating
// h.recent under h.mu.RLock(). A RWMutex only protects goroutines that
// actually acquire it; a goroutine mutating a field through an
// independent pointer, never touching h.mu, isn't covered at all.
//
// No existing test caught this at the time -- ingest-package tests never
// construct a Handlers, and this package's own tests never mutated a
// pushed event concurrently with reading it. A standalone reproduction
// of the OLD pattern (isolated from this codebase, same shape: direct
// field mutation vs RWMutex-protected reads) confirmed -race genuinely
// flags it as a data race. This test exercises the FIXED pattern
// (SetTriage) under the identical concurrent-access shape and must stay
// clean under -race.
func TestSetTriage_ConcurrentWithReadsIsRaceFree(t *testing.T) {
	mgr := novelty.NewManager(novelty.Config{})
	defer mgr.Close()
	h := NewHandlers(mgr, 500, 0.5)
	h.Push(mkEvent(1, 0.9, nil))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			h.SetTriage(1, "some triage text")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			rec := httptest.NewRecorder()
			h.RecentEvents(rec, httptest.NewRequest(http.MethodGet, "/api/events/recent", nil))
			rec2 := httptest.NewRecorder()
			h.FlaggedEvents(rec2, httptest.NewRequest(http.MethodGet, "/api/events/flagged", nil))
		}
	}()
	wg.Wait()

	// Also verify SetTriage actually did its job, not just that it didn't
	// race -- decodeEvents needs a real request/response round trip.
	rec := httptest.NewRecorder()
	h.RecentEvents(rec, httptest.NewRequest(http.MethodGet, "/api/events/recent", nil))
	events := decodeEvents(t, rec)
	if len(events) != 1 || events[0].Triage != "some triage text" {
		t.Fatalf("expected triage to be set correctly after concurrent access, got %+v", events)
	}
}

func TestSetTriage_UnknownSeqIsANoOp(t *testing.T) {
	mgr := novelty.NewManager(novelty.Config{})
	defer mgr.Close()
	h := NewHandlers(mgr, 500, 0.5)
	h.Push(mkEvent(1, 0.1, nil))

	// Setting triage for a seq that was never pushed (e.g. aged out of
	// the ring) must not panic or corrupt state -- it's a documented
	// no-op, not an error.
	h.SetTriage(999, "orphaned triage")

	rec := httptest.NewRecorder()
	h.RecentEvents(rec, httptest.NewRequest(http.MethodGet, "/api/events/recent", nil))
	events := decodeEvents(t, rec)
	if len(events) != 1 || events[0].Triage != "" {
		t.Fatalf("expected the existing event untouched and no phantom entry, got %+v", events)
	}
}
