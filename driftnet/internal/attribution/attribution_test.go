package attribution

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/yash/driftnet/internal/fingerprint"
	"github.com/yash/driftnet/internal/novelty"
)

func TestExplain_NonObjectDetailReturnsError(t *testing.T) {
	_, err := Explain(json.RawMessage(`[1,2,3]`), fingerprint.Enrich, func(b []byte) (float64, error) { return 0, nil }, 1.0)
	if err == nil {
		t.Fatal("expected an error for non-object detail, got nil")
	}
}

func TestExplain_EmptyObjectReturnsNilNoError(t *testing.T) {
	out, err := Explain(json.RawMessage(`{}`), fingerprint.Enrich, func(b []byte) (float64, error) { return 0, nil }, 1.0)
	if err != nil {
		t.Fatalf("expected no error for empty object, got %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil attributions for empty object, got %v", out)
	}
}

func TestExplain_PeekErrorPropagates(t *testing.T) {
	boom := errors.New("no baseline yet")
	_, err := Explain(json.RawMessage(`{"a":"1"}`), fingerprint.Enrich, func(b []byte) (float64, error) { return 0, boom }, 1.0)
	if err == nil {
		t.Fatal("expected peek error to propagate, got nil")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped boom error, got %v", err)
	}
}

func TestExplain_SortsByDeltaDescending(t *testing.T) {
	// Mock peek: detects which field was blanked by checking for its
	// blanked-value pattern (key present, value ""), not key absence --
	// blanking keeps the key and replaces the value, it never removes
	// the key (see package doc for why: removing a key changes object
	// arity, which was a real confound found while building this).
	peek := func(b []byte) (float64, error) {
		s := string(b)
		switch {
		case contains(s, `"a":""`):
			return 0.1, nil // blanking "a" dropped the score a lot -> "a" was important
		case contains(s, `"b":""`):
			return 0.6, nil // blanking "b" dropped it a little
		default:
			return 0.9, nil // blanking "c" barely changed it
		}
	}
	out, err := Explain(json.RawMessage(`{"a":"x","b":"y","c":"z"}`), fingerprint.Enrich, peek, 0.9)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 field attributions, got %d", len(out))
	}
	if out[0].Field != "a" {
		t.Fatalf("expected field 'a' to have the highest delta (most responsible), got order: %+v", out)
	}
	if out[0].Delta <= out[1].Delta || out[1].Delta <= out[2].Delta {
		t.Fatalf("expected strictly descending deltas, got %+v", out)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- Real integration test: no mocks, replays the exact scenario from ---
// --- the earlier end-to-end smoke tests against real components.      ---

func TestExplain_RealScorer_IdentifiesHostAsTopContributor(t *testing.T) {
	mgr := novelty.NewManager(novelty.Config{WindowSize: 128})
	defer mgr.Close()

	source := "phone1:com.example.app"
	hosts := []string{"api.example.com", "cdn.example.com", "analytics.example.com"}
	paths := []string{"/v1/sync", "/v1/events", "/v1/profile"}

	// Build a real baseline of ordinary traffic, exactly like the smoke
	// test harness did.
	for i := 0; i < 60; i++ {
		detail := json.RawMessage(`{"transport":"okhttp3","method":"POST","host":"` +
			hosts[i%3] + `","path":"` + paths[i%3] + `","request_bytes":"` + "300" + `"}`)
		enriched := fingerprint.Enrich(detail)
		if _, err := mgr.ScoreEvent(source, enriched); err != nil {
			t.Fatalf("ScoreEvent (baseline warmup): %v", err)
		}
	}

	// The exact exfil-shaped anomaly from the original smoke test: new
	// host, huge body. transport/method/path are all baseline-normal.
	anomaly := json.RawMessage(`{"transport":"okhttp3","method":"POST","host":"unknown-telemetry.ru","path":"/upload/bulk","request_bytes":"4831922"}`)
	enrichedAnomaly := fingerprint.Enrich(anomaly)

	originalScore, err := mgr.PeekScore(source, enrichedAnomaly)
	if err != nil {
		t.Fatalf("PeekScore: %v", err)
	}

	peek := func(b []byte) (float64, error) { return mgr.PeekScore(source, b) }
	out, err := Explain(anomaly, fingerprint.Enrich, peek, originalScore)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty attributions")
	}

	t.Logf("original score: %.3f", originalScore)
	for _, fa := range out {
		t.Logf("  field=%-16s delta=%.3f", fa.Field, fa.Delta)
	}

	// "host" or "request_bytes" (the two fields that are actually
	// anomalous) should be at the top -- NOT "transport" or "method",
	// which are byte-identical to baseline traffic.
	top := out[0].Field
	if top != "host" && top != "request_bytes" {
		t.Fatalf("expected 'host' or 'request_bytes' to be the top contributor, got %q (full: %+v)", top, out)
	}

	// transport and method are identical in every baseline event and in
	// the anomaly. Blanking still leaves a small measured residual (see
	// package doc: confound found and reduced, not eliminated) -- but
	// that residual must stay clearly smaller than the real signal from
	// the top field, not comparable to it.
	var transportDelta, methodDelta float64
	for _, fa := range out {
		if fa.Field == "transport" {
			transportDelta = fa.Delta
		}
		if fa.Field == "method" {
			methodDelta = fa.Delta
		}
	}
	if transportDelta >= out[0].Delta*0.5 || methodDelta >= out[0].Delta*0.5 {
		t.Fatalf("expected 'transport'/'method' residual to be well under half the top field's delta; transport=%.3f method=%.3f top=%.3f",
			transportDelta, methodDelta, out[0].Delta)
	}
}

func TestExplain_RealScorer_PeekScoreAutoCreatesForNewSource(t *testing.T) {
	// PeekScore's contract changed as part of the fix documented in its
	// package doc: it used to refuse unseen sources (on the theory that
	// ad-hoc attribution queries only make sense with real history). Now
	// that attribution runs eagerly in the ingest path -- which must
	// handle a brand-new source's very first event -- PeekScore auto-
	// creates instead, returning 1.0 (maximally novel), same as any
	// first-ever event. This test locks in that contract; the OLD
	// contract (error on unseen source) is gone on purpose, not a
	// regression.
	mgr := novelty.NewManager(novelty.Config{WindowSize: 128})
	defer mgr.Close()

	peek := func(b []byte) (float64, error) { return mgr.PeekScore("never:scored", b) }
	out, err := Explain(json.RawMessage(`{"host":"api.example.com"}`), fingerprint.Enrich, peek, 1.0)
	if err != nil {
		t.Fatalf("expected no error for a brand-new source (auto-create), got %v", err)
	}
	if len(out) != 1 || out[0].Field != "host" {
		t.Fatalf("expected one attribution for field 'host', got %+v", out)
	}
	// Blanking the only field of a first-ever event: original score is
	// 1.0 (no baseline). Blanked variant scores against a baseline that's
	// STILL empty (PeekScore doesn't mutate), so it's also 1.0 -> delta 0.
	// This is correct, if slightly unintuitive: attribution can't say
	// anything meaningful about a source's very first event, because
	// there's no baseline yet for ANY field to be more or less novel
	// against. That's an inherent limit of the technique, not a bug.
	if out[0].Delta != 0 {
		t.Fatalf("expected delta 0 for a first-ever event's only field (no baseline exists for either side of the comparison), got %.3f", out[0].Delta)
	}
}

// TestExplain_RealScorer_PerKindBaselineIsolation is a regression test
// for a real architectural fix: novelty.Manager keys baselines by
// whatever string the caller passes in, and driftnet's ingest path used
// to pass a bare "device:app" key shared across ALL event kinds. That
// meant one source's rolling baseline mixed network, crypto, and
// filesystem events together despite their JSON shapes having almost
// nothing in common -- attribution for a kind's first occurrence came
// out completely uninformative (every field showed delta ~0), because
// the compressor couldn't discriminate sub-field importance when the
// ENTIRE shape was equally alien to a baseline dominated by a different
// kind.
//
// The fix (see ingest.ScoringKey) keys baselines by "device:app:kind"
// instead. This test simulates that convention directly against
// novelty.Manager (ingest's actual key construction is tested at the
// ingest layer) to prove the isolation actually produces useful
// attribution once a same-kind baseline is genuinely established --
// something that was impossible to test meaningfully before this fix,
// since there was no way to build an isolated crypto-only baseline.
func TestExplain_RealScorer_PerKindBaselineIsolation(t *testing.T) {
	mgr := novelty.NewManager(novelty.Config{WindowSize: 128})
	defer mgr.Close()

	networkKey := "phone1:com.example.app:network"
	cryptoKey := "phone1:com.example.app:crypto"

	// Pollute with a network baseline first -- if kind-scoping weren't
	// actually isolating these, the crypto baseline below would be
	// contaminated by this dissimilar traffic.
	for i := 0; i < 30; i++ {
		detail := json.RawMessage(`{"transport":"okhttp3","method":"POST","host":"api.example.com","path":"/v1/sync","request_bytes":"200"}`)
		if _, err := mgr.ScoreEvent(networkKey, fingerprint.Enrich(detail)); err != nil {
			t.Fatalf("ScoreEvent (network baseline): %v", err)
		}
	}

	// A genuine, isolated crypto baseline: 20 benign AES/GCM calls.
	for i := 0; i < 20; i++ {
		detail := json.RawMessage(`{"api":"Cipher.getInstance","transformation":"AES/GCM/NoPadding","key_size":"256"}`)
		if _, err := mgr.ScoreEvent(cryptoKey, fingerprint.Enrich(detail)); err != nil {
			t.Fatalf("ScoreEvent (crypto baseline): %v", err)
		}
	}

	// The anomaly: same "api" field as every crypto baseline event, but a
	// weak transformation. If per-kind scoping works, "transformation"
	// should be the top-ranked field -- discriminating within an actual
	// crypto-shaped baseline, not just registering "everything here is
	// equally alien" the way it did before this fix.
	anomaly := json.RawMessage(`{"api":"Cipher.getInstance","transformation":"DES/ECB/NoPadding","key_size":"56"}`)
	enrichedAnomaly := fingerprint.Enrich(anomaly)

	originalScore, err := mgr.PeekScore(cryptoKey, enrichedAnomaly)
	if err != nil {
		t.Fatalf("PeekScore: %v", err)
	}

	peek := func(b []byte) (float64, error) { return mgr.PeekScore(cryptoKey, b) }
	out, err := Explain(anomaly, fingerprint.Enrich, peek, originalScore)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty attributions")
	}

	t.Logf("original score: %.3f", originalScore)
	for _, fa := range out {
		t.Logf("  field=%-16s delta=%.3f", fa.Field, fa.Delta)
	}

	if out[0].Field != "transformation" {
		t.Fatalf("expected 'transformation' as the top contributor once a real crypto-only baseline exists, got %q (full: %+v)", out[0].Field, out)
	}
}
