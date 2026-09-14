package ingest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yash/driftnet/internal/novelty"
	"github.com/yash/driftnet/internal/rules"
	"github.com/yash/driftnet/internal/store"
)

// testServer spins up a real httptest server backed by a real WAL (temp
// dir) and a real novelty.Manager -- no mocks. This is intentionally the
// same shape as the manual smoke-test harness used during development,
// just automated and assertion-based instead of eyeballed.
func testServer(t *testing.T) (*Server, *httptest.Server, func()) {
	t.Helper()
	dir := t.TempDir()
	wal, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	scorers := novelty.NewManager(novelty.Config{WindowSize: 32})

	srv := NewServer(wal, scorers, novelty.NewSecondaryManager(novelty.Config{WindowSize: 32}), rules.NewEvaluator(rules.Config{WarmupEvents: rules.DefaultWarmupEvents}), nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/ingest", srv.HandleWS)
	hs := httptest.NewServer(mux)

	cleanup := func() {
		hs.Close()
		wal.Close()
		scorers.Close()
	}
	return srv, hs, cleanup
}

func dialWS(t *testing.T, hs *httptest.Server) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(hs.URL, "http") + "/ws/ingest"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func sendEvent(t *testing.T, conn *websocket.Conn, device, app, kind string, detail map[string]any) {
	sendEventWithVersion(t, conn, device, app, kind, detail, "")
}

func sendEventWithVersion(t *testing.T, conn *websocket.Conn, device, app, kind string, detail map[string]any, version string) {
	t.Helper()
	d, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}
	raw := RawEvent{Device: device, App: app, Kind: kind, Detail: d, AppVersion: version}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// waitFor polls cond every 10ms until it returns true or timeout elapses.
// Fixed time.Sleep() calls are the wrong tool here: WAL.Append fsyncs on
// every single write for crash-safety, so N sequential events take N
// fsyncs -- and fsync latency varies enough (especially under
// virtualization) that a fixed sleep window is inherently flaky. An
// earlier version of these tests used sleep(300ms) and failed
// intermittently (12/20, 3/5 events observed) purely from timing, not
// from an actual bug in the server.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not met within %s", timeout)
	}
}

func TestHandleWS_OrdinaryEventsDoNotFlag(t *testing.T) {
	srv, hs, cleanup := testServer(t)
	defer cleanup()

	var mu sync.Mutex
	var flaggedCount, eventCount int
	srv.OnEvent = func(ev *store.Event) { mu.Lock(); eventCount++; mu.Unlock() }
	srv.OnFlagged = func(ev *store.Event, reply func(string, interface{})) { mu.Lock(); flaggedCount++; mu.Unlock() }

	conn := dialWS(t, hs)
	defer conn.Close()

	hosts := []string{"api.example.com", "cdn.example.com"}
	// 6 events, 2 distinct hosts. NewServer wires the rules evaluator
	// with rules.DefaultWarmupEvents (40) -- well above 6 -- so this
	// doubles as an integration check that the warmup config actually
	// makes it from NewServer through to the evaluator, not just a
	// "rules work in isolation" check (that's rules_test.go's job).
	// Expect exactly 1 flag total: the first-ever event for this source
	// scores NCD=1.0 on its own (empty baseline), independent of rules.
	// The other 5 -- including the first sighting of the second host,
	// which pre-warmup-fix would have also flagged via first_seen_host --
	// should NOT flag, proving the warmup gate is actually active here,
	// not just in rules_test.go's isolated unit tests.
	for i := 0; i < 6; i++ {
		sendEvent(t, conn, "phone1", "com.example.app", "network", map[string]any{
			"host": hosts[i%2], "path": "/v1/sync", "request_bytes": "300",
		})
	}
	waitFor(t, 15*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return eventCount >= 6
	})

	mu.Lock()
	defer mu.Unlock()
	if eventCount != 6 {
		t.Fatalf("expected 6 events ingested, got %d", eventCount)
	}
	if flaggedCount != 1 {
		t.Fatalf("expected exactly 1 flag, got %d. The first-ever event for a brand-new source always scores NCD=1.0 (Scorer.Score returns 1.0 when no baseline exists yet), which alone crosses NoveltyThreshold independent of rules -- that's flag #1. None of the remaining 5 events should flag: they're ordinary repeat traffic scoring low on NCD, and first_seen_host stays gated for all of them since 6 events never clears DefaultWarmupEvents=40. Any count other than 1 means either the warmup config isn't wired through NewServer, or NCD scoring behaved unexpectedly", flaggedCount)
	}
}

func TestHandleWS_WeakCipherFlagsViaRulesRegardlessOfNovelty(t *testing.T) {
	srv, hs, cleanup := testServer(t)
	defer cleanup()

	var mu sync.Mutex
	var flagged []*store.Event
	srv.OnFlagged = func(ev *store.Event, reply func(string, interface{})) { mu.Lock(); flagged = append(flagged, ev); mu.Unlock() }

	conn := dialWS(t, hs)
	defer conn.Close()

	// 3 repeats is enough to prove "rules fire every time, unlike
	// novelty which decays as the event joins its own baseline."
	for i := 0; i < 3; i++ {
		sendEvent(t, conn, "phone1", "com.example.app", "crypto", map[string]any{
			"api": "Cipher.getInstance", "transformation": "DES/ECB/NoPadding",
		})
	}
	waitFor(t, 15*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(flagged) >= 3
	})

	mu.Lock()
	defer mu.Unlock()
	if len(flagged) != 3 {
		t.Fatalf("expected all 3 weak-cipher events to flag via rules (novelty-independent), got %d", len(flagged))
	}
	for _, ev := range flagged {
		if !containsStr(ev.RuleMatches, "weak_cipher") {
			t.Fatalf("expected weak_cipher in RuleMatches, got %v", ev.RuleMatches)
		}
	}
}

func TestHandleWS_EventsPersistToWAL(t *testing.T) {
	srv, hs, cleanup := testServer(t)
	defer cleanup()

	var mu sync.Mutex
	var eventCount int
	srv.OnEvent = func(ev *store.Event) { mu.Lock(); eventCount++; mu.Unlock() }

	conn := dialWS(t, hs)
	sendEvent(t, conn, "phone1", "com.example.app", "network", map[string]any{
		"host": "api.example.com", "path": "/v1/sync", "request_bytes": "300",
	})
	waitFor(t, 15*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return eventCount >= 1
	})
	conn.Close()

	var events []*store.Event
	err := srv.wal.Replay(func(ev *store.Event) error {
		events = append(events, ev)
		return nil
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event persisted to WAL, got %d", len(events))
	}
	if events[0].Device != "phone1" || events[0].App != "com.example.app" {
		t.Fatalf("persisted event has wrong device/app: %+v", events[0])
	}
}

func TestHandleWS_MalformedJSONIsSkippedNotFatal(t *testing.T) {
	srv, hs, cleanup := testServer(t)
	defer cleanup()

	var mu sync.Mutex
	var eventCount int
	srv.OnEvent = func(ev *store.Event) { mu.Lock(); eventCount++; mu.Unlock() }

	conn := dialWS(t, hs)
	defer conn.Close()

	conn.WriteMessage(websocket.TextMessage, []byte("not json at all"))
	sendEvent(t, conn, "phone1", "com.example.app", "network", map[string]any{"host": "api.example.com"})
	waitFor(t, 15*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return eventCount >= 1
	})

	mu.Lock()
	defer mu.Unlock()
	if eventCount != 1 {
		t.Fatalf("malformed message should be skipped, valid one should still process; got eventCount=%d", eventCount)
	}
}

func containsStr(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

func TestHandleWS_AppVersionChangeFlagsThroughRealPipeline(t *testing.T) {
	srv, hs, cleanup := testServer(t)
	defer cleanup()

	var mu sync.Mutex
	var flagged []*store.Event
	var eventCount int
	srv.OnEvent = func(ev *store.Event) { mu.Lock(); eventCount++; mu.Unlock() }
	srv.OnFlagged = func(ev *store.Event, reply func(string, interface{})) { mu.Lock(); flagged = append(flagged, ev); mu.Unlock() }

	conn := dialWS(t, hs)
	defer conn.Close()

	// A few ordinary events on version 1.0.0. Note the FIRST of these
	// will flag too, but for an unrelated reason (NCD=1.0 on an empty
	// baseline, same as any source's first-ever event) -- the test must
	// not treat "at least one flag happened" as proof the version-change
	// event specifically has been processed yet.
	for i := 0; i < 3; i++ {
		sendEventWithVersion(t, conn, "phone1", "com.example.app", "network",
			map[string]any{"host": "api.example.com", "path": "/v1/sync", "request_bytes": "300"}, "1.0.0:100")
	}
	// The app "updates" mid-session: same event shape, new version.
	sendEventWithVersion(t, conn, "phone1", "com.example.app", "network",
		map[string]any{"host": "api.example.com", "path": "/v1/sync", "request_bytes": "300"}, "1.1.0:101")

	waitFor(t, 15*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		// Exactly 2 real flags expected: event #1 (NCD=1.0, first-ever
		// event for this source, unrelated to version tracking) and
		// event #4 (identical shape/content to baseline by now -- NCD
		// score alone would be near 0 -- flagged ONLY via app_updated).
		// Waiting on this directly, not eventCount: OnFlagged runs in a
		// spawned goroutine (see server.go's "go s.OnFlagged(ev)"),
		// decoupled from the synchronous OnEvent callback, so eventCount
		// reaching 4 does NOT guarantee event #4's OnFlagged call has
		// actually finished executing yet. An earlier version of this
		// test waited on eventCount and was genuinely flaky (passed and
		// failed on identical code across consecutive runs) for exactly
		// this reason.
		return len(flagged) >= 2
	})

	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, ev := range flagged {
		for _, rm := range ev.RuleMatches {
			if rm == "app_updated:1.0.0:100->1.1.0:101" {
				found = true
			}
		}
	}
	if !found {
		for _, ev := range flagged {
			t.Logf("flagged: seq=%d ncd=%.3f rules=%v version=%s", ev.Seq, ev.NCDScore, ev.RuleMatches, ev.AppVersion)
		}
		t.Fatalf("expected an app_updated:1.0.0:100->1.1.0:101 rule match among %d flagged event(s)", len(flagged))
	}
}

// TestHandleWS_CompressorDisagreementFlagsThroughRealPipeline is an
// end-to-end test for the secondary (DEFLATE) scorer's whole reason for
// existing: catching a case where the two independent compression
// measurements land on opposite sides of their thresholds.
//
// The specific payload here isn't arbitrary -- it was found by empirical
// search against the ACTUAL production pipeline (fingerprint.Enrich
// applied, per-kind baseline keying, the real thresholds), not guessed
// or lifted from the isolated novelty-package experiment. An RSA/OAEP
// cipher call, after a baseline of AES/GCM calls, lands primary(zstd) at
// 0.535 (crosses NoveltyThreshold=0.5) while secondary(deflate) sits at
// 0.412 (does not cross SecondaryNoveltyThreshold=0.5) -- a real,
// reproducible disagreement in the real pipeline shape, not a
// hand-picked edge case from a simplified experiment.
func TestHandleWS_CompressorDisagreementFlagsThroughRealPipeline(t *testing.T) {
	srv, hs, cleanup := testServer(t)
	defer cleanup()

	var mu sync.Mutex
	var flagged []*store.Event
	var eventCount int
	srv.OnEvent = func(ev *store.Event) { mu.Lock(); eventCount++; mu.Unlock() }
	srv.OnFlagged = func(ev *store.Event, reply func(string, interface{})) { mu.Lock(); flagged = append(flagged, ev); mu.Unlock() }

	conn := dialWS(t, hs)
	defer conn.Close()

	for i := 0; i < 20; i++ {
		sendEvent(t, conn, "phone1", "com.example.app", "crypto",
			map[string]any{"api": "Cipher.getInstance", "transformation": "AES/GCM/NoPadding", "key_size": "256"})
	}
	sendEvent(t, conn, "phone1", "com.example.app", "crypto",
		map[string]any{"api": "Cipher.getInstance", "transformation": "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "key_size": "2048"})

	waitFor(t, 15*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return eventCount >= 21
	})

	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, ev := range flagged {
		for _, rm := range ev.RuleMatches {
			if strings.HasPrefix(rm, "compressor_disagreement:") {
				found = true
				t.Logf("found: %s (ncd=%.3f secondary=%.3f)", rm, ev.NCDScore, ev.SecondaryScore)
			}
		}
	}
	if !found {
		for _, ev := range flagged {
			t.Logf("flagged: seq=%d ncd=%.3f secondary=%.3f rules=%v", ev.Seq, ev.NCDScore, ev.SecondaryScore, ev.RuleMatches)
		}
		t.Fatalf("expected a compressor_disagreement rule match among %d flagged event(s)", len(flagged))
	}
}
