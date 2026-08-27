package novelty

import "testing"

func TestNCD_RepeatedPayloadStaysLow(t *testing.T) {
	s, err := NewScorer(Config{WindowSize: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	normal := []byte(`{"host":"api.example.com","path":"/v1/ping","method":"GET","bytes":128}`)

	first := s.ScoreAndObserve(normal)
	if first != 1.0 {
		t.Fatalf("first-ever event should be maximally novel (empty baseline), got %f", first)
	}

	var last float64
	for i := 0; i < 10; i++ {
		last = s.ScoreAndObserve(normal)
	}
	if last > 0.35 {
		t.Fatalf("repeated identical payload should score low novelty after baseline fills, got %f", last)
	}
	t.Logf("steady-state NCD for repeated payload: %f", last)
}

func TestNCD_GenuinelyDifferentPayloadScoresHigh(t *testing.T) {
	s, err := NewScorer(Config{WindowSize: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	normal := []byte(`{"host":"api.example.com","path":"/v1/ping","method":"GET","bytes":128}`)
	for i := 0; i < 20; i++ {
		s.ScoreAndObserve(normal)
	}

	// Structurally and semantically different: base64-ish blob, different
	// keys entirely, much larger — simulates e.g. a sudden crypto/exfil-like
	// payload against a baseline of small polling GETs.
	anomalous := []byte(`{"op":"upload","dest":"185.212.44.90:9001","payload_b64":"TXlTZWNyZXRLZXlNYXRlcmlhbEFuZFRva2VuRHVtcEhlcmVBbmRNb3JlUmFuZG9tQnl0ZXNUb01ha2VJdExvbmdlckFuZExlc3NDb21wcmVzc2libGVYWVo="}`)

	score := s.Score(anomalous)
	if score < 0.5 {
		t.Fatalf("structurally different payload should score high novelty, got %f", score)
	}
	t.Logf("NCD for anomalous payload against normal baseline: %f", score)
}

// Regression test for a real bug: an earlier formulation used the raw
// baseline's compressed size as the ratio's denominator. Since baseline
// grows to windowSize concatenated events while payload is a single
// event, that made scores drift toward 1 purely as the window filled up
// -- independent of whether the payload was actually similar to history.
// This test asserts scores stay flat (within noise) across a growing
// baseline for genuinely repetitive traffic.
func TestNCD_ScoreStaysStableAsBaselineGrows(t *testing.T) {
	s, err := NewScorer(Config{WindowSize: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	hosts := []string{"api.example.com", "cdn.example.com", "analytics.example.com"}
	paths := []string{"/v1/sync", "/v1/events", "/v1/profile"}

	mkPayload := func(i int) []byte {
		h := hosts[i%len(hosts)]
		p := paths[i%len(paths)]
		return []byte(`{"transport":"okhttp3","method":"POST","host":"` + h + `","path":"` + p + `","request_bytes":"` + string(rune('0'+i%10)) + `00"}`)
	}

	var scores []float64
	for i := 0; i < 100; i++ {
		scores = append(scores, s.ScoreAndObserve(mkPayload(i)))
	}

	// Check the back half (baseline fully warmed and window full) doesn't
	// show a steady upward drift -- take the mean of scores[40:60] vs
	// scores[80:100] and require they're close.
	mean := func(xs []float64) float64 {
		var sum float64
		for _, x := range xs {
			sum += x
		}
		return sum / float64(len(xs))
	}
	early := mean(scores[40:60])
	late := mean(scores[80:100])

	t.Logf("mean novelty scores[40:60]=%.3f scores[80:100]=%.3f", early, late)
	if late-early > 0.15 {
		t.Fatalf("novelty score drifted upward as baseline window filled (early=%.3f late=%.3f) -- denominator likely scales with baseline size again", early, late)
	}
	if late > 0.4 {
		t.Fatalf("steady-state score for repetitive-but-varied traffic should stay well under the 0.55 flag threshold, got %.3f", late)
	}
}

func TestManager_IsolatesSourcesIndependently(t *testing.T) {
	m := NewManager(Config{WindowSize: 8})
	defer m.Close()

	chatPayload := []byte(`{"host":"chat.example.com","path":"/messages","method":"POST"}`)
	bankPayload := []byte(`{"host":"bank.example.com","path":"/balance","method":"GET"}`)

	for i := 0; i < 10; i++ {
		if _, err := m.ScoreEvent("phone:com.chat.app", chatPayload); err != nil {
			t.Fatal(err)
		}
		if _, err := m.ScoreEvent("phone:com.bank.app", bankPayload); err != nil {
			t.Fatal(err)
		}
	}

	// Steady-state score for each source's own normal traffic should be low,
	// proving the baselines didn't bleed into each other.
	chatScore, _ := m.ScoreEvent("phone:com.chat.app", chatPayload)
	bankScore, _ := m.ScoreEvent("phone:com.bank.app", bankPayload)

	if chatScore > 0.4 || bankScore > 0.4 {
		t.Fatalf("expected low novelty for each source's own steady traffic, got chat=%f bank=%f", chatScore, bankScore)
	}

	sources := m.Sources()
	if len(sources) != 2 {
		t.Fatalf("expected 2 isolated sources, got %d: %v", len(sources), sources)
	}
}
