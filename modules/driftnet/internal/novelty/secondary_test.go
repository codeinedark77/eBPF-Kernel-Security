package novelty

import (
	"testing"
)

func TestSecondaryScorer_RepeatedPayloadStaysLow(t *testing.T) {
	s := NewSecondaryScorer(Config{WindowSize: 32})
	payload := []byte(`{"transport":"okhttp3","method":"POST","host":"api.example.com","path":"/v1/sync","request_bytes":"341"}`)

	var last float64
	for i := 0; i < 40; i++ {
		last = s.Score(payload)
		s.Observe(payload)
	}
	t.Logf("steady-state secondary score for repeated payload: %f", last)
	if last > 0.3 {
		t.Fatalf("expected low steady-state score for an exact repeat, got %.3f", last)
	}
}

func TestSecondaryScorer_GenuinelyDifferentPayloadScoresHigh(t *testing.T) {
	s := NewSecondaryScorer(Config{WindowSize: 32})
	normal := []byte(`{"transport":"okhttp3","method":"POST","host":"api.example.com","path":"/v1/sync","request_bytes":"341"}`)
	for i := 0; i < 20; i++ {
		s.Observe(normal)
	}

	anomaly := []byte(`{"transport":"okhttp3","method":"POST","host":"unknown-telemetry.ru","path":"/upload/bulk","request_bytes_mag":"1e6","request_bytes":"4831922"}`)
	score := s.Score(anomaly)
	t.Logf("secondary score for anomalous payload: %f", score)
	if score < 0.4 {
		t.Fatalf("expected a clearly elevated score for a genuinely different payload, got %.3f", score)
	}
}

func TestSecondaryScorer_ScoreStaysStableAsBaselineGrows(t *testing.T) {
	s := NewSecondaryScorer(Config{WindowSize: 128})
	mkPayload := func(i int) []byte {
		hosts := []string{"api.example.com", "cdn.example.com", "analytics.example.com"}
		paths := []string{"/v1/sync", "/v1/events", "/v1/profile"}
		h := hosts[i%len(hosts)]
		p := paths[i%len(paths)]
		return []byte(`{"transport":"okhttp3","method":"POST","host":"` + h + `","path":"` + p + `","request_bytes":"` + string(rune('0'+i%10)) + `00"}`)
	}

	var scores []float64
	for i := 0; i < 100; i++ {
		sc := s.Score(mkPayload(i))
		s.Observe(mkPayload(i))
		scores = append(scores, sc)
	}

	mean := func(xs []float64) float64 {
		var sum float64
		for _, x := range xs {
			sum += x
		}
		return sum / float64(len(xs))
	}
	early := mean(scores[40:60])
	late := mean(scores[80:100])
	t.Logf("secondary mean scores[40:60]=%.3f scores[80:100]=%.3f", early, late)
	if late-early > 0.15 {
		t.Fatalf("secondary score drifted upward as baseline grew (early=%.3f late=%.3f)", early, late)
	}
}

func TestSecondaryManager_IsolatesSourcesIndependently(t *testing.T) {
	m := NewSecondaryManager(Config{WindowSize: 32})
	payloadA := []byte(`{"host":"api-a.example.com"}`)
	for i := 0; i < 20; i++ {
		m.Observe("sourceA", payloadA)
	}
	// sourceB has never seen anything -- its first event should score
	// high regardless of what sourceA's baseline looks like.
	scoreB := m.PeekScore("sourceB", []byte(`{"host":"anything.example.com"}`))
	if scoreB < 0.9 {
		t.Fatalf("expected source B's first-ever event to score near 1.0 (no cross-source baseline leakage), got %.3f", scoreB)
	}
}

// TestPrimaryAndSecondaryScorers_CanGenuinelyDisagree is the actual point
// of building a second compressor at all: prove, with real code (not just
// the standalone experiment that motivated this), that the primary
// (zstd) and secondary (DEFLATE) scorers can produce meaningfully
// different readings on identical input -- confirming disagreement is a
// real, occurring phenomenon this architecture can surface, not a
// hypothetical.
func TestPrimaryAndSecondaryScorers_CanGenuinelyDisagree(t *testing.T) {
	primary, err := NewScorer(Config{WindowSize: 32})
	if err != nil {
		t.Fatalf("NewScorer: %v", err)
	}
	defer primary.Close()
	secondary := NewSecondaryScorer(Config{WindowSize: 32})

	baselineEvents := []string{
		`{"transport":"okhttp3","method":"POST","host":"api.example.com","path":"/v1/sync","request_bytes":"341"}`,
		`{"transport":"okhttp3","method":"POST","host":"cdn.example.com","path":"/v1/events","request_bytes":"350"}`,
		`{"transport":"okhttp3","method":"POST","host":"analytics.example.com","path":"/v1/profile","request_bytes":"310"}`,
	}
	for i := 0; i < 30; i++ {
		p := []byte(baselineEvents[i%len(baselineEvents)])
		primary.Observe(p)
		secondary.Observe(p)
	}

	redundant := []byte(`{"transport":"okhttp3","method":"POST","host":"api.example.com","path":"/v1/sync","request_bytes":"355"}`)
	primaryScore := primary.Score(redundant)
	secondaryScore := secondary.Score(redundant)

	t.Logf("redundant payload: primary(zstd)=%.3f secondary(deflate)=%.3f delta=%.3f",
		primaryScore, secondaryScore, primaryScore-secondaryScore)

	anomaly := []byte(`{"transport":"okhttp3","method":"POST","host":"unknown-telemetry.ru","path":"/upload/bulk","request_bytes_mag":"1e6","request_bytes":"4831922"}`)
	primaryAnomalyScore := primary.Score(anomaly)
	secondaryAnomalyScore := secondary.Score(anomaly)
	t.Logf("anomaly payload:   primary(zstd)=%.3f secondary(deflate)=%.3f delta=%.3f",
		primaryAnomalyScore, secondaryAnomalyScore, primaryAnomalyScore-secondaryAnomalyScore)

	redundantDelta := abs(primaryScore - secondaryScore)
	anomalyDelta := abs(primaryAnomalyScore - secondaryAnomalyScore)
	if redundantDelta < 0.05 && anomalyDelta < 0.05 {
		t.Fatalf("expected a meaningful (>=0.05) disagreement between primary and secondary on at least one payload, got redundant_delta=%.3f anomaly_delta=%.3f -- if these always agree closely, this feature adds cost without adding signal",
			redundantDelta, anomalyDelta)
	}
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
