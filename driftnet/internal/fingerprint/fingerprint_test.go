package fingerprint

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEnrich_AddsMagnitudeBucketForNumericString(t *testing.T) {
	in := json.RawMessage(`{"host":"api.example.com","request_bytes":"341"}`)
	out := Enrich(in)

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("enriched output isn't valid JSON: %v", err)
	}
	if got["request_bytes_mag"] != "1e2" {
		t.Fatalf("expected request_bytes_mag=1e2, got %v (full: %s)", got["request_bytes_mag"], out)
	}
	// Original field must still be present untouched.
	if got["request_bytes"] != "341" {
		t.Fatalf("original field was dropped or mutated: %v", got["request_bytes"])
	}
}

func TestEnrich_DifferentMagnitudesProduceDifferentBuckets(t *testing.T) {
	small := Enrich(json.RawMessage(`{"host":"api.example.com","request_bytes":"341"}`))
	huge := Enrich(json.RawMessage(`{"host":"unknown-telemetry.ru","request_bytes":"4831922"}`))

	var s, h map[string]any
	json.Unmarshal(small, &s)
	json.Unmarshal(huge, &h)

	if s["request_bytes_mag"] == h["request_bytes_mag"] {
		t.Fatalf("341 and 4831922 got the same magnitude bucket: %v", s["request_bytes_mag"])
	}
	t.Logf("341 -> %v, 4831922 -> %v", s["request_bytes_mag"], h["request_bytes_mag"])
}

func TestEnrich_SameMagnitudeProducesSameBucket(t *testing.T) {
	a := Enrich(json.RawMessage(`{"request_bytes":"310"}`))
	b := Enrich(json.RawMessage(`{"request_bytes":"290"}`))

	var ma, mb map[string]any
	json.Unmarshal(a, &ma)
	json.Unmarshal(b, &mb)

	if ma["request_bytes_mag"] != mb["request_bytes_mag"] {
		t.Fatalf("310 and 290 should share a magnitude bucket, got %v vs %v", ma["request_bytes_mag"], mb["request_bytes_mag"])
	}
}

func TestEnrich_NonObjectPayloadPassesThroughUnchanged(t *testing.T) {
	in := json.RawMessage(`[1,2,3]`)
	out := Enrich(in)
	if string(out) != string(in) {
		t.Fatalf("non-object payload should pass through unchanged, got %s", out)
	}
}

func TestEnrich_MalformedJSONPassesThroughUnchanged(t *testing.T) {
	in := json.RawMessage(`not json at all`)
	out := Enrich(in)
	if string(out) != string(in) {
		t.Fatalf("malformed payload should pass through unchanged, got %s", out)
	}
}

func TestEnrich_ZeroDoesNotPanicOnLog(t *testing.T) {
	in := json.RawMessage(`{"count":"0"}`)
	out := Enrich(in) // must not panic on log10(0)
	if !strings.Contains(string(out), `"count_mag":"0"`) {
		t.Fatalf("expected count_mag=0 for zero value, got %s", out)
	}
}

func TestEnrich_DeterministicOutput(t *testing.T) {
	in := json.RawMessage(`{"host":"api.example.com","path":"/v1/sync","request_bytes":"341"}`)
	a := Enrich(in)
	b := Enrich(in)
	if string(a) != string(b) {
		t.Fatalf("Enrich isn't deterministic across calls:\n%s\nvs\n%s", a, b)
	}
}
