// Package fingerprint enriches raw event payloads before they go into the
// novelty scorer, to close a real detection gap found during smoke
// testing (see driftnet's README, "Known detection gap").
//
// The problem: the novelty scorer measures compressibility of raw JSON
// bytes. Two events with the same keys and similarly-lengthed string
// values compress almost identically even if a numeric field inside them
// differs by five orders of magnitude — {"request_bytes":"341"} and
// {"request_bytes":"4831922"} are nearly the same number of bytes and the
// same JSON shape, so a compressor sees them as barely different, even
// though 341 bytes and 4.8MB are wildly different events semantically.
//
// The fix: before scoring (never before storage — the WAL keeps the
// original payload untouched), walk the JSON and for every numeric field
// add a sibling "<key>_mag" field holding a log10 magnitude bucket label
// ("1e2", "1e6", ...). Two payloads that differ only in a field's order
// of magnitude now differ lexically too, which is what the compressor
// actually measures. This is deliberately generic (no per-event-kind
// knowledge of which fields are "sizes") — it just treats every numeric
// value, whether a native JSON number or a numeric string, the same way.
package fingerprint

import (
	"encoding/json"
	"math"
	"strconv"
)

// Enrich returns an augmented byte representation of detail suitable for
// novelty scoring. It never mutates or drops the original fields — it
// only adds "_mag" sibling keys for numeric values, so the scorer sees
// both the exact value (for events small enough that exact-value
// redundancy still matters) and its magnitude bucket (for the cases raw
// bytes hide). If detail isn't a JSON object (e.g. malformed or a bare
// array), Enrich returns it unchanged rather than failing the event.
func Enrich(detail json.RawMessage) []byte {
	var obj map[string]any
	if err := json.Unmarshal(detail, &obj); err != nil {
		// Not an object we can walk (array, scalar, malformed) -- fall
		// back to scoring the raw bytes rather than dropping the event.
		return detail
	}

	enriched := enrichObject(obj)

	out, err := marshalSorted(enriched)
	if err != nil {
		return detail
	}
	return out
}

func enrichObject(obj map[string]any) map[string]any {
	out := make(map[string]any, len(obj)*2)
	for k, v := range obj {
		out[k] = v
		switch val := v.(type) {
		case float64:
			out[k+"_mag"] = magnitudeBucket(val)
		case string:
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				out[k+"_mag"] = magnitudeBucket(f)
			}
		case map[string]any:
			out[k] = enrichObject(val)
		}
	}
	return out
}

// magnitudeBucket returns a coarse log10 bucket label for v. Zero and
// small values near zero get their own bucket rather than a huge
// negative exponent, since "0" and "3" are meaningfully different
// magnitudes for something like a byte count even though log10 treats
// them similarly at the tails.
func magnitudeBucket(v float64) string {
	av := math.Abs(v)
	if av < 1 {
		return "0"
	}
	exp := int(math.Floor(math.Log10(av)))
	if exp < 0 {
		exp = 0
	}
	return "1e" + strconv.Itoa(exp)
}

// marshalSorted marshals a map[string]any to JSON. encoding/json already
// sorts map[string]T keys alphabetically on Marshal -- documented stdlib
// behavior, not incidental -- which is exactly the determinism this
// package needs: two payloads with the same fields must produce
// byte-identical output regardless of map iteration order, or the
// scorer would see spurious novelty from key reordering alone.
func marshalSorted(obj map[string]any) ([]byte, error) {
	return json.Marshal(obj)
}
