// Package attribution provides a compression-based explanation for why a
// given event scored the novelty it did, by leave-one-field-out
// re-scoring: blank one JSON field's value at a time, re-score the
// resulting variant against the same baseline, and see how much the
// score drops. The field whose blanking drops the score the most is
// treated as the biggest contributor to that event's novelty.
//
// This is deliberately NOT a formal Shapley-value computation (which
// would score every subset of fields, exponential in field count). It's
// a cheap, single-pass approximation in the same spirit: attribute an
// outcome to its inputs by observing what changes when one input is
// blanked at a time. Good enough to answer "which field should I look at
// first" -- not rigorous enough for strong claims about field
// interactions (two fields that are only jointly informative would each
// show a small individual delta even though together they matter).
//
// MASKING STRATEGY, AND A REAL CONFOUND FOUND WHILE BUILDING THIS: the
// first version masked a field by deleting its key entirely. A direct
// measurement (isolated zstd experiment, not just eyeballing the
// integration test) showed this was wrong: deleting a key changes the
// object's arity (4 keys instead of 5), and a baseline trained entirely
// on 5-key events treats ANY 4-key object as structurally novel,
// independent of which key is missing. Concretely: masking "transport"
// -- a field that is byte-identical across every baseline event AND the
// anomalous event -- still *increased* the measured score by 0.071 in a
// controlled test, when it should have contributed ~0.
//
// The fix: replace the field's value with a type-preserving zero value
// ("" for strings, 0 for numbers, false for bools, {} / [] for
// objects/arrays) instead of deleting the key. This keeps the object's
// key set and each value's JSON type identical to the original, so only
// that one field's actual content changes. The same controlled test
// showed this roughly halves the confound (0.071 -> 0.034) but does NOT
// eliminate it -- a blanked-but-present field still isn't byte-identical
// to its original context, so there's a smaller residual cost baked into
// every attribution. Reporting that honestly rather than claiming this
// is now exact: treat Delta as a directional signal ("this field matters
// more than that one"), not a precise, confound-free measurement.
package attribution

import (
	"encoding/json"
	"fmt"
	"sort"
)

// FieldAttribution is one field's estimated contribution to an event's
// novelty score.
type FieldAttribution struct {
	Field string  `json:"field"`
	Delta float64 `json:"delta"` // originalScore - blankedScore; higher = more responsible
}

// PeekScorer scores a payload against a baseline without mutating that
// baseline. Satisfied by novelty.Manager.PeekScore bound to a source.
type PeekScorer func(payload []byte) (float64, error)

// Enricher matches fingerprint.Enrich's signature. Blanked variants MUST
// go through the same enrichment the real scoring pipeline uses, or
// blanked scores aren't comparable to the original score.
type Enricher func(detail json.RawMessage) []byte

// Explain returns per-field attributions for detail, sorted by Delta
// descending (most responsible field first). originalScore must be the
// score already computed for detail via the normal pipeline (enrich then
// score) -- Explain does not recompute it, so the "original" side of
// every delta is guaranteed to be the exact score already shown to the
// person, not a fresh computation that could differ by floating-point
// noise or a baseline that shifted between calls.
//
// Returns an error if detail isn't a JSON object (nothing to attribute
// to -- arrays and scalars have no named fields) or if peek fails (e.g.
// no baseline exists yet for this source).
func Explain(detail json.RawMessage, enrich Enricher, peek PeekScorer, originalScore float64) ([]FieldAttribution, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(detail, &obj); err != nil {
		return nil, fmt.Errorf("attribution: detail is not a JSON object: %w", err)
	}
	if len(obj) == 0 {
		return nil, nil
	}

	out := make([]FieldAttribution, 0, len(obj))
	for key := range obj {
		blanked := blankField(obj, key)
		blankedBytes, err := json.Marshal(blanked)
		if err != nil {
			// Shouldn't happen -- blanked is built entirely from
			// already-valid RawMessage values from a successful
			// Unmarshal above -- but don't let one field's marshal
			// failure take down attribution for every other field.
			continue
		}

		enriched := enrich(blankedBytes)
		blankedScore, err := peek(enriched)
		if err != nil {
			return nil, fmt.Errorf("attribution: peek score for field %q: %w", key, err)
		}

		out = append(out, FieldAttribution{
			Field: key,
			Delta: originalScore - blankedScore,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Delta > out[j].Delta })
	return out, nil
}

// blankField returns a copy of obj with target's value replaced by a
// type-preserving zero value, keeping every other field's byte
// representation exactly as received (map[string]json.RawMessage, not
// map[string]any, so there's no float64 round-tripping or re-formatting
// of nested structures to worry about).
func blankField(obj map[string]json.RawMessage, target string) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(obj))
	for k, v := range obj {
		if k == target {
			out[k] = blankValue(v)
		} else {
			out[k] = v
		}
	}
	return out
}

// blankValue returns a same-type, minimal-information replacement for a
// raw JSON value, inferred from its first byte.
func blankValue(v json.RawMessage) json.RawMessage {
	if len(v) == 0 {
		return v
	}
	switch v[0] {
	case '"':
		return json.RawMessage(`""`)
	case '{':
		return json.RawMessage(`{}`)
	case '[':
		return json.RawMessage(`[]`)
	case 't', 'f':
		return json.RawMessage(`false`)
	case 'n':
		return v // already null
	default:
		return json.RawMessage(`0`) // number
	}
}
