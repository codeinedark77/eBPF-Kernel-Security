package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/yash/driftnet/internal/novelty"
	"github.com/yash/driftnet/internal/store"
)

var uiUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Handlers holds an in-memory ring of recent events for fast dashboard
// reads, backed by the WAL for durability/history. Keeping a bounded
// in-memory tail avoids re-scanning the WAL on every dashboard poll.
type Handlers struct {
	mu      sync.RWMutex
	recent  []*store.Event
	maxKeep int

	scorers *novelty.Manager

	// flagThreshold MUST match ingest.NoveltyThreshold. It's passed in
	// explicitly (see cmd/driftnetd/main.go) rather than each package
	// hardcoding its own copy -- an earlier version had this handler
	// hardcode 0.55 independently of ingest's threshold, which had since
	// been recalibrated to 0.5. Events scoring between the two silently
	// triggered LLM triage (via ingest's threshold) but never appeared in
	// this endpoint's flagged list (using the stale 0.55) -- a real bug
	// caught by re-running the calibration smoke test after a threshold
	// change and noticing the counts didn't match.
	flagThreshold float64

	wsMu    sync.Mutex
	clients map[*websocket.Conn]bool
}

func NewHandlers(scorers *novelty.Manager, maxKeep int, flagThreshold float64) *Handlers {
	if maxKeep <= 0 {
		maxKeep = 500
	}
	return &Handlers{
		recent:        make([]*store.Event, 0, maxKeep),
		maxKeep:       maxKeep,
		scorers:       scorers,
		flagThreshold: flagThreshold,
		clients:       make(map[*websocket.Conn]bool),
	}
}

// Push adds a newly ingested (and possibly triaged) event to the tail.
func (h *Handlers) Push(ev *store.Event) {
	h.mu.Lock()
	h.recent = append(h.recent, ev)
	if len(h.recent) > h.maxKeep {
		h.recent = h.recent[len(h.recent)-h.maxKeep:]
	}
	h.mu.Unlock()

	h.broadcast(map[string]any{
		"type":  "new_event",
		"event": ev,
	})
}

// SetTriage updates a previously-pushed event's Triage field, once an
// async LLM explanation finishes. This exists to fix a real, previously
// unverified data race: an earlier version had main.go's OnFlagged
// callback mutate `ev.Triage = note` directly on the same *store.Event
// pointer already sitting in h.recent -- with zero synchronization
// against RecentEvents/FlaggedEvents concurrently reading that exact
// field while iterating h.recent under h.mu.RLock(). RWMutex only
// serializes access for goroutines that actually acquire it; a goroutine
// that mutates a field through an independent pointer reference, never
// touching h.mu at all, isn't protected by it whatsoever -- classic
// "the mutex guards the slice, not what the slice points to" mistake.
//
// No existing test caught this: ingest-package tests never construct a
// Handlers at all, and api-package tests never mutate a pushed event
// concurrently with reading it. It took a manual, non-test-driven review
// of the actual main.go wiring to find it -- worth remembering that a
// green, race-clean test suite proves the paths tests exercise are race-
// free, not that no race exists anywhere in the program.
func (h *Handlers) SetTriage(seq uint64, note string) {
	h.mu.Lock()
	for _, ev := range h.recent {
		if ev.Seq == seq {
			ev.Triage = note
			h.mu.Unlock()
			h.broadcast(map[string]any{
				"type":   "triage_update",
				"seq":    seq,
				"triage": note,
			})
			return
		}
	}
	h.mu.Unlock()
}

func (h *Handlers) RecentEvents(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*store.Event, len(h.recent))
	copy(out, h.recent)
	// newest first
	sort.Slice(out, func(i, j int) bool { return out[i].Seq > out[j].Seq })
	writeJSON(w, out)
}

func (h *Handlers) FlaggedEvents(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []*store.Event
	for _, ev := range h.recent {
		if ev.NCDScore >= h.flagThreshold || len(ev.RuleMatches) > 0 {
			out = append(out, ev)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq > out[j].Seq })
	writeJSON(w, out)
}

// Sources returns the distinct device:app pairs the dashboard should
// list, deduped from novelty.Manager's internal keys.
//
// Manager's keys are kind-qualified (device:app:kind, see
// ingest.ScoringKey) so that each event kind gets its own baseline --
// mixing network/crypto/fs events into one baseline made attribution
// useless for a kind's first occurrence (see driftnet's README). The
// dashboard wants one sidebar entry per app, not per app-per-kind, so
// strip the kind suffix and dedupe here at the API layer, which already
// understands this domain-specific key convention. novelty.Manager
// itself stays a generic, convention-agnostic key/baseline store -- it
// has no idea "kind" exists, and shouldn't need to.
func (h *Handlers) Sources(w http.ResponseWriter, r *http.Request) {
	raw := h.scorers.Sources()
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, key := range raw {
		idx := strings.LastIndex(key, ":")
		display := key
		if idx != -1 {
			display = key[:idx]
		}
		if !seen[display] {
			seen[display] = true
			out = append(out, display)
		}
	}
	sort.Strings(out)
	writeJSON(w, map[string]any{
		"sources": out,
	})
}

func (h *Handlers) HandleUIWS(w http.ResponseWriter, r *http.Request) {
	conn, err := uiUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	h.wsMu.Lock()
	h.clients[conn] = true
	h.wsMu.Unlock()

	defer func() {
		h.wsMu.Lock()
		delete(h.clients, conn)
		h.wsMu.Unlock()
		conn.Close()
	}()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func (h *Handlers) broadcast(msg any) {
	h.wsMu.Lock()
	defer h.wsMu.Unlock()
	for conn := range h.clients {
		if err := conn.WriteJSON(msg); err != nil {
			conn.Close()
			delete(h.clients, conn)
		}
	}
}

func (h *Handlers) ExportSARIF(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var results []any
	for _, ev := range h.recent {
		if ev.NCDScore >= h.flagThreshold || len(ev.RuleMatches) > 0 {
			message := "High novelty event"
			if len(ev.RuleMatches) > 0 {
				message = "Rule matches: " + strings.Join(ev.RuleMatches, ", ")
			}
			if ev.Triage != "" {
				message += "\nTriage: " + ev.Triage
			}
			results = append(results, map[string]any{
				"ruleId": "DRIFTNET-001",
				"message": map[string]any{
					"text": message,
				},
				"locations": []any{
					map[string]any{
						"physicalLocation": map[string]any{
							"artifactLocation": map[string]any{
								"uri": "device://" + ev.Device + "/" + ev.App,
							},
						},
					},
				},
			})
		}
	}

	sarif := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{
			map[string]any{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":    "Driftnet",
						"version": "1.0",
					},
				},
				"results": results,
			},
		},
	}
	writeJSON(w, sarif)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
