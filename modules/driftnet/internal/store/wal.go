// Package store implements a minimal write-ahead-logged event store.
// Every ingested event is appended as a length-prefixed JSON record and
// fsync'd, so a crash mid-write loses at most the last partial record
// (detected and truncated on recovery, not silently corrupting the log).
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yash/driftnet/internal/attribution"
	_ "modernc.org/sqlite"
)

// Event is a single instrumented observation from a Frida agent.
type Event struct {
	Seq       uint64          `json:"seq"`
	Timestamp time.Time       `json:"timestamp"`
	Device    string          `json:"device"` // e.g. "oneplus9r"
	App       string          `json:"app"`    // package name under test
	Kind      string          `json:"kind"`   // "network" | "crypto" | "fs" | "ipc" | "custom"
	Detail    json.RawMessage `json:"detail"` // raw hook payload, kind-specific shape
	// AppVersion is "versionName:versionCode", captured once per Frida
	// agent attach (see agent/hooks.js's resolveAppVersion) and stamped
	// on every event from that session. Feeds rules.Evaluator's
	// app_updated detection -- a new version appearing mid-stream is
	// itself informative, independent of anything else about the event.
	AppVersion string  `json:"app_version,omitempty"`
	NCDScore   float64 `json:"ncd_score"`
	// SecondaryScore is an independent novelty measurement using DEFLATE
	// instead of zstd (see novelty/secondary.go), computed against its
	// own separate rolling baseline. Zero if the secondary scorer wasn't
	// configured. Exists to surface disagreement between two
	// architecturally different compressors as its own signal -- see the
	// "compressor_disagreement" rule match, which fires specifically
	// when NCDScore and SecondaryScore land on opposite sides of their
	// respective thresholds.
	SecondaryScore float64 `json:"secondary_score,omitempty"`
	// RuleMatches holds names of known-bad-pattern rules that fired on
	// this event (e.g. "weak_cipher", "sensitive_path"), independent of
	// the compression-based novelty score. Empty if none matched. See
	// internal/rules -- compression novelty answers "does this look
	// unlike anything before," rules answer "does this match a known-bad
	// shape regardless of how novel it looks." An event can be flagged by
	// either mechanism alone.
	RuleMatches []string `json:"rule_matches,omitempty"`
	// Attribution holds per-field novelty attribution (internal/attribution),
	// computed only for flagged events (NCDScore above threshold or a rule
	// matched) -- it costs several extra compression passes, wasted work
	// for the vast majority of events nobody will ever look at.
	//
	// Computed EAGERLY at ingest time, against the baseline snapshot from
	// just before this event was folded in -- not lazily on a later API
	// request. That distinction matters: an earlier version computed this
	// on-demand via a separate endpoint, using whatever the live baseline
	// happened to be when someone clicked to view it. By then the real
	// event (and possibly others after it) had already been folded into
	// that same baseline, so every field's masked variant was being
	// compared against a baseline that already contained an exact copy of
	// the original -- collapsing every field's delta toward the same
	// small, uninformative number. See novelty.Manager.PeekScore's doc for
	// the full account of how this was caught and fixed.
	Attribution []attribution.FieldAttribution `json:"attribution,omitempty"`
	Triage      string                         `json:"triage,omitempty"` // filled in async by the triage worker
}

type WAL struct {
	mu      sync.Mutex
	db      *sql.DB
	nextSeq uint64
}

func Open(dir string) (*WAL, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir wal dir: %w", err)
	}
	path := filepath.Join(dir, "events.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			seq INTEGER PRIMARY KEY,
			payload TEXT
		)
	`)
	if err != nil {
		return nil, err
	}

	var maxSeq sql.NullInt64
	err = db.QueryRow(`SELECT MAX(seq) FROM events`).Scan(&maxSeq)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	nextSeq := uint64(1)
	if maxSeq.Valid {
		nextSeq = uint64(maxSeq.Int64) + 1
	}

	return &WAL{
		db:      db,
		nextSeq: nextSeq,
	}, nil
}

func (w *WAL) Append(ev *Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	ev.Seq = w.nextSeq
	w.nextSeq++
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	_, err = w.db.Exec(`INSERT INTO events (seq, payload) VALUES (?, ?)`, ev.Seq, string(payload))
	return err
}

func (w *WAL) Replay(fn func(*Event) error) error {
	rows, err := w.db.Query(`SELECT payload FROM events ORDER BY seq ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return err
		}
		var ev Event
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			return err
		}
		if err := fn(&ev); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.db.Close()
}
