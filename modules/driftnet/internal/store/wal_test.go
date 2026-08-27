package store

import (
	"encoding/json"
	"testing"
)

func TestWAL_AppendAndReplay(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		ev := &Event{
			Device: "oneplus9r",
			App:    "com.test.app",
			Kind:   "network",
			Detail: json.RawMessage(`{"n":` + string(rune('0'+i)) + `}`),
		}
		if err := w.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()

	w2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()

	count := 0
	var lastSeq uint64
	err = w2.Replay(func(ev *Event) error {
		count++
		lastSeq = ev.Seq
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("expected 5 events on replay, got %d", count)
	}
	if lastSeq != 5 {
		t.Fatalf("expected last seq 5, got %d", lastSeq)
	}
}
