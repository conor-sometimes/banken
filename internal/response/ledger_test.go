package response

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLedgerRecordDecision(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLedger(dir)
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}
	// Fixed clock so the file name is predictable.
	fixed := time.Date(2026, 10, 31, 6, 12, 3, 0, time.UTC)
	l.now = func() time.Time { return fixed }

	p := mustPolicy(t, observePolicy)
	a := procAlert()
	d := Decide(Input{Alert: a, Policy: p, Budget: Budget{RunLimit: 3, HourLimit: 10}})

	id, err := l.RecordDecision(a, d, p.Hash(), p.Mode, false, "0.0.0-test")
	if err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if id == "" {
		t.Fatalf("empty id")
	}

	// File is named for the alert's day.
	path := filepath.Join(dir, "decisions-2026-10-31.jsonl")
	f, err := os.Open(path) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatalf("no line written")
	}
	var line decisionLine
	if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
		t.Fatalf("unmarshal line: %v", err)
	}
	if line.ID != id {
		t.Errorf("line id = %q, want %q", line.ID, id)
	}
	if line.Phase != "decided" {
		t.Errorf("phase = %q, want decided", line.Phase)
	}
	if line.Decision.Intended != ActionFreeze || line.Decision.Action != ActionNone {
		t.Errorf("decision = %+v, want intended=freeze action=none", line.Decision)
	}
	if line.Decision.Rail != RailObserve {
		t.Errorf("rail = %q, want observe-mode", line.Decision.Rail)
	}
	if line.Policy != p.Hash() {
		t.Errorf("policy hash = %q, want %q", line.Policy, p.Hash())
	}
	if line.Alert.Rule != "reverse_shell" {
		t.Errorf("alert rule = %q", line.Alert.Rule)
	}
}

func TestLedgerAppends(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLedger(dir)
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}
	a := procAlert()
	d := Decision{Intended: ActionFreeze, Action: ActionNone, Rail: RailObserve, Reason: "x"}
	for i := 0; i < 3; i++ {
		if _, err := l.RecordDecision(a, d, "sha256:x", ModeObserve, false, "t"); err != nil {
			t.Fatalf("RecordDecision %d: %v", i, err)
		}
	}
	path := filepath.Join(dir, "decisions-"+a.Time.UTC().Format(ledgerDayLayout)+".jsonl")
	data, err := os.ReadFile(path) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := bytes.Count(data, []byte("\n")); n != 3 {
		t.Errorf("wrote %d lines, want 3", n)
	}
}
