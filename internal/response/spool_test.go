package response

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newSpool(t *testing.T) *Spool {
	t.Helper()
	root := t.TempDir()
	s, err := NewSpool(filepath.Join(root, "spool"), filepath.Join(root, "spool.tmp"))
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	return s
}

func sampleOrder(id string) Order {
	return Order{
		Version:  OrderVersion,
		ID:       id,
		Time:     time.Date(2026, 11, 2, 6, 12, 3, 0, time.UTC),
		Alert:    procAlert(),
		Decision: Decision{Intended: ActionFreeze, Action: ActionFreeze, Target: Target{Process: &ProcessRef{PID: 4242, Image: "/tmp/.x/sh"}}},
		Policy:   "sha256:abc",
		Banken:   "test",
	}
}

// A written order lands in spool/, round-trips through Read, and leaves the tmp
// directory empty (write + fsync + rename, no half order in spool/).
func TestSpoolWriteReadRoundTrip(t *testing.T) {
	s := newSpool(t)
	want := sampleOrder("0189aa")
	if err := s.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}

	names, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 1 || names[0] != "0189aa.json" {
		t.Fatalf("List = %v, want [0189aa.json]", names)
	}

	// The tmp directory holds no leftover (the rename moved the file out).
	tmpEnts, _ := os.ReadDir(s.tmpDir)
	if len(tmpEnts) != 0 {
		t.Fatalf("tmp dir not empty after write: %d entries", len(tmpEnts))
	}

	got, err := s.Read(names[0])
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.ID != want.ID || got.Decision.Action != ActionFreeze || got.Decision.Target.Process.PID != 4242 {
		t.Fatalf("Read = %+v, want id/freeze/pid4242", got)
	}
	if err := s.Remove(names[0]); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if names, _ := s.List(); len(names) != 0 {
		t.Fatalf("spool not empty after Remove: %v", names)
	}
}

// List is sorted by name (time order), oldest first.
func TestSpoolListSorted(t *testing.T) {
	s := newSpool(t)
	for _, id := range []string{"0003", "0001", "0002"} {
		if err := s.Write(sampleOrder(id)); err != nil {
			t.Fatal(err)
		}
	}
	names, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"0001.json", "0002.json", "0003.json"}
	for i, n := range names {
		if n != want[i] {
			t.Fatalf("List = %v, want %v", names, want)
		}
	}
}

// Bad JSON and a bad version are both ErrMalformed, distinguishable from an
// I/O read error by errors.Is, so the drain never branches on a string.
func TestSpoolReadMalformed(t *testing.T) {
	s := newSpool(t)

	badJSON := filepath.Join(s.dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read("bad.json"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bad JSON: err = %v, want ErrMalformed", err)
	}

	// Wrong version.
	o := sampleOrder("verwrong")
	o.Version = 99
	raw, _ := json.Marshal(o)
	if err := os.WriteFile(filepath.Join(s.dir, "verwrong.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read("verwrong.json"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bad version: err = %v, want ErrMalformed", err)
	}

	// No target.
	o2 := sampleOrder("notgt")
	o2.Decision.Target = Target{}
	raw2, _ := json.Marshal(o2)
	if err := os.WriteFile(filepath.Join(s.dir, "notgt.json"), raw2, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read("notgt.json"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("no target: err = %v, want ErrMalformed", err)
	}

	// A missing file is a read error, NOT malformed.
	if _, err := s.Read("absent.json"); err == nil || errors.Is(err, ErrMalformed) {
		t.Fatalf("missing file: err = %v, want a non-malformed read error", err)
	}
}

// SweepTmp removes tmp entries older than maxAge (a daemon crash between write
// and rename) and leaves younger ones (a write in flight).
func TestSpoolSweepTmp(t *testing.T) {
	s := newSpool(t)
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	old := filepath.Join(s.tmpDir, "old.json")
	fresh := filepath.Join(s.tmpDir, "fresh.json")
	for _, p := range []string{old, fresh} {
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Age the old file past maxAge; leave fresh at "now".
	oldTime := now.Add(-30 * time.Minute)
	if err := os.Chtimes(old, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(fresh, now, now); err != nil {
		t.Fatal(err)
	}

	swept, err := s.SweepTmp(10 * time.Minute)
	if err != nil {
		t.Fatalf("SweepTmp: %v", err)
	}
	if swept != 1 {
		t.Fatalf("swept %d, want 1", swept)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old tmp order not swept")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh tmp order wrongly swept: %v", err)
	}
}
