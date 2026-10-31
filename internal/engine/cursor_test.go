package engine

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCursorRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "cursor.json")

	c, corrupted := LoadCursor(path) // missing -> fresh, not corrupt
	if corrupted {
		t.Fatal("missing cursor reported corrupted")
	}
	if len(c.Offsets) != 0 {
		t.Errorf("fresh cursor should be empty, got %v", c.Offsets)
	}
	c.Offsets["/var/log/audit.log"] = 4096
	if err := c.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	c2, corrupted := LoadCursor(path)
	if corrupted {
		t.Fatal("round-tripped cursor reported corrupted")
	}
	if c2.Offsets["/var/log/audit.log"] != 4096 {
		t.Errorf("offset not persisted: %v", c2.Offsets)
	}
}

func TestCursorOpenAtSeeksAndHandlesRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(logPath, []byte("line1\nline2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Cursor{Offsets: map[string]int64{logPath: 6}} // after "line1\n"

	ch, err := c.OpenAt(logPath)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	data, _ := io.ReadAll(ch)
	_ = ch.Close()
	if string(data) != "line2\n" {
		t.Errorf("read from offset = %q, want %q", data, "line2\n")
	}
	if ch.NextOffset() != 12 {
		t.Errorf("NextOffset = %d, want 12", ch.NextOffset())
	}

	// Rotation: stored offset beyond the (now shorter) file -> reread from 0.
	if err := os.WriteFile(logPath, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.Offsets[logPath] = 999
	ch, err = c.OpenAt(logPath)
	if err != nil {
		t.Fatalf("OpenAt after rotation: %v", err)
	}
	data, _ = io.ReadAll(ch)
	_ = ch.Close()
	if string(data) != "new\n" {
		t.Errorf("after rotation read = %q, want %q", data, "new\n")
	}
	if ch.NextOffset() != 4 {
		t.Errorf("after rotation NextOffset = %d, want 4", ch.NextOffset())
	}
}

// TestChunkAdvancesToLastNewline is the A2 regression: the cursor must advance
// to the end of the last COMPLETE line, not to the stat size. OLD behavior
// returned the stat size (here 11), consuming the partial trailing "partial"
// and losing it next run; the fix leaves it at 4 (after "a\nb\n").
func TestChunkAdvancesToLastNewline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	if err := os.WriteFile(p, []byte("a\nb\npartial"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Cursor{Offsets: map[string]int64{}}
	ch, err := c.OpenAt(p)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(ch)
	_ = ch.Close()
	if ch.NextOffset() != 4 {
		t.Errorf("NextOffset = %d, want 4 (end of last complete line, not the stat size 11)", ch.NextOffset())
	}
}

// TestChunkDetectsRotationByInode is the A3 regression: when the file is
// replaced (new inode) and the new file is LONGER than the old offset, the
// old size-only heuristic (start>size) did not notice and skipped the new
// file's first bytes. Tracking the inode catches the rotation and reads the
// new file from 0.
func TestChunkDetectsRotationByInode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(p, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Cursor{Offsets: map[string]int64{}, Inodes: map[string]uint64{}}

	ch1, err := c.OpenAt(p)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(ch1)
	_ = ch1.Close()
	if ch1.Ino() == 0 {
		t.Skip("inode not available on this platform")
	}
	c.Offsets[p] = ch1.NextOffset() // 4
	c.Inodes[p] = ch1.Ino()

	// Rotate: replace the file with a new, LONGER file (new inode) -- the
	// case the old start>size heuristic misses.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("brand-new-and-longer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ch2, err := c.OpenAt(p)
	if err != nil {
		t.Fatal(err)
	}
	if ch2.Ino() == c.Inodes[p] {
		t.Skip("OS reused the inode; cannot exercise rotation")
	}
	data, _ := io.ReadAll(ch2)
	_ = ch2.Close()
	if string(data) != "brand-new-and-longer\n" {
		t.Errorf("after rotation read %q, want the whole new file (old heuristic skipped its first 4 bytes)", data)
	}
}

// TestChunkDoesNotReadPastSize is the A2 regression for duplicate alerts: the
// Chunk reads only the bytes present when it was opened, so data appended
// during the scan is neither read now (OLD code read to EOF) nor skipped next
// run (OLD code advanced to the old stat size and re-read the appendage).
func TestChunkDoesNotReadPastSize(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	if err := os.WriteFile(p, []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Cursor{Offsets: map[string]int64{}}
	ch, err := c.OpenAt(p)
	if err != nil {
		t.Fatal(err)
	}
	// Append after opening: this must not appear in the read.
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("three\n")
	_ = f.Close()

	data, _ := io.ReadAll(ch)
	_ = ch.Close()
	if string(data) != "one\ntwo\n" {
		t.Errorf("read %q, want %q (must not read bytes appended after open)", data, "one\ntwo\n")
	}
	if ch.NextOffset() != 8 {
		t.Errorf("NextOffset = %d, want 8 (the appendage is picked up next run, not duplicated)", ch.NextOffset())
	}
}

// LoadCursor must never fail: every bad cursor shape — missing, empty,
// whitespace, truncated, corrupt JSON, binary garbage — is recovered to a
// usable fresh cursor so banken keeps detecting (never die, always
// recoverable). Only a non-empty unparseable file reports corrupted=true.
func TestCursorAlwaysRecoverable(t *testing.T) {
	cases := []struct {
		name      string
		write     bool
		content   string
		corrupted bool
	}{
		{"missing", false, "", false},
		{"empty", true, "", false},
		{"whitespace", true, "   \n\t", false},
		{"corrupt", true, "{not json", true},
		{"truncated", true, `{"offsets":{"a":1`, true},
		{"garbage", true, "\x00\xff\xfe binary \x01", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "cursor.json")
			if tc.write {
				if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			c, corrupted := LoadCursor(path)
			if c == nil || c.Offsets == nil {
				t.Fatal("LoadCursor returned an unusable cursor")
			}
			if len(c.Offsets) != 0 {
				t.Errorf("recovered cursor should be empty, got %v", c.Offsets)
			}
			if corrupted != tc.corrupted {
				t.Errorf("corrupted = %v, want %v", corrupted, tc.corrupted)
			}
		})
	}
}
