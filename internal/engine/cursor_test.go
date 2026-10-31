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

	c, err := LoadCursor(path) // missing -> empty, not an error
	if err != nil {
		t.Fatalf("LoadCursor missing: %v", err)
	}
	if len(c.Offsets) != 0 {
		t.Errorf("fresh cursor should be empty, got %v", c.Offsets)
	}
	c.Offsets["/var/log/audit.log"] = 4096
	if err := c.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	c2, err := LoadCursor(path)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
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

	f, newOffset, err := c.OpenAt(logPath)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	data, _ := io.ReadAll(f)
	_ = f.Close()
	if string(data) != "line2\n" {
		t.Errorf("read from offset = %q, want %q", data, "line2\n")
	}
	if newOffset != 12 {
		t.Errorf("newOffset = %d, want 12", newOffset)
	}

	// Rotation: stored offset beyond the (now shorter) file -> reread from 0.
	if err := os.WriteFile(logPath, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.Offsets[logPath] = 999
	f, newOffset, err = c.OpenAt(logPath)
	if err != nil {
		t.Fatalf("OpenAt after rotation: %v", err)
	}
	data, _ = io.ReadAll(f)
	_ = f.Close()
	if string(data) != "new\n" {
		t.Errorf("after rotation read = %q, want %q", data, "new\n")
	}
	if newOffset != 4 {
		t.Errorf("after rotation newOffset = %d, want 4", newOffset)
	}
}

func TestCursorParseError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cursor.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCursor(path); err == nil {
		t.Error("expected parse error for malformed cursor file")
	}
}
