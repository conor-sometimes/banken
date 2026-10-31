package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Cursor records, per input file, how many bytes banken has already
// consumed, so a one-shot run reads only what is new since last time. It
// is persisted as JSON so it survives between timer-driven runs.
type Cursor struct {
	// Offsets maps an input file path to the byte offset read up to.
	Offsets map[string]int64 `json:"offsets"`
}

// LoadCursor reads a cursor from path and never fails: it always returns a
// usable cursor. A missing, empty, or unreadable file is a silent fresh start
// (first run). A non-empty file that does not parse is also recovered to a
// fresh cursor but reports corrupted=true so the caller can warn. This is the
// EDR-availability rule — losing the cursor means at worst re-reading a log
// once (a possible duplicate alert, self-healed by the next Save), whereas
// halting on a bad byte would silently stop protection.
func LoadCursor(path string) (c *Cursor, corrupted bool) {
	fresh := &Cursor{Offsets: map[string]int64{}}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied state path
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return fresh, false // missing / unreadable / empty -> fresh, nothing to warn about
	}
	var loaded Cursor
	if err := json.Unmarshal(data, &loaded); err != nil {
		return fresh, true // corrupt content -> fresh + signal; re-read from the top this pass
	}
	if loaded.Offsets == nil {
		loaded.Offsets = map[string]int64{}
	}
	return &loaded, false
}

// Save atomically writes the cursor to path (write-temp-then-rename), so a
// crash mid-write never leaves a half-written cursor that would reset
// every input to offset 0.
func (c *Cursor) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("cursor: create dir: %w", err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("cursor: marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("cursor: write temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("cursor: rename: %w", err)
	}
	return nil
}

// OpenAt opens path and seeks to the stored offset for it, returning a
// reader over the new bytes and the new end offset to store after a
// successful read. If the file is shorter than the stored offset (it was
// rotated or truncated), it starts from 0 so no events are missed.
//
// The caller is responsible for closing the returned file.
func (c *Cursor) OpenAt(path string) (f *os.File, newOffset int64, err error) {
	f, err = os.Open(path) //nolint:gosec // operator-supplied input path
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	size := info.Size()
	start := c.Offsets[path]
	if start > size {
		start = 0 // rotated/truncated -- reread from the top
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, size, nil
}
