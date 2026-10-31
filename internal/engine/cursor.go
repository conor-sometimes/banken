package engine

import (
	"encoding/json"
	"errors"
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

// LoadCursor reads a cursor from path. A missing file yields an empty
// cursor (first run), not an error.
func LoadCursor(path string) (*Cursor, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied state path
	if errors.Is(err, os.ErrNotExist) {
		return &Cursor{Offsets: map[string]int64{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cursor: read %s: %w", path, err)
	}
	var c Cursor
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("cursor: parse %s: %w", path, err)
	}
	if c.Offsets == nil {
		c.Offsets = map[string]int64{}
	}
	return &c, nil
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
