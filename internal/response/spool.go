package response

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Spool is the on-disk work-order queue between the daemon and the drain. The
// daemon writes an order to a sibling tmp directory, fsyncs it, and renames it
// into the spool directory; because rename(2) between two directories on one
// filesystem is atomic, the drain (woken by a path unit's DirectoryNotEmpty)
// only ever sees complete orders. The two directories are siblings, not a
// dotfile inside spool/, so a half-written order never makes the path unit
// fire a drain that finds nothing to do. See §2.2.
//
// A Spool is safe for concurrent use: each order has a unique id (the decided
// ledger line's id), so two writers never target one name, and the methods
// hold no shared state.
type Spool struct {
	dir    string
	tmpDir string
	now    func() time.Time
}

// NewSpool opens (creating if needed) the spool and its sibling tmp directory,
// both 0700. tmpDir must be a sibling of dir on the same filesystem for the
// rename to be atomic; the caller (main.setupResponder / the drain) derives
// both from the state dir, so this holds by construction.
func NewSpool(dir, tmpDir string) (*Spool, error) {
	for _, d := range []string{dir, tmpDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("response: create spool dir %s: %w", d, err)
		}
	}
	return &Spool{dir: dir, tmpDir: tmpDir, now: time.Now}, nil
}

// orderName is the spool filename for an order: its id plus .json. The id is a
// time-ordered hex string, so lexical order of names is time order.
func orderName(id string) string { return id + ".json" }

// Write persists one order durably and atomically: marshal, write to
// tmpDir/<id>.json, fsync the file, close, then rename into dir/<id>.json. A
// crash before the rename leaves only a tmp file (swept by SweepTmp); a crash
// after it leaves a complete order. The daemon must NOT write a half order
// into dir/, which is why the tmp file lives in the sibling directory.
func (s *Spool) Write(o Order) error {
	buf, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("response: marshal work order %s: %w", o.ID, err)
	}
	name := orderName(o.ID)
	tmpPath := filepath.Join(s.tmpDir, name)
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("response: open spool tmp %s: %w", tmpPath, err)
	}
	if _, err := f.Write(buf); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("response: write spool tmp %s: %w", tmpPath, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("response: fsync spool tmp %s: %w", tmpPath, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("response: close spool tmp %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, filepath.Join(s.dir, name)); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("response: rename spool order %s: %w", name, err)
	}
	return nil
}

// List returns the order filenames in the spool, sorted by name (time order,
// oldest first), so the drain processes orders in the order they were decided.
// Non-.json entries and the tmp directory are ignored.
func (s *Spool) List() ([]string, error) {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("response: list spool %s: %w", s.dir, err)
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// Read parses one order by filename. A read error (the file vanished, an I/O
// fault) is returned as-is; bad JSON or a failed validate (bad version, no
// target) is wrapped with ErrMalformed, so the drain can tell a malformed
// order (record, unlink) from a transient disk fault (fail closed) with
// errors.Is rather than string matching.
func (s *Spool) Read(name string) (Order, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, name)) //nolint:gosec // spool dir is 0700 root, same trust as the ledger
	if err != nil {
		return Order{}, fmt.Errorf("response: read spool order %s: %w", name, err)
	}
	var o Order
	if err := json.Unmarshal(data, &o); err != nil {
		return Order{}, fmt.Errorf("%w: order %s: %s", ErrMalformed, name, err.Error())
	}
	if err := o.validate(); err != nil {
		return Order{}, err
	}
	return o, nil
}

// Remove unlinks a processed order. A failure to remove is returned: the drain
// treats it as the one fatal error (an order it cannot unlink would be drained
// again forever), so the path unit's rate limit can stop the retry storm while
// the journal says why.
func (s *Spool) Remove(name string) error {
	if err := os.Remove(filepath.Join(s.dir, name)); err != nil {
		return fmt.Errorf("response: remove spool order %s: %w", name, err)
	}
	return nil
}

// SweepTmp removes tmp-directory entries older than maxAge: orders the daemon
// began writing but never renamed (a crash between write and rename). It
// returns the number swept. A tmp file younger than maxAge may be a write in
// flight, so it is left alone. Errors removing an individual entry are
// returned joined, never fatal to the drain (the entry is retried next sweep).
func (s *Spool) SweepTmp(maxAge time.Duration) (int, error) {
	ents, err := os.ReadDir(s.tmpDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("response: list spool tmp %s: %w", s.tmpDir, err)
	}
	cutoff := s.now().Add(-maxAge)
	swept := 0
	var errs []error
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(s.tmpDir, e.Name())); err != nil {
			errs = append(errs, err)
			continue
		}
		swept++
	}
	if len(errs) > 0 {
		return swept, fmt.Errorf("response: sweep spool tmp: %w", errors.Join(errs...))
	}
	return swept, nil
}
