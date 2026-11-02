package view

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"time"

	"github.com/conor-sometimes/banken/internal/response"
)

// Store file names, matching the executor's writer (store.go / exec_linux.go).
const (
	manifestName     = "manifest.json"
	freezeThawedName = "thawed.json"
	quarRestoredName = "restored.json"
	unhashedSentinel = "unhashed"
	methodRename     = "rename"
	methodNeuter     = "neuter"
	methodSigstop    = "sigstop"
)

// errNoManifest is returned when a store entry directory has no manifest.json.
var errNoManifest = errors.New("view: store entry has no manifest")

// FreezeManifest mirrors the freeze store manifest (docs §2.7). The view reads
// the fields §3.1 classifies over: the method and boot id (reboot loss), the
// pids and cgroup (containment), and the target (what list/explain name).
type FreezeManifest struct {
	ID      string         `json:"id"`
	Version int            `json:"version"`
	Order   string         `json:"order,omitempty"`
	State   string         `json:"state"`
	Method  string         `json:"method"`
	Target  FreezeTarget   `json:"target"`
	Scope   response.Scope `json:"scope,omitempty"`
	PIDs    []int          `json:"pids"`
	Orig    map[int]string `json:"orig,omitempty"`
	Cgroup  string         `json:"cgroup,omitempty"`
	Time    time.Time      `json:"time"`
	BootID  string         `json:"bootId,omitempty"`
}

// FreezeTarget is the identity identify() bound before the freeze.
type FreezeTarget struct {
	PID       int       `json:"pid"`
	Exe       string    `json:"exe,omitempty"`
	StartTime time.Time `json:"startTime,omitzero"`
}

// FileStat mirrors the quarantined inode's recorded identity and metadata. The
// view compares (Dev, Ino) against the live inode for the inode-replaced check
// and reapplies nothing (restore owns that).
type FileStat struct {
	Dev   uint64 `json:"dev"`
	Ino   uint64 `json:"ino"`
	Mode  uint32 `json:"mode"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	Size  int64  `json:"size"`
	MTime string `json:"mtime"`
	Nlink uint64 `json:"nlink"`
}

// QuarManifest mirrors the quarantine store manifest (docs quarantine.md §3.5).
type QuarManifest struct {
	ID        string    `json:"id"`
	Version   int       `json:"version"`
	Order     string    `json:"order,omitempty"`
	State     string    `json:"state"`
	OrigPath  string    `json:"origPath"`
	Method    string    `json:"method"`
	Stat      FileStat  `json:"stat"`
	SHA256    string    `json:"sha256"`
	Immutable bool      `json:"immutable"`
	Time      time.Time `json:"time"`
	BootID    string    `json:"bootId,omitempty"`
}

// EvidenceManifest mirrors the evidence (collect) store manifest.
type EvidenceManifest struct {
	ID        string    `json:"id"`
	Version   int       `json:"version"`
	Order     string    `json:"order,omitempty"`
	State     string    `json:"state"`
	PID       int       `json:"pid"`
	Exe       string    `json:"exe,omitempty"`
	StartTime time.Time `json:"startTime,omitzero"`
	SHA256    string    `json:"sha256,omitempty"`
	Time      time.Time `json:"time"`
}

// FreezeThawed is the freeze tombstone; its presence means the handle is
// thawed and a reader shows "thawed <time>" rather than reading the cgroup.
type FreezeThawed struct {
	Time        time.Time      `json:"time"`
	OperatorUID int            `json:"operatorUid"`
	Outcome     string         `json:"outcome,omitempty"`
	PerPID      map[int]string `json:"perPid,omitempty"`
}

// QuarRestored is the quarantine tombstone.
type QuarRestored struct {
	Time        time.Time `json:"time"`
	OperatorUID int       `json:"operatorUid"`
	Outcome     string    `json:"outcome,omitempty"`
	Dest        string    `json:"dest,omitempty"`
}

// Entry is one store entry the view resolved: the kind, the raw manifest bytes
// (verbatim, for `-json`), the typed manifest for the matching kind, and the
// tombstone that may make it thawed/restored. Exactly one typed manifest is
// non-nil, matching Kind. A dry-run handle has no store entry at all, so Entry
// is only ever built from a real store directory.
type Entry struct {
	Kind response.Action
	ID   string
	Raw  json.RawMessage

	Freeze   *FreezeManifest
	Quar     *QuarManifest
	Evidence *EvidenceManifest

	Thawed   bool
	ThawedAt time.Time

	Restored    bool
	RestoredAt  time.Time
	RestoreDest string
}

// readEntry reads the store entry for one handle id of a given kind. A missing
// manifest is errNoManifest (the handle has no store entry: a dry-run, a kill,
// or an id that is not in this store). Any other read/decode error is returned.
func (r *Reader) readEntry(kind response.Action, id string) (Entry, error) {
	dir := r.storeDirFor(kind)
	if dir == "" {
		return Entry{}, errNoManifest
	}
	entryDir := path.Join(dir, id)
	raw, err := fs.ReadFile(r.root, path.Join(entryDir, manifestName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Entry{}, errNoManifest
		}
		return Entry{}, fmt.Errorf("view: read manifest %s: %w", entryDir, err)
	}
	e := Entry{Kind: kind, ID: id, Raw: append(json.RawMessage(nil), raw...)}
	switch kind {
	case response.ActionFreeze:
		var m FreezeManifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return Entry{}, fmt.Errorf("view: decode freeze manifest %s: %w", entryDir, err)
		}
		e.Freeze = &m
		if t, ok := r.readTombstone(entryDir, freezeThawedName); ok {
			var tomb FreezeThawed
			_ = json.Unmarshal(t, &tomb)
			e.Thawed, e.ThawedAt = true, tomb.Time
		}
	case response.ActionQuarantine:
		var m QuarManifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return Entry{}, fmt.Errorf("view: decode quarantine manifest %s: %w", entryDir, err)
		}
		e.Quar = &m
		if t, ok := r.readTombstone(entryDir, quarRestoredName); ok {
			var tomb QuarRestored
			_ = json.Unmarshal(t, &tomb)
			e.Restored, e.RestoredAt, e.RestoreDest = true, tomb.Time, tomb.Dest
		}
	case response.ActionCollect:
		var m EvidenceManifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return Entry{}, fmt.Errorf("view: decode evidence manifest %s: %w", entryDir, err)
		}
		e.Evidence = &m
	default:
		return Entry{}, errNoManifest
	}
	return e, nil
}

// FindEntry resolves an id (exact, or a prefix of at least minIDPrefix
// characters) to the one store entry of kind that it addresses, and reads it.
// It is how the privileged undo commands (thaw, restore) turn the operator's
// short id into a full handle id and learn the entry's order id, target and
// tombstone state before acting -- the same resolution list/explain use, so an
// id that lists is an id that thaws. A query that matches no entry, or more
// than one, is a clear error naming the ambiguity; a query shorter than the
// minimum is refused rather than matched loosely.
func (r *Reader) FindEntry(kind response.Action, query string) (Entry, error) {
	if len(query) < minIDPrefix {
		return Entry{}, fmt.Errorf("id %q is too short: give at least %d hex characters", query, minIDPrefix)
	}
	dir := r.storeDirFor(kind)
	if dir == "" {
		return Entry{}, fmt.Errorf("no store for %s", kind)
	}
	ents, err := fs.ReadDir(r.root, dir)
	if err != nil {
		return Entry{}, fmt.Errorf("no %s store entry for %q", kind, query)
	}
	var matches []string
	for _, ent := range ents {
		if ent.IsDir() && idMatches(ent.Name(), query) {
			matches = append(matches, ent.Name())
		}
	}
	switch len(matches) {
	case 0:
		return Entry{}, fmt.Errorf("no %s store entry for %q", kind, query)
	case 1:
		return r.readEntry(kind, matches[0])
	default:
		return Entry{}, fmt.Errorf("id %q is ambiguous: it matches %d %s entries", query, len(matches), kind)
	}
}

// readTombstone reads a tombstone file beside a manifest; ok is false when it
// does not exist (the undo has not happened).
func (r *Reader) readTombstone(entryDir, name string) ([]byte, bool) {
	b, err := fs.ReadFile(r.root, path.Join(entryDir, name))
	if err != nil {
		return nil, false
	}
	return b, true
}

// isUnhashed reports whether a recorded sha256 is the over-cap sentinel rather
// than a hex digest (Q6): the view tests the prefix, never parses it as hex.
func isUnhashed(sum string) bool {
	return sum == unhashedSentinel || len(sum) >= len(unhashedSentinel) && sum[:len(unhashedSentinel)] == unhashedSentinel
}
