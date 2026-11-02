//go:build linux

package exec

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// A store is a directory of per-id entries, one directory per handle id, each
// holding a manifest.json and (for quarantine) the quarantined file. The
// manifest is written BEFORE the act, with state "pending", so a crash between
// the manifest and the act is recoverable: the recovery pass (see Recover)
// finds the pending entry and either finalises it from the live system or rolls
// it back. After the act succeeds the manifest is finalised (state set to the
// kind's terminal value and the file made read-only), and an undo writes a
// tombstone beside it so a second undo is a no-op.
//
// The idempotency key is the ORDER id recorded in the manifest, not the handle
// id: a replayed work order (a crash between the act and the unlink, or an
// operator copying an order back in) is matched by storeScanForOrder and the
// drain records already-applied instead of acting again. See
// docs/design/response-architecture.md sections 2.6 and 2.7.
//
// These helpers are deliberately kind-agnostic: the freeze store (this item)
// and later the quarantine and evidence stores share one read/write/finalise/
// tombstone implementation so list, thaw and restore have one shape to learn.

const (
	// manifestName is the per-entry manifest file. storeFinalize makes it 0400.
	manifestName = "manifest.json"
	// statePending marks a manifest written before its act. Any other non-empty
	// state is a finalised (committed) entry; see storeFinalised.
	statePending = "pending"
	// manifestVersion is the on-disk store manifest schema version, shared by
	// the freeze and evidence manifests. Bump it only on an incompatible change.
	manifestVersion = 1
)

// errNoManifest is returned by storeReadHeader / storeReadManifest when an
// entry has no manifest.json. It is a sentinel so callers branch structurally
// (a missing entry vs a corrupt one), never on an error string.
var errNoManifest = errors.New("exec: store entry has no manifest")

// storeHeader is the subset every kind's manifest shares. Scanning a store for
// an order id, or classifying an entry during recovery, reads only this, never
// the kind-specific fields. Each concrete manifest (freezeManifest, and later
// the quarantine/evidence manifests) embeds these three json tags.
type storeHeader struct {
	ID    string `json:"id"`
	Order string `json:"order,omitempty"`
	State string `json:"state,omitempty"`
}

// storeFinalised reports whether a manifest state is a committed (non-pending)
// entry. Empty state is treated as not finalised (an entry mid-write).
func storeFinalised(state string) bool { return state != "" && state != statePending }

// storeWriteManifest writes v as the entry's manifest, creating the entry dir.
// It is the manifest-FIRST write: callers write a pending manifest with this,
// then act, then storeFinalize. The dir is 0700 and the manifest 0600 until
// finalised.
func storeWriteManifest(entryDir string, v any) error {
	if err := os.MkdirAll(entryDir, 0o700); err != nil {
		return fmt.Errorf("store: create entry dir: %w", err)
	}
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal manifest: %w", err)
	}
	// Write to a temp sibling and rename so a crashed write never leaves a
	// half-manifest the recovery pass would misread.
	tmp := filepath.Join(entryDir, manifestName+".tmp")
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return fmt.Errorf("store: write manifest: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(entryDir, manifestName)); err != nil {
		return fmt.Errorf("store: commit manifest: %w", err)
	}
	return nil
}

// storeFinalize marks an entry committed: it makes the manifest read-only
// (0400). The state field is set by the caller re-writing the manifest with
// storeWriteManifest before this call; storeFinalize only seals the mode.
func storeFinalize(entryDir string) error {
	if err := os.Chmod(filepath.Join(entryDir, manifestName), 0o400); err != nil {
		return fmt.Errorf("store: seal manifest: %w", err)
	}
	return nil
}

// storeTombstone writes a tombstone file (e.g. "thawed.json") beside the
// manifest, recording an undo. Its presence makes a second undo a no-op.
func storeTombstone(entryDir, name string, v any) error {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal tombstone: %w", err)
	}
	if err := os.WriteFile(filepath.Join(entryDir, name), buf, 0o600); err != nil {
		return fmt.Errorf("store: write tombstone: %w", err)
	}
	return nil
}

// storeHasTombstone reports whether the named tombstone exists for an entry.
func storeHasTombstone(entryDir, name string) bool {
	_, err := os.Stat(filepath.Join(entryDir, name))
	return err == nil
}

// storeReadManifest decodes an entry's manifest into v (a pointer to the
// kind's manifest struct). A missing manifest is errNoManifest.
func storeReadManifest(entryDir string, v any) error {
	data, err := os.ReadFile(filepath.Join(entryDir, manifestName)) //nolint:gosec // our own store dir
	if err != nil {
		if os.IsNotExist(err) {
			return errNoManifest
		}
		return fmt.Errorf("store: read manifest: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("store: decode manifest: %w", err)
	}
	return nil
}

// storeReadHeader reads just the shared header of an entry's manifest.
func storeReadHeader(entryDir string) (storeHeader, error) {
	var h storeHeader
	err := storeReadManifest(entryDir, &h)
	return h, err
}

// storeScanForOrder scans a store directory for a FINALISED entry whose
// manifest carries orderID, returning that entry's id. A pending entry does
// NOT match: it has not been applied yet (recovery, not already-applied, owns
// it). A store dir that does not exist yet scans as empty, not an error.
func storeScanForOrder(storeDir, orderID string) (string, bool) {
	if orderID == "" {
		return "", false
	}
	entries, err := os.ReadDir(storeDir)
	if err != nil {
		return "", false // no store yet, or unreadable: nothing applied
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		h, err := storeReadHeader(filepath.Join(storeDir, ent.Name()))
		if err != nil {
			continue
		}
		if h.Order == orderID && storeFinalised(h.State) {
			return h.ID, true
		}
	}
	return "", false
}
