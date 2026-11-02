//go:build linux

package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/response"
)

// These tests cover build item 5: quarantine on the fd (Q1), manifest-first
// (Q2), the hash cap (Q6) and store neutering (Q7). They are designed to run
// WITHOUT root (the claude user in the hokkaido gate is non-root): the EXDEV
// neuter branch is forced with the renameat2Fn seam rather than a real second
// mount, and the swap race is driven by the quarantineSwapHook seam. The one
// assertion that needs CAP_LINUX_IMMUTABLE (the immutable bit actually taking)
// is guarded behind os.Geteuid()==0 and is proven for real in the item 9 VM
// quarantine proof.

// quarantineFixture makes a work dir, a store dir and a victim file under a
// single t.TempDir (same filesystem, so the rename branch runs), and returns an
// enforcing executor plus the paths.
func quarantineFixture(t *testing.T, content []byte, mode os.FileMode) (Executor, string, string, string) {
	t.Helper()
	base := t.TempDir()
	work := filepath.Join(base, "work")
	qdir := filepath.Join(base, "quarantine")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(work, "payload")
	if err := os.WriteFile(victim, content, mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile honours umask; force the exact mode the test asked for.
	if err := os.Chmod(victim, mode); err != nil {
		t.Fatal(err)
	}
	e, _ := New(Config{Enforce: true, QuarantineDir: qdir, QuarantineAllowPaths: []string{work}})
	return e, work, qdir, victim
}

func lstatMode(t *testing.T, path string) (os.FileMode, bool) {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return 0, false
	}
	return os.FileMode(st.Mode & 0o7777), true
}

// TestQuarantineManifestFirst is Q2: when the store cannot be written, NOTHING
// is moved. The store dir's parent is a regular file, so the manifest-first
// MkdirAll fails ENOTDIR for any user (root too), and the victim must be left
// exactly where it was -- no orphaned, unrestorable file.
func TestQuarantineManifestFirst(t *testing.T) {
	base := t.TempDir()
	work := filepath.Join(base, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(work, "payload")
	want := []byte("dropper")
	if err := os.WriteFile(victim, want, 0o644); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// QuarantineDir sits UNDER a regular file: storeWriteManifest's MkdirAll
	// fails before any rename can be attempted.
	e, _ := New(Config{Enforce: true, QuarantineDir: filepath.Join(blocker, "q"), QuarantineAllowPaths: []string{work}})

	if _, err := e.Quarantine(context.Background(), response.FileRef{Path: victim}); err == nil {
		t.Fatalf("Quarantine with an unwritable store returned nil, want an error")
	}
	got, err := os.ReadFile(victim) //nolint:gosec // test tempdir
	if err != nil {
		t.Fatalf("manifest-first violated: victim gone after a refused quarantine: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("victim content changed after a refused quarantine")
	}
	if m, _ := lstatMode(t, victim); m != 0o644 {
		t.Errorf("victim mode = %o after a refused quarantine, want 0644 (untouched)", m)
	}
}

// TestQuarantineUnhashedOverCap is Q6: a 1 TiB sparse file is still moved and
// neutered, but its sha256 is recorded as the unhashed sentinel and the whole
// operation completes well under a second (the file is never read).
func TestQuarantineUnhashedOverCap(t *testing.T) {
	base := t.TempDir()
	work := filepath.Join(base, "work")
	qdir := filepath.Join(base, "quarantine")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(work, "big")
	f, err := os.Create(victim)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1 << 40); err != nil { // 1 TiB, sparse
		_ = f.Close()
		t.Skipf("cannot make a 1 TiB sparse file here: %v", err)
	}
	_ = f.Close()

	e, _ := New(Config{Enforce: true, QuarantineDir: qdir, QuarantineAllowPaths: []string{work}, MaxFileBytes: 256 << 20})

	start := time.Now()
	h, err := e.Quarantine(context.Background(), response.FileRef{Path: victim})
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Quarantine of a 1 TiB sparse file took %s, want < 1s (the file must not be hashed)", d)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Errorf("over-cap file was not moved (Q6: the rename costs nothing, so it is still taken)")
	}
	var man quarantineManifest
	if err := storeReadManifest(filepath.Join(qdir, h.ID), &man); err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if man.SHA256 != unhashedSentinel {
		t.Errorf("sha256 = %q, want %q (Q6)", man.SHA256, unhashedSentinel)
	}
	if man.State != stateHeld {
		t.Errorf("manifest state = %q, want held", man.State)
	}
}

// TestStoredFileIsNeutered is Q7: after a rename quarantine the stored file is
// mode 0000 (always, non-root), and immutable in the store where the platform
// allows it (root + CAP_LINUX_IMMUTABLE on a flag-supporting fs).
func TestStoredFileIsNeutered(t *testing.T) {
	e, _, qdir, victim := quarantineFixture(t, []byte("#!/bin/sh\necho malware\n"), 0o755)

	h, err := e.Quarantine(context.Background(), response.FileRef{Path: victim})
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if h.Method != "rename" {
		t.Fatalf("method = %q, want rename", h.Method)
	}
	dest := filepath.Join(qdir, h.ID, "file")
	if m, ok := lstatMode(t, dest); !ok || m != 0 {
		t.Errorf("stored file mode = %o, want 0000 (Q7)", m)
	}
	if os.Geteuid() == 0 {
		var man quarantineManifest
		if err := storeReadManifest(filepath.Join(qdir, h.ID), &man); err != nil {
			t.Fatal(err)
		}
		if !man.Immutable {
			t.Errorf("immutable flag not recorded as set in the store (running as root)")
		}
	}
}

// TestQuarantineSwapRaceRename is Q1 for the rename path: a hook swaps the
// directory entry between the fstat and the rename. The post-rename (dev, ino)
// recheck must catch that the moved file is not the one we fstat'd, put the
// swapped-in (innocent) file straight back, and refuse with ErrStaleTarget --
// the innocent file untouched, the store clean.
func TestQuarantineSwapRaceRename(t *testing.T) {
	e, work, qdir, victim := quarantineFixture(t, []byte("malware"), 0o644)
	innocent := []byte("innocent config")
	decoy := filepath.Join(work, "decoy")
	if err := os.WriteFile(decoy, innocent, 0o600); err != nil {
		t.Fatal(err)
	}

	quarantineSwapHook = func() {
		quarantineSwapHook = nil // fire exactly once
		// Replace the victim's directory entry with the innocent decoy.
		if err := os.Rename(decoy, victim); err != nil {
			t.Errorf("swap hook rename: %v", err)
		}
	}
	t.Cleanup(func() { quarantineSwapHook = nil })

	_, err := e.Quarantine(context.Background(), response.FileRef{Path: victim})
	if !errors.Is(err, ErrStaleTarget) {
		t.Fatalf("Quarantine under a swap race = %v, want ErrStaleTarget (Q1)", err)
	}
	got, rerr := os.ReadFile(victim) //nolint:gosec // test tempdir
	if rerr != nil {
		t.Fatalf("innocent file gone after a refused swap-race quarantine: %v", rerr)
	}
	if string(got) != string(innocent) {
		t.Errorf("innocent file content changed: %q", got)
	}
	if m, _ := lstatMode(t, victim); m != 0o600 {
		t.Errorf("innocent file mode = %o, want 0600 (untouched)", m)
	}
	ents, _ := os.ReadDir(qdir)
	if len(ents) != 0 {
		t.Errorf("store has %d entries after a refused quarantine, want 0", len(ents))
	}
}

// TestQuarantineSwapRaceNeuter is Q1 for the EXDEV neuter path: the neuter must
// act on the fstat'd fd, so a directory-entry swap before the neuter cannot
// redirect it onto an innocent file. EXDEV is forced with the renameat2Fn seam
// (no real second mount needed). We keep a hard link to the original inode so
// we can observe that IT was neutered while the swapped-in file was not.
func TestQuarantineSwapRaceNeuter(t *testing.T) {
	e, work, _, victim := quarantineFixture(t, []byte("malware"), 0o755)

	origLink := filepath.Join(work, "orig-link")
	if err := os.Link(victim, origLink); err != nil {
		t.Skipf("cannot hard-link to observe the original inode: %v", err)
	}
	innocent := []byte("innocent config")
	decoy := filepath.Join(work, "decoy")
	if err := os.WriteFile(decoy, innocent, 0o600); err != nil {
		t.Fatal(err)
	}

	origRename := renameat2Fn
	renameat2Fn = func(int, string, int, string, uint) error { return syscall.EXDEV }
	t.Cleanup(func() { renameat2Fn = origRename })

	quarantineSwapHook = func() {
		quarantineSwapHook = nil
		if err := os.Rename(decoy, victim); err != nil { // decoy replaces the victim name
			t.Errorf("swap hook rename: %v", err)
		}
	}
	t.Cleanup(func() { quarantineSwapHook = nil })

	h, err := e.Quarantine(context.Background(), response.FileRef{Path: victim})
	if err != nil {
		t.Fatalf("Quarantine (neuter) under a swap race: %v", err)
	}
	if h.Method != "neuter" {
		t.Fatalf("method = %q, want neuter", h.Method)
	}
	// The ORIGINAL inode (reachable via the hard link) was neutered.
	if m, _ := lstatMode(t, origLink); m != 0 {
		t.Errorf("original inode mode = %o, want 0000 (the neuter must act on the fstat'd fd, Q1)", m)
	}
	// The innocent file now sitting at the victim path was NOT touched.
	if m, _ := lstatMode(t, victim); m != 0o600 {
		t.Errorf("innocent swapped-in file mode = %o, want 0600 (Q1: never re-resolve the path)", m)
	}
	if got, _ := os.ReadFile(victim); string(got) != string(innocent) { //nolint:gosec // test tempdir
		t.Errorf("innocent swapped-in file content changed: %q", got)
	}
}

// TestQuarantineRecoverPending is Q2's recovery half: a crash between the rename
// and the finalise leaves a pending manifest and a stored file. The recovery
// pass finalises it from the store alone (verifying (dev, ino) against the
// manifest and neutering the stored inode), and a replayed order then hits
// already-applied. No root.
func TestQuarantineRecoverPending(t *testing.T) {
	base := t.TempDir()
	qdir := filepath.Join(base, "quarantine")
	id := newHandleID()
	entryDir := filepath.Join(qdir, id)
	if err := os.MkdirAll(entryDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stored := filepath.Join(entryDir, "file")
	if err := os.WriteFile(stored, []byte("payload"), 0o644); err != nil { // the "moved" file
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(stored, &st); err != nil {
		t.Fatal(err)
	}
	man := quarantineManifest{
		ID: id, Version: manifestVersion, Order: "ord-q", State: statePending, Method: "pending",
		OrigPath: filepath.Join(base, "work", "payload"), Stat: statToFileStat(st),
		SHA256: "deadbeef", Time: time.Now().UTC(),
	}
	if err := storeWriteManifest(entryDir, man); err != nil {
		t.Fatal(err)
	}

	e, _ := New(Config{Enforce: true, QuarantineDir: qdir, CgroupRoot: t.TempDir(), FreezeDir: t.TempDir(), EvidenceDir: t.TempDir()})
	rec := e.(interface {
		Recover(context.Context) ([]RecoveryResult, error)
	})
	res, err := rec.Recover(context.Background())
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	var got *RecoveryResult
	for i := range res {
		if res[i].ID == id {
			got = &res[i]
		}
	}
	if got == nil || got.Outcome != "finalised" {
		t.Fatalf("recovery results = %v, want one finalised for %s", res, id)
	}
	if got.Order != "ord-q" {
		t.Errorf("recovered order = %q, want ord-q", got.Order)
	}

	var m2 quarantineManifest
	if err := storeReadManifest(entryDir, &m2); err != nil {
		t.Fatal(err)
	}
	if m2.State != stateHeld {
		t.Errorf("recovered manifest state = %q, want held", m2.State)
	}
	if m2.Method != "rename" {
		t.Errorf("recovered method = %q, want rename", m2.Method)
	}
	if m, _ := lstatMode(t, stored); m != 0 {
		t.Errorf("stored file not neutered after recovery: mode %o", m)
	}

	ap := e.(interface {
		Applied(context.Context, string) (Handle, bool, error)
	})
	h, found, _ := ap.Applied(context.Background(), "ord-q")
	if !found {
		t.Fatalf("a finalised entry was not reported already-applied on replay")
	}
	if h.ID != id {
		t.Errorf("already-applied handle id = %q, want %q", h.ID, id)
	}
}

// TestQuarantineRecoverRollsBack proves the other recovery branch: a pending
// manifest whose act never landed (no stored file, the original intact at its
// path) is rolled back with a tombstone, and is NOT reported already-applied,
// so the order reprocesses normally.
func TestQuarantineRecoverRollsBack(t *testing.T) {
	base := t.TempDir()
	qdir := filepath.Join(base, "quarantine")
	work := filepath.Join(base, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(work, "payload")
	if err := os.WriteFile(victim, []byte("intact"), 0o644); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(victim, &st); err != nil {
		t.Fatal(err)
	}
	id := newHandleID()
	entryDir := filepath.Join(qdir, id)
	man := quarantineManifest{
		ID: id, Version: manifestVersion, Order: "ord-r", State: statePending, Method: "pending",
		OrigPath: victim, Stat: statToFileStat(st), SHA256: "x", Time: time.Now().UTC(),
	}
	if err := storeWriteManifest(entryDir, man); err != nil { // no <id>/file: the act never landed
		t.Fatal(err)
	}

	e, _ := New(Config{Enforce: true, QuarantineDir: qdir, CgroupRoot: t.TempDir(), FreezeDir: t.TempDir(), EvidenceDir: t.TempDir()})
	rec := e.(interface {
		Recover(context.Context) ([]RecoveryResult, error)
	})
	res, err := rec.Recover(context.Background())
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	var got *RecoveryResult
	for i := range res {
		if res[i].ID == id {
			got = &res[i]
		}
	}
	if got == nil || got.Outcome != "rolled-back" {
		t.Fatalf("recovery results = %v, want one rolled-back for %s", res, id)
	}
	if !storeHasTombstone(entryDir, restoredName) {
		t.Errorf("rolled-back entry has no tombstone")
	}
	if m, _ := lstatMode(t, victim); m != 0o644 {
		t.Errorf("original file touched by a rollback: mode %o, want 0644", m)
	}
	ap := e.(interface {
		Applied(context.Context, string) (Handle, bool, error)
	})
	if _, found, _ := ap.Applied(context.Background(), "ord-r"); found {
		t.Errorf("a rolled-back pending entry was reported already-applied")
	}
}

// TestQuarantineRestoreNeuterEXDEV extends the restore proof to the EXDEV neuter
// path. EXDEV is forced with the seam so it runs non-root on any filesystem;
// the real tmpfs cross-device neuter is proven in the item 9 VM proof. The
// round trip must return the recorded mode and leave the content untouched.
func TestQuarantineRestoreNeuterEXDEV(t *testing.T) {
	e, _, _, victim := quarantineFixture(t, []byte("#!/bin/sh\necho malware\n"), 0o755)
	want, err := os.ReadFile(victim) //nolint:gosec // test tempdir
	if err != nil {
		t.Fatal(err)
	}

	origRename := renameat2Fn
	renameat2Fn = func(int, string, int, string, uint) error { return syscall.EXDEV }
	t.Cleanup(func() { renameat2Fn = origRename })

	ctx := context.Background()
	h, err := e.Quarantine(ctx, response.FileRef{Path: victim})
	if err != nil {
		t.Fatalf("Quarantine (neuter): %v", err)
	}
	if h.Method != "neuter" {
		t.Fatalf("method = %q, want neuter", h.Method)
	}
	if m, _ := lstatMode(t, victim); m != 0 {
		t.Errorf("neutered file mode = %o, want 0000", m)
	}

	if err := e.Restore(ctx, h); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if m, _ := lstatMode(t, victim); m != 0o755 {
		t.Errorf("restored mode = %o, want 0755", m)
	}
	got, err := os.ReadFile(victim) //nolint:gosec // test tempdir
	if err != nil {
		t.Fatalf("restored file unreadable: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("restored content = %q, want %q", got, want)
	}
}
