//go:build linux

package exec

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/conor-sometimes/banken/internal/response"
)

// These tests cover build item 7: the restore undo path with Q3 (the entry is
// KEPT and a tombstone written, so a second restore is a clean no-op) and Q4
// (BOTH dev and ino are checked on the rename AND the neuter method), plus the
// -to destination bounded by the shared allowPaths/never-touch lists. They run
// WITHOUT root (the claude user in the hokkaido gate is non-root): the EXDEV
// neuter branch is forced with the renameat2Fn seam, and the immutable bit is
// never relied upon (it does not take without CAP_LINUX_IMMUTABLE, which the
// item 9 VM proof covers). The one rail that needs a uid-0 target (E1's) is
// driven deterministically through the readUID seam, so it is exercised
// whatever uid the runner has.

// inodeSnap is the comparable subset of a file's identity and metadata the
// round-trip property asserts is unchanged across quarantine + restore.
type inodeSnap struct {
	dev, ino  uint64
	mode      uint32
	uid, gid  uint32
	mtimeSec  int64
	mtimeNsec int64
	nlink     uint64
}

// TestRestoreTwice is Q3: a second restore is a clean no-op (no error) and the
// store entry is KEPT -- the manifest survives, a restored.json tombstone is
// written, and the restored file at its original path is untouched by the
// second call.
func TestRestoreTwice(t *testing.T) {
	e, _, qdir, victim := quarantineFixture(t, []byte("#!/bin/sh\necho malware\n"), 0o750)
	ctx := context.Background()

	h, err := e.Quarantine(ctx, response.FileRef{Path: victim})
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	entryDir := filepath.Join(qdir, h.ID)

	if err := e.Restore(ctx, h, ""); err != nil {
		t.Fatalf("first Restore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(entryDir, manifestName)); err != nil {
		t.Fatalf("Q3 violated: manifest gone after restore (entry not kept): %v", err)
	}
	if !storeHasTombstone(entryDir, restoredName) {
		t.Fatalf("no restored.json tombstone after restore")
	}
	first, err := os.ReadFile(victim) //nolint:gosec // test tempdir
	if err != nil {
		t.Fatalf("restored file missing: %v", err)
	}

	if err := e.Restore(ctx, h, ""); err != nil {
		t.Fatalf("second Restore (idempotent) returned error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(entryDir, manifestName)); err != nil {
		t.Fatalf("Q3 violated: manifest gone after SECOND restore: %v", err)
	}
	second, err := os.ReadFile(victim) //nolint:gosec // test tempdir
	if err != nil {
		t.Fatalf("file disturbed by second restore: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("second restore changed the restored file")
	}
}

// TestRestoreRefusesReplacedInode is Q4 for BOTH methods: if the thing now at
// the path/store is a different inode than the manifest recorded, restore
// refuses with ErrStaleTarget rather than acting on the wrong file.
func TestRestoreRefusesReplacedInode(t *testing.T) {
	ctx := context.Background()

	t.Run("rename", func(t *testing.T) {
		e, _, qdir, victim := quarantineFixture(t, []byte("payload-rename"), 0o644)
		h, err := e.Quarantine(ctx, response.FileRef{Path: victim})
		if err != nil {
			t.Fatalf("Quarantine: %v", err)
		}
		// Replace the stored inode with a DIFFERENT inode. Create the impostor
		// while the stored file still exists (so the kernel cannot reuse its freed
		// inode number) then rename it over, guaranteeing a distinct (dev,ino).
		stored := filepath.Join(qdir, h.ID, "file")
		impostor := stored + ".new"
		if err := os.WriteFile(impostor, []byte("not the original"), 0o600); err != nil {
			t.Fatalf("write impostor: %v", err)
		}
		_ = clearImmutable(stored)
		if err := os.Rename(impostor, stored); err != nil {
			t.Fatalf("swap stored inode: %v", err)
		}
		if err := e.Restore(ctx, h, ""); !errors.Is(err, ErrStaleTarget) {
			t.Fatalf("Restore with replaced stored inode = %v, want ErrStaleTarget", err)
		}
	})

	t.Run("neuter", func(t *testing.T) {
		e, _, _, victim := quarantineFixture(t, []byte("payload-neuter"), 0o644)
		origRename := renameat2Fn
		renameat2Fn = func(int, string, int, string, uint) error { return syscall.EXDEV }
		h, err := e.Quarantine(ctx, response.FileRef{Path: victim})
		renameat2Fn = origRename
		if err != nil {
			t.Fatalf("Quarantine (neuter): %v", err)
		}
		if h.Method != "neuter" {
			t.Fatalf("method = %q, want neuter", h.Method)
		}
		// Replace the neutered inode at its original path with a DIFFERENT inode
		// (create-then-rename so the inode number cannot be reused).
		impostor := victim + ".new"
		if err := os.WriteFile(impostor, []byte("impostor"), 0o600); err != nil {
			t.Fatalf("write impostor: %v", err)
		}
		_ = clearImmutable(victim)
		if err := os.Rename(impostor, victim); err != nil {
			t.Fatalf("swap neutered inode: %v", err)
		}
		if err := e.Restore(ctx, h, ""); !errors.Is(err, ErrStaleTarget) {
			t.Fatalf("Restore with replaced neutered inode = %v, want ErrStaleTarget", err)
		}
	})
}

// TestRestoreOccupiedPath proves restore never clobbers a squatter at the
// original path (RENAME_NOREPLACE -> ErrDenied, squatter untouched), that -to
// relocates under allowPaths, and that -to is bounded by the shared lists: a
// never-touch destination and a destination inside the store are both refused.
// The refusals run first, on the un-restored entry, because the successful -to
// writes the tombstone that makes any later restore a no-op.
func TestRestoreOccupiedPath(t *testing.T) {
	e, work, qdir, victim := quarantineFixture(t, []byte("the real payload"), 0o644)
	ctx := context.Background()
	want := []byte("the real payload")

	h, err := e.Quarantine(ctx, response.FileRef{Path: victim})
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	// -to a never-touch path is refused before anything is touched.
	if err := e.Restore(ctx, h, "/etc/banken-restore-x"); !errors.Is(err, ErrDenied) {
		t.Fatalf("-to /etc = %v, want ErrDenied (never-touch)", err)
	}
	// -to inside the quarantine store is refused.
	if err := e.Restore(ctx, h, filepath.Join(qdir, "escape")); !errors.Is(err, ErrDenied) {
		t.Fatalf("-to store = %v, want ErrDenied", err)
	}

	// A squatter now sits at the original path: restore must refuse, not clobber.
	squatter := []byte("I am not the payload")
	if err := os.WriteFile(victim, squatter, 0o600); err != nil {
		t.Fatalf("place squatter: %v", err)
	}
	if err := e.Restore(ctx, h, ""); !errors.Is(err, ErrDenied) {
		t.Fatalf("Restore onto a squatter = %v, want ErrDenied", err)
	}
	got, err := os.ReadFile(victim) //nolint:gosec // test tempdir
	if err != nil || !bytes.Equal(got, squatter) {
		t.Fatalf("squatter disturbed by refused restore: got %q err %v", got, err)
	}

	// -to a free path under allowPaths works, and lands the real payload.
	dest := filepath.Join(work, "restored-elsewhere")
	if err := e.Restore(ctx, h, dest); err != nil {
		t.Fatalf("Restore -to free path: %v", err)
	}
	moved, err := os.ReadFile(dest) //nolint:gosec // test tempdir
	if err != nil || !bytes.Equal(moved, want) {
		t.Fatalf("restored content at -to dest = %q err %v, want %q", moved, err, want)
	}
}

// TestRestoreRoundTripProperty is the §3.4 round trip: for random content,
// mode (including setuid/setgid/sticky), mtime, an optional user.* xattr and an
// optional hard link, quarantine then restore leaves the inode's content, mode,
// uid/gid, mtime, xattr and nlink identical, on the same-fs (rename) path and
// the cross-fs (EXDEV neuter) path alike.
func TestRestoreRoundTripProperty(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "banken-rt")
	if err != nil {
		t.Skipf("no writable /tmp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })

	rapid.Check(t, func(rt *rapid.T) {
		content := rapid.SliceOfN(rapid.Byte(), 0, 2048).Draw(rt, "content")
		// Force owner-read so a non-root runner can read the file back and hash it;
		// the setuid/setgid/sticky bits are still drawn and asserted.
		mode := rapid.Uint32Range(0, 0o7777).Draw(rt, "mode") | 0o400
		exdev := rapid.Bool().Draw(rt, "exdev")
		withLink := rapid.Bool().Draw(rt, "hardlink")
		withXattr := rapid.Bool().Draw(rt, "xattr")

		dir, derr := os.MkdirTemp(base, "it")
		if derr != nil {
			rt.Fatalf("tempdir: %v", derr)
		}
		defer func() { _ = os.RemoveAll(dir) }()
		work := filepath.Join(dir, "work")
		qdir := filepath.Join(dir, "q")
		if merr := os.MkdirAll(work, 0o755); merr != nil {
			rt.Fatalf("mkdir: %v", merr)
		}
		victim := filepath.Join(work, "payload")
		if werr := os.WriteFile(victim, content, 0o600); werr != nil {
			rt.Fatalf("write victim: %v", werr)
		}
		// Raw-bit chmod so setuid/setgid/sticky actually set (os.Chmod drops them).
		if cerr := syscall.Chmod(victim, mode); cerr != nil {
			rt.Fatalf("chmod: %v", cerr)
		}
		mt := time.Unix(1_600_000_000, 123_000_000)
		_ = os.Chtimes(victim, mt, mt)
		if withLink {
			if lerr := os.Link(victim, filepath.Join(work, "payload.ln")); lerr != nil {
				rt.Fatalf("hardlink: %v", lerr)
			}
		}
		haveXattr := false
		xval := []byte("banken-rt")
		if withXattr && syscall.Setxattr(victim, "user.banken-test", xval, 0) == nil {
			haveXattr = true
		}

		snap := func(path string) inodeSnap {
			var st syscall.Stat_t
			if serr := syscall.Lstat(path, &st); serr != nil {
				rt.Fatalf("lstat %s: %v", path, serr)
			}
			return inodeSnap{
				dev: st.Dev, ino: st.Ino, mode: st.Mode & 0o7777,
				uid: st.Uid, gid: st.Gid,
				mtimeSec: st.Mtim.Sec, mtimeNsec: st.Mtim.Nsec,
				nlink: uint64(st.Nlink), //nolint:unconvert // uint32 on arm64
			}
		}
		before := snap(victim)

		origRename := renameat2Fn
		if exdev {
			renameat2Fn = func(int, string, int, string, uint) error { return syscall.EXDEV }
		}
		e, _ := New(Config{Enforce: true, QuarantineDir: qdir, QuarantineAllowPaths: []string{work}})
		ctx := context.Background()
		h, qerr := e.Quarantine(ctx, response.FileRef{Path: victim})
		renameat2Fn = origRename
		if qerr != nil {
			rt.Fatalf("Quarantine: %v", qerr)
		}
		wantMethod := "rename"
		if exdev {
			wantMethod = "neuter"
		}
		if h.Method != wantMethod {
			rt.Fatalf("method = %q, want %q", h.Method, wantMethod)
		}

		if rerr := e.Restore(ctx, h, ""); rerr != nil {
			rt.Fatalf("Restore: %v", rerr)
		}

		after := snap(victim)
		if after.dev != before.dev || after.ino != before.ino {
			rt.Errorf("inode changed: (%d,%d) -> (%d,%d)", before.dev, before.ino, after.dev, after.ino)
		}
		if after.mode != before.mode {
			rt.Errorf("mode = %04o, want %04o", after.mode, before.mode)
		}
		if after.uid != before.uid || after.gid != before.gid {
			rt.Errorf("uid/gid changed: (%d,%d) -> (%d,%d)", before.uid, before.gid, after.uid, after.gid)
		}
		if after.mtimeSec != before.mtimeSec || after.mtimeNsec != before.mtimeNsec {
			rt.Errorf("mtime changed: %d.%09d -> %d.%09d", before.mtimeSec, before.mtimeNsec, after.mtimeSec, after.mtimeNsec)
		}
		if after.nlink != before.nlink {
			rt.Errorf("nlink = %d, want %d", after.nlink, before.nlink)
		}
		got, gerr := os.ReadFile(victim) //nolint:gosec // test tempdir
		if gerr != nil {
			rt.Fatalf("read restored: %v", gerr)
		}
		if !bytes.Equal(got, content) {
			rt.Errorf("content changed (len %d -> %d)", len(content), len(got))
		}
		if haveXattr {
			buf := make([]byte, 64)
			n, xerr := syscall.Getxattr(victim, "user.banken-test", buf)
			if xerr != nil || !bytes.Equal(buf[:n], xval) {
				rt.Errorf("xattr not preserved: n=%d err=%v", n, xerr)
			}
		}
	})
}

// TestRestoreDryRunHandleSaysSo: a dry-run handle has no store entry, so restore
// is a clean no-op that touches nothing (the file was never moved in dry-run).
func TestRestoreDryRunHandleSaysSo(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "banken-dr")
	if err != nil {
		t.Skipf("no writable /tmp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	victim := filepath.Join(base, "payload")
	want := []byte("still here")
	if err := os.WriteFile(victim, want, 0o644); err != nil {
		t.Fatal(err)
	}

	e, _ := New(Config{QuarantineAllowPaths: []string{base}}) // Enforce defaults to false
	ctx := context.Background()
	h, err := e.Quarantine(ctx, response.FileRef{Path: victim})
	if err != nil {
		t.Fatalf("dry-run Quarantine: %v", err)
	}
	if !h.DryRun {
		t.Fatalf("Quarantine handle not marked DryRun")
	}
	if err := e.Restore(ctx, h, ""); err != nil {
		t.Fatalf("Restore of a dry-run handle returned error: %v", err)
	}
	got, err := os.ReadFile(victim) //nolint:gosec // test tempdir
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("dry-run restore disturbed the file: got %q err %v", got, err)
	}
}

// TestDryRunNeverErrorsOnUID0Rail is the E1 guard: a non-enforcing executor
// must NEVER return an error from a safety rail -- it records the would-be
// refusal in the handle and acts on nothing. The uid-0 rail is driven through
// the readUID seam so this holds whatever uid the test runner has (the bug only
// showed when the self-target was uid 0, i.e. under root). Freeze, Kill and
// Collect are all checked.
func TestDryRunNeverErrorsOnUID0Rail(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	origUID := readUID
	readUID = func(int) (int, error) { return 0, nil } // force the uid-0 rail
	t.Cleanup(func() { readUID = origUID })

	e, err := New(Config{}) // Enforce false, AllowRoot false
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	p := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()}

	for _, tc := range []struct {
		name string
		call func() (Handle, error)
	}{
		{"freeze", func() (Handle, error) { return e.Freeze(ctx, p, response.ScopeProcess) }},
		{"kill", func() (Handle, error) { return e.Kill(ctx, p, response.ScopeProcess) }},
		{"collect", func() (Handle, error) { return e.Collect(ctx, p) }},
	} {
		h, cerr := tc.call()
		if cerr != nil {
			t.Fatalf("%s dry-run returned an error on the uid-0 rail (E1): %v", tc.name, cerr)
		}
		if !h.DryRun {
			t.Errorf("%s handle not marked DryRun", tc.name)
		}
		if !contains(h.Note, "would be refused") {
			t.Errorf("%s handle Note = %q, want it to record the would-be refusal", tc.name, h.Note)
		}
	}
	if !alive(pid) {
		t.Errorf("dry-run acted on the process")
	}
	if procStateIs(t, pid, "T") {
		t.Errorf("dry-run stopped the process")
	}
}

// contains is a tiny substring helper kept local to the restore tests.
func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
