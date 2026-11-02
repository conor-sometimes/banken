//go:build linux

package exec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/response"
)

// These tests split along the root boundary the task names. The store/manifest
// logic -- idempotency key, manifest-first, the thaw tombstone, the recovery
// pass, confirm-then-move -- runs WITHOUT root (SIGSTOP or staged seams) and is
// expected to pass in the gate on hokkaido as the non-root claude user. The
// tests that need a real cgroup v2 freezer (TestFreezeIdempotent,
// TestKillTreeWaitsForPopulatedZero) t.Skip unless root with cgroup v2; those
// assertions run later in the VM freeze proof (build item 8).

// requireCgroupV2Root skips unless the test is root on a cgroup v2 host, and
// returns a throwaway cgroup to use as CgroupRoot (cleaned up after).
func requireCgroupV2Root(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("cgroup freeze/kill tests require root (run in the VM freeze proof)")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("no cgroup v2 unified hierarchy")
	}
	root := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("banken-test-%d", os.Getpid()))
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Skipf("cannot create a test cgroup: %v", err)
	}
	t.Cleanup(func() {
		ents, _ := os.ReadDir(root)
		for _, e := range ents {
			_ = os.Remove(filepath.Join(root, e.Name()))
		}
		_ = os.Remove(root)
	})
	return root
}

func countDirs(ents []os.DirEntry) int {
	n := 0
	for _, e := range ents {
		if e.IsDir() {
			n++
		}
	}
	return n
}

func stateNow(t *testing.T, pid int) string {
	t.Helper()
	f, err := statFields(pid)
	if err != nil || len(f) == 0 {
		return ""
	}
	return f[0]
}

// TestFreezeIdempotent is F7: a second Freeze of the same tree returns the FIRST
// handle and makes no second cgroup; a single Thaw returns the pid to its
// pre-freeze cgroup and resumes it. Needs a real cgroup v2 freezer.
func TestFreezeIdempotent(t *testing.T) {
	root := requireCgroupV2Root(t)
	_, pid, bin := spawnSleep(t)
	freezeDir := t.TempDir()
	e, _ := New(Config{Enforce: true, AllowRoot: true, CgroupRoot: root, FreezeDir: freezeDir})
	ctx := context.Background()
	p := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()}

	preCg, err := readCgroup(pid)
	if err != nil {
		t.Fatalf("read pre-freeze cgroup: %v", err)
	}

	h1, err := e.Freeze(ctx, p, response.ScopeProcess)
	if err != nil {
		t.Fatalf("first Freeze: %v", err)
	}
	if h1.Method != "cgroup" {
		t.Fatalf("first Freeze method = %q, want cgroup (no v2 freezer available?)", h1.Method)
	}

	h2, err := e.Freeze(ctx, p, response.ScopeProcess)
	if err != nil {
		t.Fatalf("second Freeze: %v", err)
	}
	if h2.ID != h1.ID {
		t.Errorf("second Freeze id = %s, want the first handle %s (F7 idempotency)", h2.ID, h1.ID)
	}
	if cgs, _ := os.ReadDir(root); countDirs(cgs) != 1 {
		t.Errorf("cgroup dirs under root = %d, want exactly 1 (no second cgroup)", countDirs(cgs))
	}
	if fds, _ := os.ReadDir(freezeDir); countDirs(fds) != 1 {
		t.Errorf("freeze store entries = %d, want exactly 1", countDirs(fds))
	}

	if err := e.Thaw(ctx, h1); err != nil {
		t.Fatalf("Thaw: %v", err)
	}
	postCg, err := readCgroup(pid)
	if err != nil {
		t.Fatalf("read post-thaw cgroup: %v", err)
	}
	if postCg != preCg {
		t.Errorf("post-thaw cgroup = %q, want pre-freeze %q (pid not returned home)", postCg, preCg)
	}
	if stateNow(t, pid) == "T" {
		t.Errorf("process still stopped after thaw")
	}
	if !alive(pid) {
		t.Fatalf("process gone after thaw")
	}
	if cgs, _ := os.ReadDir(root); countDirs(cgs) != 0 {
		t.Errorf("quarantine cgroup not removed after thaw: %d dir(s) left", countDirs(cgs))
	}
}

// TestFreezeManifestFirst is the manifest-first invariant: when the freeze
// store cannot be written, NO pid is stopped. The store's parent is a regular
// file, so the manifest MkdirAll fails with ENOTDIR for any user (root too),
// and CgroupRoot is absent so the SIGSTOP path runs -- which must refuse before
// signalling. No root needed.
func TestFreezeManifestFirst(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Enforce: true, AllowRoot: true,
		CgroupRoot: filepath.Join(t.TempDir(), "nope", "q"),
		FreezeDir:  filepath.Join(blocker, "freeze"),
	}
	e, _ := New(cfg)
	p := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()}

	if _, err := e.Freeze(context.Background(), p, response.ScopeProcess); err == nil {
		t.Fatalf("Freeze with an unwritable store returned nil, want an error")
	}
	if stateNow(t, pid) == "T" {
		t.Errorf("manifest-first violated: a pid was stopped though the store write failed")
	}
	if !alive(pid) {
		t.Fatalf("process gone after a refused freeze")
	}
}

// TestThawTwice proves the tombstone idempotency over the SIGSTOP method (no
// root): the first Thaw resumes the process and writes thawed.json; the second
// is a no-op, never an error.
func TestThawTwice(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	freezeDir := t.TempDir()
	cfg := Config{
		Enforce: true, AllowRoot: true,
		CgroupRoot: filepath.Join(t.TempDir(), "nope", "q"),
		FreezeDir:  freezeDir,
	}
	e, _ := New(cfg)
	ctx := context.Background()
	p := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()}

	h, err := e.Freeze(ctx, p, response.ScopeProcess)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	if h.Method != "sigstop" {
		t.Fatalf("Freeze method = %q, want sigstop", h.Method)
	}
	if !procStateIs(t, pid, "T") {
		t.Fatalf("process not stopped after Freeze")
	}

	if err := e.Thaw(ctx, h); err != nil {
		t.Fatalf("first Thaw: %v", err)
	}
	if _, err := os.Stat(filepath.Join(freezeDir, h.ID, thawedName)); err != nil {
		t.Errorf("tombstone missing after thaw: %v", err)
	}
	if err := e.Thaw(ctx, h); err != nil {
		t.Fatalf("second Thaw (idempotent) = %v, want nil", err)
	}
	if stateNow(t, pid) == "T" {
		t.Fatalf("process still stopped after thaw")
	}
	if !alive(pid) {
		t.Fatalf("process gone after idempotent thaw")
	}
}

// TestThawSkipsMovedPid proves confirm-then-move: a pid that has already left
// the quarantine cgroup is NOT force-moved (it may since have been reused by an
// innocent). Staged with seams so it runs without root.
func TestThawSkipsMovedPid(t *testing.T) {
	freezeDir := t.TempDir()
	id := "testhandle000001"
	man := freezeManifest{
		ID: id, Version: manifestVersion, State: stateFrozen, Method: "cgroup",
		Target: freezeTarget{PID: 100}, PIDs: []int{100, 200},
		// /sys/fs/cgroup exists on any Linux, so cgroupExists() confirms the home.
		Orig:   map[int]string{100: "/sys/fs/cgroup", 200: "/sys/fs/cgroup"},
		Cgroup: "/sys/fs/cgroup/banken-test-nonexistent",
		Time:   time.Now().UTC(), BootID: currentBootID(),
	}
	if err := storeWriteManifest(filepath.Join(freezeDir, id), man); err != nil {
		t.Fatal(err)
	}

	origProcs, origWrite, origPop := readCgroupProcs, writeCgroupProcs, cgroupPopulated
	t.Cleanup(func() { readCgroupProcs, writeCgroupProcs, cgroupPopulated = origProcs, origWrite, origPop })
	readCgroupProcs = func(string) ([]int, error) { return []int{100}, nil } // 200 has left
	moved := map[int]string{}
	writeCgroupProcs = func(cgDir string, pid int) error { moved[pid] = cgDir; return nil }
	cgroupPopulated = func(string) bool { return false }

	e, _ := New(Config{Enforce: true, AllowRoot: true, FreezeDir: freezeDir})
	if err := e.Thaw(context.Background(), Handle{ID: id, Undo: id}); err != nil {
		t.Fatalf("Thaw: %v", err)
	}
	if dst, ok := moved[200]; ok {
		t.Errorf("pid 200 (already left the cgroup) was force-moved to %q", dst)
	}
	if moved[100] == "" {
		t.Errorf("pid 100 (still in the cgroup) was not moved home")
	}

	var tomb freezeThawed
	data, err := os.ReadFile(filepath.Join(freezeDir, id, thawedName)) //nolint:gosec // test tempdir
	if err != nil {
		t.Fatalf("read tombstone: %v", err)
	}
	if err := json.Unmarshal(data, &tomb); err != nil {
		t.Fatalf("decode tombstone: %v", err)
	}
	if tomb.PerPID[200] != "moved" {
		t.Errorf("perPid[200] = %q, want moved (skipped)", tomb.PerPID[200])
	}
	if tomb.PerPID[100] != "moved-home" {
		t.Errorf("perPid[100] = %q, want moved-home", tomb.PerPID[100])
	}
}

// TestKillTreeWaitsForPopulatedZero is F8: after N tree kills the cgroup root is
// empty -- no leaked dirs. Needs a real cgroup v2 freezer.
func TestKillTreeWaitsForPopulatedZero(t *testing.T) {
	root := requireCgroupV2Root(t)
	e, _ := New(Config{Enforce: true, AllowRoot: true, CgroupRoot: root, FreezeDir: t.TempDir()})
	ctx := context.Background()
	const n = 20
	for i := 0; i < n; i++ {
		cmd, pid, bin := spawnSleep(t)
		h, err := e.Kill(ctx, response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()}, response.ScopeTree)
		if err != nil {
			t.Fatalf("Kill tree %d: %v", i, err)
		}
		if h.Method != "cgroup-kill" {
			t.Fatalf("Kill tree %d method = %q, want cgroup-kill", i, h.Method)
		}
		_ = cmd.Wait()
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read cgroup root: %v", err)
	}
	if leaked := countDirs(ents); leaked != 0 {
		t.Errorf("leaked %d cgroup dir(s) after %d tree kills (F8)", leaked, n)
	}
}

// TestRecoverRollsBackPendingFreeze proves the recovery pass over a crash left
// a freeze manifest pending whose act never landed: it is rolled back (a
// tombstone written) and is NOT reported already-applied. Seams, no root.
func TestRecoverRollsBackPendingFreeze(t *testing.T) {
	freezeDir := t.TempDir()
	id := "pending000000001"
	man := freezeManifest{
		ID: id, Version: manifestVersion, Order: "ord-x", State: statePending, Method: "cgroup",
		PIDs: []int{100}, Orig: map[int]string{100: "/sys/fs/cgroup"},
		Cgroup: "/sys/fs/cgroup/banken-test-nonexistent", Time: time.Now().UTC(),
	}
	if err := storeWriteManifest(filepath.Join(freezeDir, id), man); err != nil {
		t.Fatal(err)
	}
	origProcs, origWrite := readCgroupProcs, writeCgroupProcs
	t.Cleanup(func() { readCgroupProcs, writeCgroupProcs = origProcs, origWrite })
	readCgroupProcs = func(string) ([]int, error) { return nil, nil } // nothing migrated
	writeCgroupProcs = func(string, int) error { return nil }

	e, _ := New(Config{Enforce: true, FreezeDir: freezeDir, CgroupRoot: t.TempDir()})
	rec := e.(interface {
		Recover(context.Context) ([]RecoveryResult, error)
	})
	res, err := rec.Recover(context.Background())
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(res) != 1 || res[0].Outcome != "rolled-back" {
		t.Fatalf("recovery results = %v, want one rolled-back", res)
	}
	if !storeHasTombstone(filepath.Join(freezeDir, id), thawedName) {
		t.Errorf("rolled-back entry has no tombstone")
	}
	ap := e.(interface {
		Applied(context.Context, string) (Handle, bool, error)
	})
	if _, found, _ := ap.Applied(context.Background(), "ord-x"); found {
		t.Errorf("a rolled-back pending entry was reported already-applied")
	}
}
