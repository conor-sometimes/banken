//go:build linux

package exec

import (
	"context"
	"errors"
	"os"
	osexec "os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/response"
)

// Every test here touches ONLY scratch the test itself owns: a `sleep` child
// it spawns and reaps, and files under a temp dir it created. Nothing real is
// ever killed, frozen or quarantined. Real enforcement (Enforce:true) is used
// only against that self-owned scratch.

func spawnSleep(t *testing.T) (*osexec.Cmd, int, string) {
	t.Helper()
	bin, err := osexec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary in PATH")
	}
	cmd := osexec.Command(bin, "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd, pid, bin
}

func alive(pid int) bool { return sigPid(pid, 0) == nil }

func procStateIs(t *testing.T, pid int, want string) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f, err := statFields(pid)
		if err == nil && len(f) > 0 && f[0] == want {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestDryRunDefaultDoesNotAct is the central safety proof: with Enforce false
// (the default), Freeze and Kill touch nothing -- the self-spawned sleep is
// still alive and not stopped afterwards.
func TestDryRunDefaultDoesNotAct(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	e, err := New(Config{}) // Enforce defaults to false
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.Enforcing() {
		t.Fatalf("default executor must not enforce")
	}
	ctx := context.Background()
	p := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()}

	h, err := e.Freeze(ctx, p, response.ScopeProcess)
	if err != nil {
		t.Fatalf("Freeze dry-run: %v", err)
	}
	if !h.DryRun {
		t.Errorf("Freeze handle not marked DryRun")
	}
	if !alive(pid) {
		t.Errorf("dry-run Freeze killed the process")
	}
	if procStateIs(t, pid, "T") {
		t.Errorf("dry-run Freeze actually stopped the process")
	}

	h, err = e.Kill(ctx, p, response.ScopeProcess)
	if err != nil {
		t.Fatalf("Kill dry-run: %v", err)
	}
	if !h.DryRun {
		t.Errorf("Kill handle not marked DryRun")
	}
	if !alive(pid) {
		t.Errorf("dry-run Kill actually killed the process")
	}
}

func TestVerifyIdentity(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	e, err := New(Config{Enforce: true}) // Verify is read-only regardless
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	live, err := e.Verify(context.Background(), response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if live.PID != pid {
		t.Errorf("live.PID = %d, want %d", live.PID, pid)
	}
	if live.StartTime.IsZero() {
		t.Errorf("live.StartTime is zero")
	}
	// On NixOS `sleep` is a coreutils multicall binary, so /proc/pid/exe
	// resolves to coreutils, not a path ending in "sleep". Assert only that an
	// exe was resolved.
	if live.Exe == "" {
		t.Errorf("live.Exe is empty")
	}
}

// TestVerifyStaleByStartBound exercises the pid-reuse refusal without forcing
// an actual reuse: a reference event time well before the process started
// means any process now holding the pid must be a reuser, so Verify refuses.
func TestVerifyStaleByStartBound(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	e, _ := New(Config{Enforce: true})
	ref := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now().Add(-1 * time.Hour)}
	_, err := e.Verify(context.Background(), ref)
	if !errors.Is(err, ErrStaleTarget) {
		t.Fatalf("Verify with stale event time = %v, want ErrStaleTarget", err)
	}
}

func TestVerifyGone(t *testing.T) {
	bin, err := osexec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary in PATH")
	}
	cmd := osexec.Command(bin, "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	pid := cmd.Process.Pid
	// Kill AND reap, so the pid is fully freed (a zombie still answers pidfd).
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	e, _ := New(Config{Enforce: true})
	_, verr := e.Verify(context.Background(), response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()})
	if verr == nil {
		t.Fatalf("Verify of an exited (reaped) process returned nil error")
	}
}

func TestDenylistRefusesInit(t *testing.T) {
	e, _ := New(Config{Enforce: true})
	_, err := e.Kill(context.Background(), response.ProcessRef{PID: 1, Image: "/sbin/init"}, response.ScopeProcess)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Kill pid 1 = %v, want ErrDenied", err)
	}
	// (No liveness sanity check: a non-root test cannot signal pid 1 at all,
	// so sigPid(1, 0) returns EPERM rather than confirming life. The point is
	// that the denylist refused before any pidfd syscall was attempted.)
}

// TestFreezeThawSigstop proves the SIGSTOP fallback: with no writable cgroup
// freezer, Freeze stops the self-owned sleep and Thaw resumes it.
func TestFreezeThawSigstop(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	// Point cgroup root at a non-existent place so the executor falls back.
	cfg := Config{Enforce: true, CgroupRoot: filepath.Join(t.TempDir(), "nope", "banken.quarantine")}
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
		t.Fatalf("Thaw: %v", err)
	}
	if procStateIs(t, pid, "T") {
		t.Fatalf("process still stopped after Thaw")
	}
	if !alive(pid) {
		t.Fatalf("process gone after Thaw")
	}
}

// TestKillPidfd proves a real kill of a self-owned process via pidfd. We reap
// the child ourselves (cmd.Wait) so "it died" is proven by the wait returning
// a signal exit, not by a liveness poll (a zombie still answers pidfd).
func TestKillPidfd(t *testing.T) {
	cmd, pid, bin := spawnSleep(t)
	e, _ := New(Config{Enforce: true})
	p := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()}

	h, err := e.Kill(context.Background(), p, response.ScopeProcess)
	if err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if h.DryRun {
		t.Fatalf("Kill handle marked DryRun under Enforce")
	}
	if h.Method != "pidfd" {
		t.Errorf("Kill method = %q, want pidfd", h.Method)
	}

	werr := cmd.Wait()
	var ee *osexec.ExitError
	if !errors.As(werr, &ee) {
		t.Fatalf("after Kill, child wait = %v, want a signal exit", werr)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
		if !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Errorf("child exit status = %v, want killed by SIGKILL", ee)
		}
	}
}

// TestQuarantineRestore proves a real same-filesystem quarantine (renameat2)
// and restore, on a file the test created under /tmp.
func TestQuarantineRestore(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "banken-resp-test")
	if err != nil {
		t.Skipf("no writable /tmp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })

	work := filepath.Join(base, "work")
	qdir := filepath.Join(base, "quarantine")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(qdir, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(work, "dropper.sh")
	want := []byte("#!/bin/sh\necho malware\n")
	if err := os.WriteFile(victim, want, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{Enforce: true, QuarantineDir: qdir, QuarantineAllowPaths: []string{work}}
	e, _ := New(cfg)
	ctx := context.Background()

	h, err := e.Quarantine(ctx, response.FileRef{Path: victim})
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if h.DryRun {
		t.Fatalf("Quarantine handle marked DryRun under Enforce")
	}
	if h.Method != "rename" {
		t.Fatalf("Quarantine method = %q, want rename", h.Method)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Errorf("original file still present after quarantine")
	}
	dest := filepath.Join(qdir, h.ID, "file")
	if _, err := os.Stat(dest); err != nil {
		t.Errorf("quarantined file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(qdir, h.ID, "manifest.json")); err != nil {
		t.Errorf("manifest missing: %v", err)
	}

	if err := e.Restore(ctx, h); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got, err := os.ReadFile(victim) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatalf("file not restored: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("restored content = %q, want %q", got, want)
	}
}

func TestQuarantineRefusesNeverTouch(t *testing.T) {
	e, _ := New(Config{Enforce: true, QuarantineAllowPaths: []string{"/etc"}})
	_, err := e.Quarantine(context.Background(), response.FileRef{Path: "/etc/passwd"})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Quarantine /etc/passwd = %v, want ErrDenied", err)
	}
}

// TestCollectSelf collects evidence for the test's own process (self-owned).
func TestCollectSelf(t *testing.T) {
	dir := t.TempDir()
	e, _ := New(Config{Enforce: true, EvidenceDir: dir})
	h, err := e.Collect(context.Background(), response.ProcessRef{PID: os.Getpid(), Image: "test"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if h.DryRun {
		t.Fatalf("Collect marked DryRun under Enforce")
	}
	for _, name := range []string{"status", "cmdline", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(dir, h.ID, name)); err != nil {
			t.Errorf("evidence %s missing: %v", name, err)
		}
	}
}
