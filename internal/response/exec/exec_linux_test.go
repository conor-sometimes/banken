//go:build linux

package exec

import (
	"context"
	"errors"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/response"
)

// TestMain doubles as a re-exec helper: a child launched with BANKEN_SLEEPER
// set just sleeps, so a test can copy this binary to a scratch path (e.g.
// /tmp/<dir>/sshd) and run it to stage a live process whose /proc/<pid>/exe is
// a protected NAME at an untrusted PATH -- the masquerade F2 must see through.
func TestMain(m *testing.M) {
	if os.Getenv("BANKEN_SLEEPER") != "" {
		time.Sleep(300 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// spawnMasquerader copies the test binary to <scratch>/<name> under an
// untrusted dir and runs it as a sleeper, returning the cmd and its pid. The
// live exe is therefore <scratch>/<name> -- a protected name at an untrusted
// path when name is e.g. "sshd".
func spawnMasquerader(t *testing.T, name string) (*osexec.Cmd, int, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	dir, err := os.MkdirTemp("/tmp", "banken-masq")
	if err != nil {
		t.Skipf("no writable /tmp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dst := filepath.Join(dir, name)
	if err := copyExecutable(self, dst); err != nil {
		t.Skipf("copy helper binary: %v", err)
	}
	cmd := osexec.Command(dst)
	cmd.Env = append(os.Environ(), "BANKEN_SLEEPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn masquerader: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd, pid, dst
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // the test's own binary
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) //nolint:gosec // test-owned scratch
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

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
	e, err := New(Config{Enforce: true, AllowRoot: true}) // Verify is read-only regardless; AllowRoot so a root test runner can verify its own sleep
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
	e, _ := New(Config{Enforce: true, AllowRoot: true})
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

	e, _ := New(Config{Enforce: true, AllowRoot: true})
	_, verr := e.Verify(context.Background(), response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()})
	if verr == nil {
		t.Fatalf("Verify of an exited (reaped) process returned nil error")
	}
}

func TestDenylistRefusesInit(t *testing.T) {
	e, _ := New(Config{Enforce: true, AllowRoot: true})
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
	cfg := Config{Enforce: true, AllowRoot: true, CgroupRoot: filepath.Join(t.TempDir(), "nope", "banken.quarantine")}
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
	e, _ := New(Config{Enforce: true, AllowRoot: true})
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
// The ProcessRef names the test binary's own exe so the §5.1 identity bind
// (now run by Collect too) succeeds.
func TestCollectSelf(t *testing.T) {
	dir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	e, _ := New(Config{Enforce: true, AllowRoot: true, EvidenceDir: dir})
	h, err := e.Collect(context.Background(), response.ProcessRef{PID: os.Getpid(), Image: self, EventTime: time.Now()})
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
	// (e) the handle (what the ledger stores) carries the verified identity.
	if h.Exe == "" {
		t.Errorf("Collect handle has empty Exe; want the verified exe")
	}
	if h.StartTime.IsZero() {
		t.Errorf("Collect handle has zero StartTime; want the verified start time")
	}
	// The manifest records exe + start time alongside the snapshot.
	man, err := os.ReadFile(filepath.Join(dir, h.ID, "manifest.json")) //nolint:gosec // test-owned evidence dir
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !strings.Contains(string(man), `"exe"`) || !strings.Contains(string(man), `"startTime"`) {
		t.Errorf("manifest missing exe/startTime: %s", man)
	}
}

// TestKillStartTimeMismatchDoesNotSignal is (a): a reference whose start time
// does not match the live process is refused with ErrStaleTarget, and a Kill
// through it sends NO signal -- the self-owned sleep is still alive.
func TestKillStartTimeMismatchDoesNotSignal(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	e, _ := New(Config{Enforce: true, AllowRoot: true})
	ctx := context.Background()
	// Exe matches (bin) so only the start time is wrong: a deliberately absurd
	// value well outside the one-tick tolerance.
	ref := response.ProcessRef{PID: pid, Image: bin, StartTime: time.Unix(1, 0)}

	if _, err := e.Verify(ctx, ref); !errors.Is(err, ErrStaleTarget) {
		t.Fatalf("Verify start-time mismatch = %v, want ErrStaleTarget", err)
	}
	h, err := e.Kill(ctx, ref, response.ScopeProcess)
	if !errors.Is(err, ErrStaleTarget) {
		t.Fatalf("Kill start-time mismatch = %v, want ErrStaleTarget", err)
	}
	if h.PID != 0 || h.Method != "" {
		t.Errorf("refused Kill returned a non-zero handle: %+v", h)
	}
	if !alive(pid) {
		t.Fatalf("refused Kill signalled the process; it is gone")
	}
}

// TestVerifyStartTimeUnreadableFailsClosed is the other half of (a): when the
// start time cannot be READ at all, identity cannot be confirmed, so the
// target is refused (fail closed) rather than returned as a verified handle --
// the pre-fix bug skipped the check and returned a verified pidfd.
func TestVerifyStartTimeUnreadableFailsClosed(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	orig := readStartTime
	readStartTime = func(int) (time.Time, error) { return time.Time{}, errors.New("forced stat failure") }
	t.Cleanup(func() { readStartTime = orig })

	e, _ := New(Config{Enforce: true, AllowRoot: true})
	ctx := context.Background()
	ref := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()}

	if _, err := e.Verify(ctx, ref); !errors.Is(err, ErrStaleTarget) {
		t.Fatalf("Verify with unreadable start time = %v, want ErrStaleTarget", err)
	}
	if _, err := e.Kill(ctx, ref, response.ScopeProcess); !errors.Is(err, ErrStaleTarget) {
		t.Fatalf("Kill with unreadable start time = %v, want ErrStaleTarget", err)
	}
	if !alive(pid) {
		t.Fatalf("refused Kill signalled the process; it is gone")
	}
}

// TestExeMismatchRefused is (b): a reference whose image is a different binary
// than the live exe is refused, even though the pid and start time are right.
func TestExeMismatchRefused(t *testing.T) {
	_, pid, _ := spawnSleep(t)
	e, _ := New(Config{Enforce: true, AllowRoot: true})
	ctx := context.Background()
	// The test binary itself: a real, existing file that is a DIFFERENT inode
	// from the coreutils `sleep` the target runs, so the exe bind must refuse.
	// (A sibling like /usr/bin/env would be the SAME coreutils inode on NixOS
	// and would legitimately match.)
	other, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	ref := response.ProcessRef{PID: pid, Image: other, EventTime: time.Now()}

	if _, err := e.Verify(ctx, ref); !errors.Is(err, ErrStaleTarget) {
		t.Fatalf("Verify exe mismatch (%s) = %v, want ErrStaleTarget", other, err)
	}
	if _, err := e.Kill(ctx, ref, response.ScopeProcess); !errors.Is(err, ErrStaleTarget) {
		t.Fatalf("Kill exe mismatch = %v, want ErrStaleTarget", err)
	}
	if !alive(pid) {
		t.Fatalf("refused Kill signalled the process; it is gone")
	}
}

// TestReusedPidRefusedDoesNotSignal is (c), the pid-reuse safety the
// whack-a-mole stress test hammers: the alert's event time is in the past, but
// the process now holding the pid started later, so it must be a different
// (reused) process. The executor refuses and sends no signal.
func TestReusedPidRefusedDoesNotSignal(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	e, _ := New(Config{Enforce: true, AllowRoot: true})
	ctx := context.Background()
	// Event time an hour before this process started: any process at this pid
	// now was forked after the event, hence a reuser.
	ref := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now().Add(-1 * time.Hour)}

	if _, err := e.Verify(ctx, ref); !errors.Is(err, ErrStaleTarget) {
		t.Fatalf("Verify reused-pid = %v, want ErrStaleTarget", err)
	}
	if _, err := e.Kill(ctx, ref, response.ScopeProcess); !errors.Is(err, ErrStaleTarget) {
		t.Fatalf("Kill reused-pid = %v, want ErrStaleTarget", err)
	}
	if !alive(pid) {
		t.Fatalf("refused Kill signalled the process; it is gone")
	}
}

// TestCollectRefusesStaleTarget is (d): Collect identifies before snapshotting,
// so a stale/mismatched target is refused (no /proc snapshot of the wrong
// process is written).
func TestCollectRefusesStaleTarget(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	dir := t.TempDir()
	e, _ := New(Config{Enforce: true, AllowRoot: true, EvidenceDir: dir})
	ref := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now().Add(-1 * time.Hour)}

	h, err := e.Collect(context.Background(), ref)
	if !errors.Is(err, ErrStaleTarget) {
		t.Fatalf("Collect stale target = %v, want ErrStaleTarget", err)
	}
	if h.ID != "" {
		t.Errorf("refused Collect returned a handle: %+v", h)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Errorf("refused Collect wrote evidence dirs: %v", ents)
	}
}

// ---- F2: the basename-denylist cloak is closed -----------------------------

// TestMasqueradeNamedSshdIsKilled is the headline F2 proof: a self-owned
// process whose LIVE exe is a protected NAME (`sshd`) at an UNTRUSTED path
// (/tmp/<scratch>/sshd) is NOT shielded by the name denylist -- it is killed.
// Before the fix, filepath.Base(exe)=="sshd" made it immune (ErrDenied). The
// Verify result records Masquerade=true so the ledger shows the cloak.
func TestMasqueradeNamedSshdIsKilled(t *testing.T) {
	cmd, pid, masqPath := spawnMasquerader(t, "sshd")
	e, _ := New(Config{Enforce: true, AllowRoot: true})
	ctx := context.Background()
	ref := response.ProcessRef{PID: pid, Image: masqPath, EventTime: time.Now()}

	// It is seen through as a masquerade, not refused as protected.
	live, verr := e.Verify(ctx, ref)
	if verr != nil {
		t.Fatalf("Verify masquerader = %v, want nil (actionable)", verr)
	}
	if !live.Masquerade {
		t.Errorf("Verify did not flag Masquerade for a protected name at %s", masqPath)
	}

	h, err := e.Kill(ctx, ref, response.ScopeProcess)
	if err != nil {
		t.Fatalf("Kill masquerader = %v, want nil (it must be killable)", err)
	}
	if h.DryRun || h.Method != "pidfd" {
		t.Errorf("Kill masquerader handle = %+v, want a real pidfd kill", h)
	}
	werr := cmd.Wait()
	var ee *osexec.ExitError
	if !errors.As(werr, &ee) {
		t.Fatalf("after Kill, masquerader wait = %v, want a signal exit", werr)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && (!ws.Signaled() || ws.Signal() != syscall.SIGKILL) {
		t.Errorf("masquerader exit = %v, want killed by SIGKILL", ee)
	}
}

// TestProtectedNameAtTrustedPathRefused proves the other side: when the live
// exe IS a protected name under a trusted prefix, it stays refused. We stage
// the trusted realpath via the readExe seam against a self-owned sleep.
func TestProtectedNameAtTrustedPathRefused(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	orig := readExe
	readExe = func(int) (string, error) { return "/nix/store/zzz-openssh/bin/sshd", nil }
	t.Cleanup(func() { readExe = orig })

	e, _ := New(Config{Enforce: true, AllowRoot: true})
	// Image empty so the exe-identity compare does not fire; we are testing the
	// live name+trusted-path shield only.
	ref := response.ProcessRef{PID: pid, Image: "", EventTime: time.Now()}
	_ = bin

	if _, err := e.Verify(context.Background(), ref); !errors.Is(err, ErrDenied) {
		t.Fatalf("Verify sshd under /nix/store = %v, want ErrDenied (protected)", err)
	}
	if _, err := e.Kill(context.Background(), ref, response.ScopeProcess); !errors.Is(err, ErrDenied) {
		t.Fatalf("Kill sshd under /nix/store = %v, want ErrDenied", err)
	}
	if !alive(pid) {
		t.Fatalf("refused Kill signalled the protected process")
	}
}

// TestDenylistRefusesPid1StillHolds keeps the pid-1 guard explicit alongside F2.
func TestDenylistRefusesPid1StillHolds(t *testing.T) {
	e, _ := New(Config{Enforce: true, AllowRoot: true})
	if _, err := e.Kill(context.Background(), response.ProcessRef{PID: 1, Image: "/sbin/init"}, response.ScopeProcess); !errors.Is(err, ErrDenied) {
		t.Fatalf("Kill pid 1 = %v, want ErrDenied", err)
	}
}

// ---- F3: live uid-0 and cgroup-unit rails ----------------------------------

// TestLiveUID0RefusedUnlessAllowRoot proves the live uid-0 rail: a target whose
// LIVE uid is 0 is refused when allowRoot is false, and acted on when true. The
// uid is staged via the readUID seam against a self-owned sleep.
func TestLiveUID0RefusedUnlessAllowRoot(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	orig := readUID
	readUID = func(int) (int, error) { return 0, nil }
	t.Cleanup(func() { readUID = orig })
	ctx := context.Background()
	ref := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()}

	// allowRoot false: refused.
	deny, _ := New(Config{Enforce: true})
	if _, err := deny.Verify(ctx, ref); !errors.Is(err, ErrDenied) {
		t.Fatalf("Verify uid-0 with allowRoot=false = %v, want ErrDenied", err)
	}
	if _, err := deny.Kill(ctx, ref, response.ScopeProcess); !errors.Is(err, ErrDenied) {
		t.Fatalf("Kill uid-0 with allowRoot=false = %v, want ErrDenied", err)
	}
	if !alive(pid) {
		t.Fatalf("refused Kill signalled the process")
	}

	// allowRoot true: the uid rail no longer refuses (Verify succeeds).
	allow, _ := New(Config{Enforce: true, AllowRoot: true})
	if live, err := allow.Verify(ctx, ref); err != nil {
		t.Fatalf("Verify uid-0 with allowRoot=true = %v, want nil", err)
	} else if live.UID != 0 {
		t.Errorf("live.UID = %d, want 0", live.UID)
	}
}

// TestLiveUIDUnreadableFailsClosed: if the uid cannot be read and allowRoot is
// false, the target is refused (cannot confirm it is not root).
func TestLiveUIDUnreadableFailsClosed(t *testing.T) {
	_, pid, bin := spawnSleep(t)
	orig := readUID
	readUID = func(int) (int, error) { return -1, errors.New("forced status failure") }
	t.Cleanup(func() { readUID = orig })

	e, _ := New(Config{Enforce: true}) // allowRoot false
	ref := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()}
	if _, err := e.Verify(context.Background(), ref); !errors.Is(err, ErrDenied) {
		t.Fatalf("Verify with unreadable uid (allowRoot=false) = %v, want ErrDenied", err)
	}
	if !alive(pid) {
		t.Fatalf("refused Kill signalled the process")
	}
}

// TestLiveCgroupProtectedUnitRefused proves the live cgroup-unit rail: a target
// whose cgroup resolves to a protected unit is refused regardless of exe name.
// Staged via the readCgroup seam against a self-owned sleep.
func TestLiveCgroupProtectedUnitRefused(t *testing.T) {
	for _, cg := range []string{"/init.scope", "/system.slice/sshd.service"} {
		t.Run(cg, func(t *testing.T) {
			_, pid, bin := spawnSleep(t)
			orig := readCgroup
			readCgroup = func(int) (string, error) { return cg, nil }
			t.Cleanup(func() { readCgroup = orig })

			e, _ := New(Config{Enforce: true, AllowRoot: true})
			ref := response.ProcessRef{PID: pid, Image: bin, EventTime: time.Now()}
			if _, err := e.Verify(context.Background(), ref); !errors.Is(err, ErrDenied) {
				t.Fatalf("Verify in cgroup %s = %v, want ErrDenied", cg, err)
			}
			if _, err := e.Kill(context.Background(), ref, response.ScopeProcess); !errors.Is(err, ErrDenied) {
				t.Fatalf("Kill in cgroup %s = %v, want ErrDenied", cg, err)
			}
			if !alive(pid) {
				t.Fatalf("refused Kill signalled the process in %s", cg)
			}
		})
	}
}

// TestCgroupProtectedUnit unit-tests the pure classifier: critical units and
// init.scope are protected; a user session scope or an arbitrary service is
// not (so a reverse shell inheriting a random unit's cgroup stays actionable).
func TestCgroupProtectedUnit(t *testing.T) {
	cases := map[string]bool{
		"/init.scope":                                 true,
		"/system.slice/sshd.service":                  true,
		"/system.slice/auditd.service":                true,
		"/system.slice/dbus-broker.service":           true,
		"/user.slice/user-1100.slice/session-3.scope": false,
		"/system.slice/my-app.service":                false,
		"/user.slice/user-1100.slice/user@1100.service/app.slice/run-u42.service": false,
		"": false,
	}
	for cg, want := range cases {
		if got := cgroupProtectedUnit(cg); got != want {
			t.Errorf("cgroupProtectedUnit(%q) = %v, want %v", cg, got, want)
		}
	}
}

// TestUnderTrustedExePrefix unit-tests the trusted-path classifier used by F2.
func TestUnderTrustedExePrefix(t *testing.T) {
	cases := map[string]bool{
		"/nix/store/abc/bin/sshd":        true,
		"/usr/sbin/sshd":                 true,
		"/run/current-system/sw/bin/ssh": true,
		"/run/wrappers/bin/sudo":         true,
		"/tmp/.x/sshd":                   false,
		"/home/u/sshd":                   false,
		"/dev/shm/sshd":                  false,
		"/run/user/1100/sshd":            false,
	}
	for p, want := range cases {
		if got := underTrustedExePrefix(p); got != want {
			t.Errorf("underTrustedExePrefix(%q) = %v, want %v", p, got, want)
		}
	}
}
