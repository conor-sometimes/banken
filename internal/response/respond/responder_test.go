package respond

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/response"
	"github.com/conor-sometimes/banken/internal/response/exec"
)

// fakeExecutor records every call and performs nothing. enforcing reports what
// the executor would be armed as; the protocol tests assert on the calls, never
// on a real process.
type fakeExecutor struct {
	enforcing bool
	calls     []string
	failKill  error
}

func (f *fakeExecutor) Enforcing() bool { return f.enforcing }

func (f *fakeExecutor) Verify(_ context.Context, p response.ProcessRef) (exec.Live, error) {
	return exec.Live{PID: p.PID}, nil
}

func (f *fakeExecutor) Kill(_ context.Context, p response.ProcessRef, scope response.Scope) (exec.Handle, error) {
	f.calls = append(f.calls, "kill")
	if f.failKill != nil {
		return exec.Handle{}, f.failKill
	}
	return exec.Handle{ID: "h-kill", Kind: response.ActionKill, PID: p.PID, Method: "pidfd", DryRun: !f.enforcing}, nil
}

func (f *fakeExecutor) Freeze(_ context.Context, p response.ProcessRef, scope response.Scope) (exec.Handle, error) {
	f.calls = append(f.calls, "freeze")
	return exec.Handle{ID: "h-freeze", Kind: response.ActionFreeze, PID: p.PID, DryRun: !f.enforcing}, nil
}

func (f *fakeExecutor) Quarantine(_ context.Context, fr response.FileRef) (exec.Handle, error) {
	f.calls = append(f.calls, "quarantine")
	return exec.Handle{ID: "h-quar", Kind: response.ActionQuarantine, DryRun: !f.enforcing}, nil
}

func (f *fakeExecutor) Thaw(_ context.Context, h exec.Handle) error { return nil }

func (f *fakeExecutor) Restore(_ context.Context, h exec.Handle) error { return nil }

func (f *fakeExecutor) Collect(_ context.Context, p response.ProcessRef) (exec.Handle, error) {
	f.calls = append(f.calls, "collect")
	return exec.Handle{ID: "h-collect", Kind: response.ActionCollect, PID: p.PID, DryRun: !f.enforcing}, nil
}

func killPolicy(t *testing.T, mode response.Mode) response.Policy {
	t.Helper()
	y := "mode: " + string(mode) + `
minLevel: high
enforceSources: [auditd]
actions:
  - name: kill-revshell
    rules: [reverse_shell]
    action: kill
    scope: process
`
	p, err := response.ParsePolicy([]byte(y))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	return p
}

func revshellAlert() alert.Alert {
	return alert.Alert{
		Kind:   alert.KindSigma,
		Rule:   "reverse_shell",
		Level:  "critical",
		Source: "auditd",
		Time:   time.Unix(1700000000, 0).UTC(),
		Tags:   []string{"attack.command-and-control"},
		Event: event.Event{
			Source:      "auditd",
			Image:       "/usr/bin/bash",
			CommandLine: "bash -c : /dev/tcp/192.0.2.30/4444",
			User:        "alice",
			PID:         4242,
			PPID:        4100,
			Time:        time.Unix(1700000000, 0).UTC(),
		},
	}
}

func readActions(t *testing.T, dir string) []map[string]any {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(dir, "actions-*.jsonl"))
	var out []map[string]any
	for _, m := range matches {
		f, err := os.Open(m) //nolint:gosec // test-owned tempdir
		if err != nil {
			t.Fatalf("open action ledger: %v", err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var rec map[string]any
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				t.Fatalf("decode action line: %v", err)
			}
			out = append(out, rec)
		}
		_ = f.Close()
	}
	return out
}

func newResponder(t *testing.T, p response.Policy, fe *fakeExecutor) (*Responder, string) {
	t.Helper()
	dir := t.TempDir()
	led, err := response.NewLedger(dir)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	return New(p, response.SelfIdentity{Exe: "/run/current-system/sw/bin/banken"}, fe, led, "test", nil), dir
}

// Observe mode: Decide returns none, so the executor is never called and no
// action line is written. This is the default-inert proof at the responder.
func TestObserveModeNeverCallsExecutor(t *testing.T) {
	fe := &fakeExecutor{enforcing: false}
	r, dir := newResponder(t, killPolicy(t, response.ModeObserve), fe)
	if err := r.Respond(revshellAlert()); err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if len(fe.calls) != 0 {
		t.Fatalf("observe mode called executor: %v", fe.calls)
	}
	if acts := readActions(t, dir); len(acts) != 0 {
		t.Fatalf("observe mode wrote %d action line(s), want 0", len(acts))
	}
}

// Enforce mode + armed executor: the executor's Kill is called and an executed
// action line records the real (non-dry-run) kill.
func TestEnforceCallsKillAndRecords(t *testing.T) {
	fe := &fakeExecutor{enforcing: true}
	r, dir := newResponder(t, killPolicy(t, response.ModeEnforce), fe)
	if err := r.Respond(revshellAlert()); err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if len(fe.calls) != 1 || fe.calls[0] != "kill" {
		t.Fatalf("expected one kill call, got %v", fe.calls)
	}
	acts := readActions(t, dir)
	if len(acts) != 1 {
		t.Fatalf("expected 1 action line, got %d", len(acts))
	}
	a := acts[0]
	if a["phase"] != "executed" || a["action"] != "kill" {
		t.Fatalf("action line = %v", a)
	}
	if a["enforced"] != true {
		t.Fatalf("expected enforced=true, got %v", a["enforced"])
	}
	h, _ := a["handle"].(map[string]any)
	if h == nil || h["dryRun"] != false {
		t.Fatalf("expected real (dryRun=false) handle, got %v", a["handle"])
	}
}

// Enforce mode but a DRY-RUN executor: the decision still reaches the executor
// (Kill is called), but the handle is marked dryRun and nothing real happened.
// This is the real-host posture: policy says enforce, executor is not armed.
func TestEnforceDryRunExecutorMarksDryRun(t *testing.T) {
	fe := &fakeExecutor{enforcing: false}
	r, dir := newResponder(t, killPolicy(t, response.ModeEnforce), fe)
	if err := r.Respond(revshellAlert()); err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if len(fe.calls) != 1 {
		t.Fatalf("expected one kill call, got %v", fe.calls)
	}
	acts := readActions(t, dir)
	if len(acts) != 1 || acts[0]["enforced"] != false {
		t.Fatalf("expected one action line with enforced=false, got %v", acts)
	}
	h, _ := acts[0]["handle"].(map[string]any)
	if h == nil || h["dryRun"] != true {
		t.Fatalf("expected dryRun handle, got %v", acts[0]["handle"])
	}
}

// A failing executor records a failed action line and does NOT suppress the
// alert (Respond returns nil).
func TestExecutorFailureRecordedNotFatal(t *testing.T) {
	fe := &fakeExecutor{enforcing: true, failKill: exec.ErrGone}
	r, dir := newResponder(t, killPolicy(t, response.ModeEnforce), fe)
	if err := r.Respond(revshellAlert()); err != nil {
		t.Fatalf("Respond returned error: %v", err)
	}
	acts := readActions(t, dir)
	if len(acts) != 1 || acts[0]["phase"] != "failed" {
		t.Fatalf("expected one failed action line, got %v", acts)
	}
	if acts[0]["error"] == "" || acts[0]["error"] == nil {
		t.Fatalf("expected an error string on the failed line")
	}
}

// The kill-switch file stops the action even in enforce mode with an armed
// executor: Decide rails to none, the executor is never called.
func TestKillSwitchStopsEverything(t *testing.T) {
	// Point the policy's kill-switch at a file that exists.
	ks := filepath.Join(t.TempDir(), "disable")
	if err := os.WriteFile(ks, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	y := `mode: enforce
minLevel: high
enforceSources: [auditd]
killSwitchPath: ` + ks + `
actions:
  - name: kill-revshell
    rules: [reverse_shell]
    action: kill
    scope: process
`
	p, err := response.ParsePolicy([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fe := &fakeExecutor{enforcing: true}
	r, _ := newResponder(t, p, fe)
	if err := r.Respond(revshellAlert()); err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if len(fe.calls) != 0 {
		t.Fatalf("kill-switch failed to stop the executor: %v", fe.calls)
	}
}

// Dedupe: the same target decided twice in one run acts once; the second is
// railed as a duplicate.
func TestDuplicateTargetActsOnce(t *testing.T) {
	fe := &fakeExecutor{enforcing: true}
	r, _ := newResponder(t, killPolicy(t, response.ModeEnforce), fe)
	a := revshellAlert()
	if err := r.Respond(a); err != nil {
		t.Fatal(err)
	}
	if err := r.Respond(a); err != nil {
		t.Fatal(err)
	}
	if len(fe.calls) != 1 {
		t.Fatalf("expected the duplicate to be skipped, got calls %v", fe.calls)
	}
}
