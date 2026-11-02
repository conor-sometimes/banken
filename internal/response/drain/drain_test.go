package drain

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/response"
	"github.com/conor-sometimes/banken/internal/response/exec"
)

// fakeExec records calls and performs nothing. It models an order-keyed store
// via the applied map (the real store lands with build items 4-5), and lets a
// test force a per-action error (the stale-collect case). It never touches a
// real process or file.
type fakeExec struct {
	enforcing  bool
	calls      []string
	applied    map[string]exec.Handle // order id -> handle, consulted by Applied
	recover    []exec.RecoveryResult  // returned by Recover (the startup repair pass)
	freezeErr  error
	killErr    error
	collectErr error
	quarErr    error
}

func newFake() *fakeExec { return &fakeExec{applied: map[string]exec.Handle{}} }

func (f *fakeExec) Enforcing() bool { return f.enforcing }

func (f *fakeExec) Verify(_ context.Context, p response.ProcessRef) (exec.Live, error) {
	return exec.Live{PID: p.PID, Exe: p.Image}, nil
}

func (f *fakeExec) Freeze(_ context.Context, p response.ProcessRef, _ response.Scope) (exec.Handle, error) {
	f.calls = append(f.calls, "freeze")
	if f.freezeErr != nil {
		return exec.Handle{}, f.freezeErr
	}
	return exec.Handle{ID: "h-freeze", Kind: response.ActionFreeze, PID: p.PID, Method: "cgroup", Exe: p.Image, StartTime: p.StartTime, DryRun: !f.enforcing}, nil
}

func (f *fakeExec) Kill(_ context.Context, p response.ProcessRef, _ response.Scope) (exec.Handle, error) {
	f.calls = append(f.calls, "kill")
	if f.killErr != nil {
		return exec.Handle{}, f.killErr
	}
	return exec.Handle{ID: "h-kill", Kind: response.ActionKill, PID: p.PID, Method: "pidfd", Exe: p.Image, DryRun: !f.enforcing}, nil
}

func (f *fakeExec) Quarantine(_ context.Context, fr response.FileRef) (exec.Handle, error) {
	f.calls = append(f.calls, "quarantine")
	if f.quarErr != nil {
		return exec.Handle{}, f.quarErr
	}
	return exec.Handle{ID: "h-quar", Kind: response.ActionQuarantine, Method: "rename", DryRun: !f.enforcing}, nil
}

func (f *fakeExec) Collect(_ context.Context, p response.ProcessRef) (exec.Handle, error) {
	f.calls = append(f.calls, "collect")
	if f.collectErr != nil {
		return exec.Handle{}, f.collectErr
	}
	return exec.Handle{ID: "h-collect", Kind: response.ActionCollect, PID: p.PID, Exe: p.Image, DryRun: !f.enforcing}, nil
}

func (f *fakeExec) Thaw(_ context.Context, _ exec.Handle) error    { return nil }
func (f *fakeExec) Restore(_ context.Context, _ exec.Handle) error { return nil }

func (f *fakeExec) Applied(_ context.Context, orderID string) (exec.Handle, bool, error) {
	h, ok := f.applied[orderID]
	return h, ok, nil
}

func (f *fakeExec) Recover(_ context.Context) ([]exec.RecoveryResult, error) {
	return f.recover, nil
}

// ---- policies and alerts ----

func freezePolicy(t *testing.T) response.Policy {
	t.Helper()
	return mustParse(t, `
mode: enforce
minLevel: high
enforceSources: [auditd]
allowRoot: false
actions:
  - name: freeze-revshell
    rules: [reverse_shell]
    action: freeze
    scope: tree
  - name: collect-suspicious
    rules: [suspicious_exec]
    action: collect
`)
}

func mustParse(t *testing.T, y string) response.Policy {
	t.Helper()
	p, err := response.ParsePolicy([]byte(y))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return p
}

func revshellAlert() alert.Alert {
	now := time.Now().UTC()
	return alert.Alert{
		Kind:   alert.KindSigma,
		Rule:   "reverse_shell",
		Level:  "critical",
		Source: "auditd",
		Time:   now,
		Event: event.Event{
			Source: "auditd",
			Image:  "/tmp/.x/sh",
			User:   "alice",
			PID:    4242,
			PPID:   4100,
			Time:   now,
		},
	}
}

func collectAlert() alert.Alert {
	a := revshellAlert()
	a.Rule = "suspicious_exec"
	return a
}

// ---- drain environment ----

type drainEnv struct {
	spool     *response.Spool
	spoolDir  string
	ledger    *response.Ledger
	ledgerDir string
	fake      *fakeExec
	policy    response.Policy
	armed     bool
	now       time.Time
}

func setup(t *testing.T, policy response.Policy, armed bool) *drainEnv {
	t.Helper()
	root := t.TempDir()
	spoolDir := filepath.Join(root, "spool")
	spool, err := response.NewSpool(spoolDir, filepath.Join(root, "spool.tmp"))
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	ledgerDir := filepath.Join(root, "ledger")
	led, err := response.NewLedger(ledgerDir)
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}
	return &drainEnv{spool: spool, spoolDir: spoolDir, ledger: led, ledgerDir: ledgerDir, fake: newFake(), policy: policy, armed: armed, now: time.Now().UTC()}
}

func (e *drainEnv) opts() Options {
	return Options{
		Spool:                e.spool,
		Policy:               e.policy,
		Executor:             e.fake,
		Ledger:               e.ledger,
		Self:                 response.SelfIdentity{Exe: "/run/current-system/sw/bin/banken"},
		Armed:                e.armed,
		MaxAge:               10 * time.Minute,
		QuarantineAllowPaths: []string{"/tmp", "/var/tmp", "/dev/shm", "/home", "/root"},
		Version:              "test",
		Now:                  func() time.Time { return e.now },
	}
}

func (e *drainEnv) run(t *testing.T) error {
	t.Helper()
	return Run(context.Background(), e.opts())
}

// buildOrder runs Decide to produce a legitimate order the drain will agree
// with (verdicts equal). when sets the order's decided time.
func (e *drainEnv) buildOrder(id string, a alert.Alert, when time.Time) response.Order {
	d := response.Decide(response.Input{Alert: a, Policy: e.policy, Armed: e.armed})
	return response.Order{Version: response.OrderVersion, ID: id, Time: when, Alert: a, Decision: d, Policy: e.policy.Hash(), Banken: "test"}
}

func (e *drainEnv) put(t *testing.T, o response.Order) {
	t.Helper()
	if err := e.spool.Write(o); err != nil {
		t.Fatalf("spool Write %s: %v", o.ID, err)
	}
}

func (e *drainEnv) actions(t *testing.T) []map[string]any {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(e.ledgerDir, "actions-*.jsonl"))
	var out []map[string]any
	for _, m := range matches {
		f, err := os.Open(m) //nolint:gosec // test tempdir
		if err != nil {
			t.Fatalf("open %s: %v", m, err)
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

func (e *drainEnv) spoolEmpty(t *testing.T) bool {
	t.Helper()
	names, err := e.spool.List()
	if err != nil {
		t.Fatalf("spool List: %v", err)
	}
	return len(names) == 0
}

// ---- tests ----

// The happy path: an order whose verdict the drain agrees with is dispatched,
// recorded executed with a handle and the bound identity, and unlinked.
func TestDrainExecutes(t *testing.T) {
	e := setup(t, freezePolicy(t), true)
	e.fake.enforcing = true
	e.put(t, e.buildOrder("ord1", revshellAlert(), e.now))
	if err := e.run(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !e.spoolEmpty(t) {
		t.Fatalf("spool not drained")
	}
	acts := e.actions(t)
	if len(acts) != 1 || acts[0]["phase"] != "executed" || acts[0]["action"] != "freeze" {
		t.Fatalf("expected one executed freeze line, got %v", acts)
	}
	if acts[0]["decisionId"] != "ord1" {
		t.Errorf("decisionId = %v, want ord1", acts[0]["decisionId"])
	}
	live, _ := acts[0]["live"].(map[string]any)
	if live == nil || live["exe"] != "/tmp/.x/sh" {
		t.Errorf("expected live identity recorded, got %v", acts[0]["live"])
	}
	if len(e.fake.calls) != 1 || e.fake.calls[0] != "freeze" {
		t.Fatalf("expected one freeze dispatch, got %v", e.fake.calls)
	}
}

// Expired: an order older than maxAge is recorded expired and unlinked without
// any dispatch.
func TestDrainExpired(t *testing.T) {
	e := setup(t, freezePolicy(t), true)
	e.put(t, e.buildOrder("old", revshellAlert(), e.now.Add(-30*time.Minute)))
	if err := e.run(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	acts := e.actions(t)
	if len(acts) != 1 || acts[0]["phase"] != "expired" {
		t.Fatalf("expected one expired line, got %v", acts)
	}
	if len(e.fake.calls) != 0 {
		t.Fatalf("expired order was dispatched: %v", e.fake.calls)
	}
	if !e.spoolEmpty(t) {
		t.Fatalf("expired order not unlinked")
	}
}

// Kill-switch: a fresh kill-switch file stops every order; the drain records
// failed/kill-switch and dispatches nothing.
func TestDrainKillSwitch(t *testing.T) {
	e := setup(t, freezePolicy(t), true)
	ks := filepath.Join(t.TempDir(), "disable")
	if err := os.WriteFile(ks, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.policy.KillSwitchPath = ks // overrides the default; validated already
	e.put(t, e.buildOrder("ord1", revshellAlert(), e.now))
	if err := e.run(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	acts := e.actions(t)
	if len(acts) != 1 || acts[0]["phase"] != "failed" || acts[0]["note"] != "kill-switch" {
		t.Fatalf("expected one failed/kill-switch line, got %v", acts)
	}
	if len(e.fake.calls) != 0 {
		t.Fatalf("kill-switch order was dispatched: %v", e.fake.calls)
	}
	if !e.spoolEmpty(t) {
		t.Fatalf("kill-switch order not unlinked")
	}
}

// Malformed: a bad order (unknown version) is recorded failed/malformed and
// unlinked, never dispatched, never left to wedge the queue.
func TestDrainMalformed(t *testing.T) {
	e := setup(t, freezePolicy(t), true)
	o := e.buildOrder("badver", revshellAlert(), e.now)
	o.Version = 99
	// Write it raw (spool.Write would accept it; the drain's Read rejects it).
	raw, _ := json.Marshal(o)
	if err := os.WriteFile(filepath.Join(e.spoolDir, "badver.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.run(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	acts := e.actions(t)
	if len(acts) != 1 || acts[0]["phase"] != "failed" || acts[0]["note"] != "malformed" {
		t.Fatalf("expected one failed/malformed line, got %v", acts)
	}
	if len(e.fake.calls) != 0 {
		t.Fatalf("malformed order was dispatched: %v", e.fake.calls)
	}
	if !e.spoolEmpty(t) {
		t.Fatalf("malformed order not unlinked")
	}
}

// Downgraded, forged kill under a freeze policy: an order asking kill for a rule
// the policy maps to freeze is downgraded (the helper decided freeze), never a
// kill. An order can only lower an action, never raise it.
func TestDrainDowngradeForgedKill(t *testing.T) {
	e := setup(t, freezePolicy(t), true)
	o := e.buildOrder("forged", revshellAlert(), e.now)
	o.Decision.Action = response.ActionKill // forge: claim kill though the policy maps freeze
	e.put(t, o)
	if err := e.run(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	acts := e.actions(t)
	if len(acts) != 1 || acts[0]["phase"] != "downgraded" {
		t.Fatalf("expected one downgraded line, got %v", acts)
	}
	if acts[0]["requested"] != "kill" || acts[0]["action"] != "freeze" {
		t.Errorf("downgraded line = requested %v action %v, want kill/freeze", acts[0]["requested"], acts[0]["action"])
	}
	if len(e.fake.calls) != 0 {
		t.Fatalf("a forged kill was dispatched: %v", e.fake.calls)
	}
}

// Downgraded, order for an unmapped rule: the helper's policy selects no entry,
// so the verdict is none and the order is downgraded, never acted on.
func TestDrainDowngradeUnmappedRule(t *testing.T) {
	e := setup(t, freezePolicy(t), true)
	a := revshellAlert()
	a.Rule = "not_in_policy"
	o := e.buildOrder("unmapped", a, e.now)
	o.Decision.Action = response.ActionKill // forge an action despite no policy entry
	o.Decision.Target = response.Target{Process: &response.ProcessRef{PID: 4242, Image: "/tmp/.x/sh"}}
	e.put(t, o)
	if err := e.run(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	acts := e.actions(t)
	if len(acts) != 1 || acts[0]["phase"] != "downgraded" {
		t.Fatalf("expected one downgraded line, got %v", acts)
	}
	if acts[0]["action"] != "none" {
		t.Errorf("unmapped rule: action = %v, want none", acts[0]["action"])
	}
	if len(e.fake.calls) != 0 {
		t.Fatalf("an unmapped-rule order was dispatched: %v", e.fake.calls)
	}
}

// Already-applied on replay: an order whose id the store already holds (an
// operator copied it back in) is a no-op -- recorded already-applied, not
// dispatched again.
func TestDrainAlreadyApplied(t *testing.T) {
	e := setup(t, freezePolicy(t), true)
	e.fake.enforcing = true
	e.fake.applied["ord1"] = exec.Handle{ID: "h-freeze", Kind: response.ActionFreeze, PID: 4242}
	e.put(t, e.buildOrder("ord1", revshellAlert(), e.now))
	if err := e.run(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	acts := e.actions(t)
	if len(acts) != 1 || acts[0]["phase"] != "already-applied" {
		t.Fatalf("expected one already-applied line, got %v", acts)
	}
	if len(e.fake.calls) != 0 {
		t.Fatalf("already-applied order was re-dispatched: %v", e.fake.calls)
	}
	if !e.spoolEmpty(t) {
		t.Fatalf("already-applied order not unlinked")
	}
}

// Crash-after-act replay: the helper crashed between the act and the unlink, so
// on restart the order is still in the spool AND the store carries its manifest.
// The drain must not act twice: it records already-applied and unlinks. This is
// the §2.6 "crashes between the act and the unlink" row.
func TestDrainCrashAfterActReplay(t *testing.T) {
	e := setup(t, freezePolicy(t), true)
	e.fake.enforcing = true

	// First pass acts and records the manifest (modelled by the store map), but
	// crashes before unlink: re-seed the order and the store to that state.
	order := e.buildOrder("ord1", revshellAlert(), e.now)
	e.put(t, order)
	if err := e.run(t); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if len(e.fake.calls) != 1 {
		t.Fatalf("first pass should dispatch once, got %v", e.fake.calls)
	}
	// Simulate the crash: the order is back in the spool and the store now holds
	// its manifest (what the real executor would have written before the act).
	e.fake.applied["ord1"] = exec.Handle{ID: "h-freeze", Kind: response.ActionFreeze, PID: 4242}
	e.put(t, order)

	if err := e.run(t); err != nil {
		t.Fatalf("replay Run: %v", err)
	}
	if len(e.fake.calls) != 1 {
		t.Fatalf("replay re-dispatched (not idempotent): %v", e.fake.calls)
	}
	acts := e.actions(t)
	if len(acts) != 2 || acts[1]["phase"] != "already-applied" {
		t.Fatalf("expected executed then already-applied, got %v", acts)
	}
	if !e.spoolEmpty(t) {
		t.Fatalf("replayed order not unlinked")
	}
}

// Recovery pass: a store-backed executor's startup repairs are each recorded as
// a `recovered` ledger line before any order is processed. This proves the
// drain runs the pass (build item 4) and ledgers it; the repair logic itself is
// unit-tested in the exec package.
func TestDrainRecoveryPass(t *testing.T) {
	e := setup(t, freezePolicy(t), true)
	e.fake.enforcing = true
	e.fake.recover = []exec.RecoveryResult{
		{ID: "h1", Order: "ord-a", Kind: response.ActionFreeze, Outcome: "rolled-back"},
		{ID: "cg2", Outcome: "cgroup-removed"},
	}
	if err := e.run(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	acts := e.actions(t)
	if len(acts) != 2 {
		t.Fatalf("expected two recovered lines, got %v", acts)
	}
	for _, a := range acts {
		if a["phase"] != "recovered" {
			t.Errorf("phase = %v, want recovered", a["phase"])
		}
	}
	if acts[0]["note"] != "rolled-back" || acts[1]["note"] != "cgroup-removed" {
		t.Errorf("recovered notes = %v, %v; want rolled-back, cgroup-removed", acts[0]["note"], acts[1]["note"])
	}
	if acts[0]["decisionId"] != "ord-a" {
		t.Errorf("recovered decisionId = %v, want ord-a", acts[0]["decisionId"])
	}
}

// Policy-outside-sandbox refused at startup: a policy quarantine.allowPaths
// entry not under any sandbox ReadWritePaths path is a startup error; the drain
// touches nothing (the order stays in the spool).
func TestDrainRefusesPolicyOutsideSandbox(t *testing.T) {
	policy := mustParse(t, `
mode: enforce
minLevel: high
enforceSources: [auditd]
quarantine:
  allowPaths: [/tmp]
actions:
  - name: q
    rules: [download_ip_to_tmp]
    action: quarantine
    target: targetFilename
`)
	e := setup(t, policy, true)
	o := e.buildOrder("ord1", revshellAlert(), e.now)
	e.put(t, o)

	opts := e.opts()
	opts.QuarantineAllowPaths = []string{"/var/tmp"} // the sandbox does NOT include /tmp
	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatalf("expected a startup error for a policy path outside the sandbox")
	}
	if !strings.Contains(err.Error(), "/tmp") {
		t.Errorf("startup error should name the offending path, got %v", err)
	}
	if e.spoolEmpty(t) {
		t.Fatalf("a startup refusal must touch nothing; the order was removed")
	}
	if len(e.fake.calls) != 0 {
		t.Fatalf("a startup refusal dispatched: %v", e.fake.calls)
	}
}

// A stale collect returns failed with the ErrStaleTarget sentinel: F9 (collect
// re-identifies before snapshotting) stays closed through the drain port. The
// test asserts the sentinel structurally, not a substring.
func TestDrainStaleCollectFails(t *testing.T) {
	e := setup(t, freezePolicy(t), true)
	e.fake.enforcing = true
	e.fake.collectErr = exec.ErrStaleTarget
	e.put(t, e.buildOrder("ord1", collectAlert(), e.now))
	if err := e.run(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	acts := e.actions(t)
	if len(acts) != 1 || acts[0]["phase"] != "failed" {
		t.Fatalf("expected one failed line, got %v", acts)
	}
	if acts[0]["error"] != exec.ErrStaleTarget.Error() {
		t.Errorf("error = %v, want the ErrStaleTarget sentinel message", acts[0]["error"])
	}
	if acts[0]["action"] != "collect" {
		t.Errorf("action = %v, want collect", acts[0]["action"])
	}
	if !e.spoolEmpty(t) {
		t.Fatalf("stale collect order not unlinked")
	}
}
