package respond

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/response"
)

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

// testEnv is a responder over a spool and ledger, both under t.TempDir().
type testEnv struct {
	r         *Responder
	ledgerDir string
	spool     *response.Spool
	spoolDir  string
	tmpDir    string
}

func newResponder(t *testing.T, p response.Policy, armed bool) testEnv {
	t.Helper()
	root := t.TempDir()
	ledgerDir := filepath.Join(root, "ledger")
	led, err := response.NewLedger(ledgerDir)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	spoolDir := filepath.Join(root, "spool")
	tmpDir := filepath.Join(root, "spool.tmp")
	spool, err := response.NewSpool(spoolDir, tmpDir)
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	r := New(p, response.SelfIdentity{Exe: "/run/current-system/sw/bin/banken"}, spool, led, armed, "test", nil)
	return testEnv{r: r, ledgerDir: ledgerDir, spool: spool, spoolDir: spoolDir, tmpDir: tmpDir}
}

func (e testEnv) orders(t *testing.T) []response.Order {
	t.Helper()
	names, err := e.spool.List()
	if err != nil {
		t.Fatalf("spool List: %v", err)
	}
	out := make([]response.Order, 0, len(names))
	for _, n := range names {
		o, err := e.spool.Read(n)
		if err != nil {
			t.Fatalf("spool Read %s: %v", n, err)
		}
		out = append(out, o)
	}
	return out
}

func (e testEnv) decisions(t *testing.T) []map[string]any {
	t.Helper()
	return readJSONL(t, e.ledgerDir, "decisions-*.jsonl")
}

func readJSONL(t *testing.T, dir, glob string) []map[string]any {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(dir, glob))
	var out []map[string]any
	for _, m := range matches {
		f, err := os.Open(m) //nolint:gosec // test-owned tempdir
		if err != nil {
			t.Fatalf("open %s: %v", m, err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var rec map[string]any
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				t.Fatalf("decode line: %v", err)
			}
			out = append(out, rec)
		}
		_ = f.Close()
	}
	return out
}

// Observe mode: Decide rails to none, so no order is written. A decided line is
// still recorded. This is the default-inert posture at the responder.
func TestObserveModeWritesNoOrder(t *testing.T) {
	e := newResponder(t, killPolicy(t, response.ModeObserve), false)
	if err := e.r.Respond(revshellAlert()); err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if o := e.orders(t); len(o) != 0 {
		t.Fatalf("observe mode wrote %d order(s), want 0", len(o))
	}
	if d := e.decisions(t); len(d) != 1 || d[0]["phase"] != "decided" {
		t.Fatalf("expected exactly one decided line, got %v", d)
	}
}

// Enforce mode but NOT armed (response.enforce off): the not-armed rail fires,
// so no order is written even though the policy is enforce. This is the
// real-host posture across the split.
func TestEnforceNotArmedWritesNoOrder(t *testing.T) {
	e := newResponder(t, killPolicy(t, response.ModeEnforce), false)
	if err := e.r.Respond(revshellAlert()); err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if o := e.orders(t); len(o) != 0 {
		t.Fatalf("not-armed wrote %d order(s), want 0", len(o))
	}
	d := e.decisions(t)
	if len(d) != 1 {
		t.Fatalf("expected one decided line, got %d", len(d))
	}
	dec, _ := d[0]["decision"].(map[string]any)
	if dec == nil || dec["rail"] != "not-armed" {
		t.Fatalf("expected rail not-armed on the decided line, got %v", d[0]["decision"])
	}
}

// Enforce mode AND armed: a decided action writes EXACTLY ONE order, whose id
// matches the decided line, via tmp+rename (the tmp dir is left empty). The
// responder itself never acts.
func TestEnforceArmedWritesExactlyOneOrder(t *testing.T) {
	e := newResponder(t, killPolicy(t, response.ModeEnforce), true)
	if err := e.r.Respond(revshellAlert()); err != nil {
		t.Fatalf("Respond: %v", err)
	}
	orders := e.orders(t)
	if len(orders) != 1 {
		t.Fatalf("expected exactly one order, got %d", len(orders))
	}
	o := orders[0]
	if o.Version != response.OrderVersion {
		t.Errorf("order version = %d, want %d", o.Version, response.OrderVersion)
	}
	if o.Decision.Action != response.ActionKill {
		t.Errorf("order action = %q, want kill", o.Decision.Action)
	}
	if o.Decision.Target.Process == nil || o.Decision.Target.Process.PID != 4242 {
		t.Errorf("order target = %+v, want pid 4242", o.Decision.Target)
	}
	// The order id is the decided ledger line's id.
	d := e.decisions(t)
	if len(d) != 1 {
		t.Fatalf("expected one decided line, got %d", len(d))
	}
	if o.ID != d[0]["id"] {
		t.Errorf("order id %q != decided line id %v", o.ID, d[0]["id"])
	}
	// tmp+rename: no half order left behind in the tmp dir.
	if ents, _ := os.ReadDir(e.tmpDir); len(ents) != 0 {
		t.Errorf("spool tmp dir not empty: %d entries", len(ents))
	}
}

// A ledger-write failure writes NO order: the decided line is the request, so a
// decision that could not be recorded must not be requested. We force the
// ledger open to fail by occupying the day-file path with a directory (EISDIR
// for any uid, so this holds as root in CI too).
func TestLedgerFailureWritesNoOrder(t *testing.T) {
	e := newResponder(t, killPolicy(t, response.ModeEnforce), true)
	a := revshellAlert()
	day := a.Time.UTC().Format("2006-01-02")
	clash := filepath.Join(e.ledgerDir, "decisions-"+day+".jsonl")
	if err := os.Mkdir(clash, 0o700); err != nil {
		t.Fatalf("occupy ledger path: %v", err)
	}
	if err := e.r.Respond(a); err == nil {
		t.Fatalf("expected Respond to return the ledger write error")
	}
	if o := e.orders(t); len(o) != 0 {
		t.Fatalf("a ledger failure wrote %d order(s), want 0", len(o))
	}
}

// The kill-switch file rails the decision to none, so no order is written even
// in enforce mode with an armed responder.
func TestKillSwitchWritesNoOrder(t *testing.T) {
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
	e := newResponder(t, p, true)
	if err := e.r.Respond(revshellAlert()); err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if o := e.orders(t); len(o) != 0 {
		t.Fatalf("kill-switch wrote %d order(s), want 0", len(o))
	}
}

// Dedupe: the same target decided twice in one run writes one order; the second
// is railed as a duplicate.
func TestDuplicateTargetWritesOneOrder(t *testing.T) {
	e := newResponder(t, killPolicy(t, response.ModeEnforce), true)
	a := revshellAlert()
	if err := e.r.Respond(a); err != nil {
		t.Fatal(err)
	}
	if err := e.r.Respond(a); err != nil {
		t.Fatal(err)
	}
	if o := e.orders(t); len(o) != 1 {
		t.Fatalf("expected the duplicate to be railed, got %d order(s)", len(o))
	}
}
