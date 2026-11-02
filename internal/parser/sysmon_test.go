package parser

import (
	"strings"
	"testing"
)

// A Sysmon-for-Linux ProcessCreate (EventID 1), as sysmonforlinux logs it: the Windows Sysmon XML
// shape. The < > in the command line are XML-escaped on the wire and decode back.
const sysmonProcessCreate = `<Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/>` +
	`<EventID>1</EventID><Version>5</Version><Level>4</Level></System><EventData>` +
	`<Data Name="RuleName">-</Data>` +
	`<Data Name="UtcTime">2026-11-01 14:33:22.279</Data>` +
	`<Data Name="ProcessId">414626</Data>` +
	`<Data Name="Image">/usr/bin/timeout</Data>` +
	`<Data Name="CommandLine">timeout 1 bash -c exec 3&lt;&gt;/dev/tcp/192.0.2.1/4444</Data>` +
	`<Data Name="CurrentDirectory">/root</Data>` +
	`<Data Name="User">root</Data>` +
	`<Data Name="ParentProcessId">414609</Data>` +
	`<Data Name="ParentImage">/usr/bin/bash</Data>` +
	`<Data Name="ParentCommandLine">bash</Data>` +
	`</EventData></Event>`

func TestSysmonParsesProcessCreate(t *testing.T) {
	// With a syslog prefix in front, as it arrives over syslog -- the parser must strip it.
	line := `<30>1 2026-11-01T14:33:22Z host Linux-Sysmon 414626 - - ` + sysmonProcessCreate
	evs, err := Sysmon{}.Parse(strings.NewReader(line + "\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	e := evs[0]
	checks := map[string]struct{ got, want string }{
		"Source":            {e.Source, "sysmon"},
		"Image":             {e.Image, "/usr/bin/timeout"},
		"CommandLine":       {e.CommandLine, "timeout 1 bash -c exec 3<>/dev/tcp/192.0.2.1/4444"},
		"ParentImage":       {e.ParentImage, "/usr/bin/bash"},
		"CurrentDirectory":  {e.CurrentDirectory, "/root"},
		"User":              {e.User, "root"},
		"EventID":           {e.Raw["EventID"], "1"},
		"ParentCommandLine": {e.Raw["ParentCommandLine"], "bash"},
	}
	for name, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", name, c.got, c.want)
		}
	}
	if e.PID != 414626 || e.PPID != 414609 {
		t.Errorf("pid/ppid = %d/%d, want 414626/414609", e.PID, e.PPID)
	}
	if e.Time.IsZero() || e.Time.Year() != 2026 {
		t.Errorf("UtcTime not parsed: %v", e.Time)
	}
}

func TestSysmonSkipsNonEvents(t *testing.T) {
	in := "a plain syslog line, not sysmon\n{\"json\":true}\n" + sysmonProcessCreate + "\n"
	evs, err := Sysmon{}.Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1 (only the Sysmon XML line)", len(evs))
	}
}
