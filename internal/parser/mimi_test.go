package parser

import (
	"bytes"
	"os"
	"testing"
)

// The contract: testdata/mimi_event.golden.jsonl is a byte-for-byte copy of mimi's render_mimi
// output (mimi commits the identical file and asserts its render equals it; `just contract` checks
// the two repos still agree). Parsing it here proves banken ingests exactly what mimi emits, so the
// schema is tested on both sides and the repos cannot drift silently.
func TestMimiParsesTheContractFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/mimi_event.golden.jsonl")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	events, err := Mimi{}.Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	ev := events[0]

	str := []struct{ name, got, want string }{
		{"Source", ev.Source, "mimi"},
		{"Image", ev.Image, "/usr/bin/ping"},
		{"CommandLine", ev.CommandLine, "ping 8.8.8.8"},
		{"User", ev.User, "1000"},
		{"Raw[Ancestry]", ev.Raw["Ancestry"], "ping(213541) < fish(210139) < systemd(1)"},
		{"Raw[ParentName]", ev.Raw["ParentName"], "fish"},
		{"Raw[Gid]", ev.Raw["Gid"], "1000"},
	}
	for _, c := range str {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if ev.PID != 213541 {
		t.Errorf("PID = %d, want 213541", ev.PID)
	}
	if ev.PPID != 210139 {
		t.Errorf("PPID = %d, want 210139", ev.PPID)
	}
	if ev.Time.Year() != 2026 {
		t.Errorf("Time = %v, want year 2026", ev.Time)
	}
}

// An unknown schema version is skipped, not misread (version skew): banken refuses newer bytes it
// cannot be sure it understands rather than parsing them as mimi/1.
func TestMimiSkipsUnknownSchema(t *testing.T) {
	line := `{"schema":"mimi/99","process":{"name":"x","pid":1}}`
	events, err := Mimi{}.Parse(bytes.NewReader([]byte(line)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("got %d events from an unknown schema, want 0 (skipped)", len(events))
	}
}
