package parser

import (
	"strings"
	"testing"
)

func TestGenericParse(t *testing.T) {
	in := `{"image":"/bin/bash","commandLine":"bash -i","user":"root"}
not json, skipped
{"image":"/usr/bin/curl","commandLine":"curl http://x","source":"falco"}
`
	events, err := Generic{}.Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (the non-JSON line skipped)", len(events))
	}
	// Fields unmarshal straight from the camelCase JSON shape.
	if events[0].Image != "/bin/bash" || events[0].CommandLine != "bash -i" || events[0].User != "root" {
		t.Errorf("event 0 wrong: %+v", events[0])
	}
	// Source defaults to "generic" when absent, and is preserved when present.
	if events[0].Source != "generic" {
		t.Errorf("event 0 source = %q, want generic (default)", events[0].Source)
	}
	if events[1].Source != "falco" {
		t.Errorf("event 1 source = %q, want falco (preserved)", events[1].Source)
	}
}

func TestGenericRegistered(t *testing.T) {
	if _, ok := Registry()["generic"]; !ok {
		t.Error(`"generic" not in the parser registry`)
	}
}
