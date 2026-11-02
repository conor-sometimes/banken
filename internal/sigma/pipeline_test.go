package sigma

import (
	"reflect"
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

// TestPipelineRouting checks that a rule's logsource is routed to the right
// banken sensor sources through the shipped pipeline, and that an event is
// only matched against rules its source is eligible for.
func TestPipelineRouting(t *testing.T) {
	cases := []struct {
		name        string
		logsource   string
		wantSources []string // nil => unrestricted
	}{
		{
			name:        "linux process_creation routes to every linux sensor",
			logsource:   "logsource:\n  product: linux\n  category: process_creation\n",
			wantSources: []string{"auditd", "laurel", "mimi", "sysmon", "generic"},
		},
		{
			name:        "linux auditd service excludes sysmon",
			logsource:   "logsource:\n  product: linux\n  service: auditd\n",
			wantSources: []string{"auditd", "laurel", "mimi", "generic"},
		},
		{
			name:        "windows routes to sysmon only",
			logsource:   "logsource:\n  product: windows\n  category: process_creation\n",
			wantSources: []string{"sysmon"},
		},
		{
			name:        "macos routes to no live sensor (restricted, empty)",
			logsource:   "logsource:\n  product: macos\n  category: process_creation\n",
			wantSources: []string{},
		},
		{
			name:        "no logsource is unrestricted",
			logsource:   "",
			wantSources: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rule := c.logsource + "detection:\n  s:\n    Image|endswith: /x\n  condition: s"
			r := compileOK(t, rule)
			if !reflect.DeepEqual(r.Sources, c.wantSources) {
				t.Fatalf("Sources = %#v, want %#v", r.Sources, c.wantSources)
			}
		})
	}
}

// TestRoutingGatesMatch is the behavioural half: a windows rule must not fire
// on a linux auditd event, and a linux rule must not fire on (a hypothetical)
// windows-only source, while an empty source matches regardless (preserving the
// source-agnostic `banken check` and the conformance differential).
func TestRoutingGatesMatch(t *testing.T) {
	win := compileOK(t, "logsource:\n  product: windows\n  category: process_creation\n"+
		"detection:\n  s:\n    Image|endswith: evil.exe\n  condition: s")
	linux := compileOK(t, "logsource:\n  product: linux\n  category: process_creation\n"+
		"detection:\n  s:\n    Image|endswith: /evil\n  condition: s")

	// Windows rule: matches a sysmon event, not an auditd event, but matches a
	// source-less event (check/replay).
	if !win.Match(event.Event{Source: "sysmon", Image: "C:/evil.exe"}) {
		t.Error("windows rule should match a sysmon event")
	}
	if win.Match(event.Event{Source: "auditd", Image: "C:/evil.exe"}) {
		t.Error("windows rule must NOT match an auditd event")
	}
	if !win.Match(event.Event{Image: "C:/evil.exe"}) {
		t.Error("windows rule should match a source-less event (check/replay)")
	}

	// Linux rule: matches auditd/laurel/mimi, not a foreign source.
	if !linux.Match(event.Event{Source: "laurel", Image: "/bin/evil"}) {
		t.Error("linux rule should match a laurel event")
	}
	if linux.Match(event.Event{Source: "sysmon-windows-only", Image: "/bin/evil"}) {
		t.Error("linux rule must NOT match a foreign source")
	}
}

// TestPipelineRename exercises the field-alias mechanism with a custom pipeline
// (the shipped table uses identity maps, since banken's event model already
// uses Sigma's field names). A rule written against a source field name is
// rewritten to banken's event field for that logsource.
func TestPipelineRename(t *testing.T) {
	p := &pipeline{Entries: []pipelineEntry{
		{
			Name:    "demo",
			When:    logSourceCond{Product: "linux"},
			Sources: []string{"auditd"},
			Rename:  map[string]string{"Executable": "Image"},
		},
	}}
	rule := "logsource:\n  product: linux\n" +
		"detection:\n  s:\n    Executable|endswith: /sudo\n  condition: s"
	r, err := compile([]byte(rule), p)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// The rule referenced `Executable`; after the rename it must read banken's
	// `Image` field.
	if !r.Match(event.Event{Source: "auditd", Image: "/usr/bin/sudo"}) {
		t.Error("renamed field Executable->Image should match on Image")
	}
}

// TestShippedPipelineParses guards the embedded routing table: a malformed
// pipeline.yml would otherwise panic only at first use.
func TestShippedPipelineParses(t *testing.T) {
	if defaultPipeline == nil || len(defaultPipeline.Entries) == 0 {
		t.Fatal("shipped pipeline failed to parse or is empty")
	}
}
