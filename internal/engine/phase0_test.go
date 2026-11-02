package engine

import (
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// TestPhase0 locks the shared-foundation work: ProcessId/ParentProcessId are
// matchable *through the Matcher* (not just Rule.Match - i.e. the prefilter
// scans them, or the rule would be silently skipped), and a rule's tags ride
// onto the alert for OCSF/response.
func TestPhase0(t *testing.T) {
	r, err := sigma.Compile([]byte("title: t\n" +
		"tags:\n  - attack.execution\n  - attack.t1059.004\n" +
		"detection:\n  s:\n    ParentProcessId: '1200'\n    ProcessId: '1234'\n  condition: s\n"))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	r.Name = "p0"
	eng := New([]*sigma.Rule{r}, nil, nil)

	// matches via the Matcher (prefilter + Rule.Match) on pid/ppid
	hits := eng.Match(event.Event{Image: "/bin/sh", PID: 1234, PPID: 1200})
	if len(hits) != 1 {
		t.Fatalf("expected 1 alert matching on ProcessId/ParentProcessId, got %d", len(hits))
	}
	// the tags rode onto the alert
	if got := hits[0].Tags; len(got) != 2 || got[0] != "attack.execution" || got[1] != "attack.t1059.004" {
		t.Errorf("alert tags = %v, want the rule's attack.* tags", got)
	}
	// a different pid must not match (prefilter stays exact)
	if n := len(eng.Match(event.Event{Image: "/bin/sh", PID: 9999, PPID: 9999})); n != 0 {
		t.Errorf("wrong pid should not match, got %d alerts", n)
	}
}
