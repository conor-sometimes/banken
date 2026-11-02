package sigma

import (
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

// TestNullAndExists checks banken's field-presence semantics against the
// pySigma truth table: `field: null` and `field|exists: false` are true when
// the field is ABSENT; `field|exists: true` is true when it is PRESENT.
func TestNullAndExists(t *testing.T) {
	cases := []struct {
		name string
		rule string
		ev   event.Event
		want bool
	}{
		{
			name: "null matches when field absent",
			rule: "detection:\n  s:\n    TargetFilename: null\n  condition: s",
			ev:   event.Event{Image: "/bin/sh"}, // no TargetFilename
			want: true,
		},
		{
			name: "null does not match when field present",
			rule: "detection:\n  s:\n    TargetFilename: null\n  condition: s",
			ev:   event.Event{TargetFilename: "/etc/passwd"},
			want: false,
		},
		{
			name: "exists:false matches when absent",
			rule: "detection:\n  s:\n    ParentImage|exists: false\n  condition: s",
			ev:   event.Event{Image: "/bin/sh"},
			want: true,
		},
		{
			name: "exists:false does not match when present",
			rule: "detection:\n  s:\n    ParentImage|exists: false\n  condition: s",
			ev:   event.Event{ParentImage: "/bin/bash"},
			want: false,
		},
		{
			name: "exists:true matches when present",
			rule: "detection:\n  s:\n    ParentImage|exists: true\n  condition: s",
			ev:   event.Event{ParentImage: "/bin/bash"},
			want: true,
		},
		{
			name: "exists:true does not match when absent",
			rule: "detection:\n  s:\n    ParentImage|exists: true\n  condition: s",
			ev:   event.Event{Image: "/bin/sh"},
			want: false,
		},
		{
			name: "null on a Raw field, absent",
			rule: "detection:\n  s:\n    syscall: null\n  condition: s",
			ev:   event.Event{Image: "/bin/sh"},
			want: true,
		},
		{
			name: "null on a Raw field, present",
			rule: "detection:\n  s:\n    syscall: null\n  condition: s",
			ev:   event.Event{Raw: map[string]string{"syscall": "execve"}},
			want: false,
		},
		{
			name: "common combo: field present AND another absent",
			rule: "detection:\n  s:\n    Image|endswith: /sudo\n    TargetFilename: null\n  condition: s",
			ev:   event.Event{Image: "/usr/bin/sudo"},
			want: true,
		},
		{
			name: "combo fails when the null field is present",
			rule: "detection:\n  s:\n    Image|endswith: /sudo\n    TargetFilename: null\n  condition: s",
			ev:   event.Event{Image: "/usr/bin/sudo", TargetFilename: "/x"},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := compileOK(t, c.rule)
			if got := r.Match(c.ev); got != c.want {
				t.Errorf("Match() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestNullExistsViaMatcher confirms the prefilter does not drop a presence-only
// rule: a rule that fires precisely when a field is ABSENT has no literal to
// index on, so it must be evaluated on every event (the `always` set).
func TestNullExistsViaMatcher(t *testing.T) {
	r := compileOK(t, "detection:\n  s:\n    TargetFilename: null\n  condition: s")
	m := NewMatcher([]*Rule{r})
	// An event with no TargetFilename and no other hooks must still be offered
	// to this rule and match.
	if hits := m.Match(event.Event{Image: "/bin/true"}); len(hits) != 1 {
		t.Fatalf("expected the absence rule to fire via the matcher, got %d hits", len(hits))
	}
	if hits := m.Match(event.Event{TargetFilename: "/present"}); len(hits) != 0 {
		t.Fatalf("expected no hit when the field is present, got %d", len(hits))
	}
}

func TestExistsCompileErrors(t *testing.T) {
	for _, rule := range []string{
		// |exists with a non-boolean value
		"detection:\n  s:\n    Image|exists: maybe\n  condition: s",
		// null combined with a comparison modifier is meaningless
		"detection:\n  s:\n    Image|contains: null\n  condition: s",
	} {
		if _, err := Compile([]byte(rule)); err == nil {
			t.Errorf("expected a load error for:\n%s", rule)
		}
	}
}
