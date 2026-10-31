package sigma

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
)

// TestRuleRegexCannotReDoS locks in banken's ReDoS immunity. A rule carries a
// user-supplied regex (CommandLine|re), and a rule can come from anywhere a
// deployment loads rules from, so a hostile rule must not be able to wedge the
// detector on a crafted event -- the classic catastrophic-backtracking attack.
// banken compiles rule regexes with the standard library's regexp, which is
// RE2: it matches in time linear in the input and cannot backtrack-explode. If
// anyone ever swapped in a backtracking engine (regexp2, a cgo PCRE), these
// patterns against these inputs would blow past the deadline and this test
// would fail. Each is a textbook evil regex paired with the input that makes a
// backtracking engine hang.
func TestRuleRegexCannotReDoS(t *testing.T) {
	cases := []struct {
		pattern string
		input   string
	}{
		{`(a+)+$`, strings.Repeat("a", 40000) + "!"},
		{`(a|a)+$`, strings.Repeat("a", 40000) + "!"},
		{`(.*a){25}$`, strings.Repeat("a", 40000) + "!"},
		{`(x+x+)+y`, strings.Repeat("x", 40000)},
		{`a*a*a*a*a*a*a*a*a*b`, strings.Repeat("a", 40000)},
	}
	for i, c := range cases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			// A minimal rule keying on the evil regex.
			y := "title: t\ndetection:\n  s:\n    CommandLine|re: '" + c.pattern + "'\n  condition: s\n"
			r, err := Compile([]byte(y))
			if err != nil {
				t.Fatalf("compile %q: %v", c.pattern, err)
			}
			ev := event.Event{CommandLine: c.input}

			done := make(chan bool, 1)
			go func() { done <- r.Match(ev) }()
			select {
			case <-done: // returned (true or false, both fine) -- the point is it returned
			case <-time.After(2 * time.Second):
				t.Fatalf("regex %q did not return within 2s on a %d-byte input -- not RE2?", c.pattern, len(c.input))
			}
		})
	}
}
