package sigma

import (
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

// TestRuleValuesAreInertData is the anti-trojan guarantee as an executable
// contract: banken runs as root and may ingest rules from a remote repo, so
// a rule value must be treated as an opaque string to match -- never a shell
// command, a format string, a template, or a path to open. Each case below
// is a value that would be dangerous if any such interpretation existed; the
// only observable effect is a literal substring match against the event,
// and nothing is expanded, executed, or dereferenced.
//
// If someone ever adds templating or command execution to rule handling,
// these assertions break -- which is the point.
func TestRuleValuesAreInertData(t *testing.T) {
	cases := []struct {
		name     string
		value    string // the literal a rule looks for
		cmd      string // the event's CommandLine
		wantFire bool
	}{
		{
			name:     "shell substitution stays literal",
			value:    "$(whoami)",
			cmd:      "echo $(whoami)", // literal text present
			wantFire: true,
		},
		{
			name:     "shell substitution not executed/compared to output",
			value:    "$(whoami)",
			cmd:      "echo root", // the *result* of whoami -- must NOT match
			wantFire: false,
		},
		{
			name:     "backticks stay literal",
			value:    "`id`",
			cmd:      "run `id` now",
			wantFire: true,
		},
		{
			name:     "format verbs stay literal",
			value:    "%s%n%x",
			cmd:      "weird %s%n%x arg",
			wantFire: true,
		},
		{
			name:     "go template stays literal",
			value:    "{{.Image}}",
			cmd:      "cmd {{.Image}} end",
			wantFire: true,
		},
		{
			name:     "path traversal stays literal (no file is opened)",
			value:    "../../../../etc/passwd",
			cmd:      "cat ../../../../etc/passwd",
			wantFire: true,
		},
		{
			name:     "glob stays literal (no expansion)",
			value:    "/tmp/*",
			cmd:      "ls /tmp/*",
			wantFire: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := compileOK(t, "detection:\n  s:\n    CommandLine|contains: "+quoteYAML(tc.value)+"\n  condition: s\n")
			got := r.Match(event.Event{CommandLine: tc.cmd})
			if got != tc.wantFire {
				t.Errorf("value %q vs cmd %q: fired=%v, want %v (value must be matched as inert text only)",
					tc.value, tc.cmd, got, tc.wantFire)
			}
		})
	}
}

// quoteYAML single-quotes a scalar for embedding in rule YAML, doubling any
// embedded single quote, so the test values survive YAML parsing verbatim.
func quoteYAML(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		if r == '\'' {
			b.WriteString("''")
			continue
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}
