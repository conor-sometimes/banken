package sigma

import (
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

// compileOK compiles rule YAML and fails the test if it does not.
func compileOK(t testing.TB, yml string) *Rule {
	t.Helper()
	r, err := Compile([]byte(yml))
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v\n--- rule ---\n%s", err, yml)
	}
	return r
}

func TestMatchModifiers(t *testing.T) {
	cases := []struct {
		name string
		rule string
		ev   event.Event
		want bool
	}{
		{
			name: "endswith list OR, one matches",
			rule: `detection:
  sel:
    Image|endswith:
      - /curl
      - /wget
  condition: sel`,
			ev:   event.Event{Image: "/usr/bin/wget"},
			want: true,
		},
		{
			name: "endswith list, none match",
			rule: `detection:
  sel:
    Image|endswith: [/curl, /wget]
  condition: sel`,
			ev:   event.Event{Image: "/usr/bin/cat"},
			want: false,
		},
		{
			name: "contains, case-insensitive",
			rule: `detection:
  sel:
    CommandLine|contains: /ETC/shadow
  condition: sel`,
			ev:   event.Event{CommandLine: "cat /etc/shadow"},
			want: true,
		},
		{
			name: "startswith",
			rule: `detection:
  sel:
    CommandLine|startswith: sudo
  condition: sel`,
			ev:   event.Event{CommandLine: "sudo -n true"},
			want: true,
		},
		{
			name: "equals exact",
			rule: `detection:
  sel:
    User: root
  condition: sel`,
			ev:   event.Event{User: "root"},
			want: true,
		},
		{
			name: "equals not substring",
			rule: `detection:
  sel:
    User: root
  condition: sel`,
			ev:   event.Event{User: "rootkit"},
			want: false,
		},
		{
			name: "regexp",
			rule: `detection:
  sel:
    CommandLine|re: 'https?://(\d{1,3}\.){3}\d{1,3}'
  condition: sel`,
			ev:   event.Event{CommandLine: "curl http://192.0.2.1/x"},
			want: true,
		},
		{
			name: "contains all, both present",
			rule: `detection:
  sel:
    CommandLine|contains|all:
      - socket.socket(
      - .connect(
  condition: sel`,
			ev:   event.Event{CommandLine: `python -c s=socket.socket();s.connect(("h",1))`},
			want: true,
		},
		{
			name: "contains all, one missing",
			rule: `detection:
  sel:
    CommandLine|contains|all: [socket.socket(, .connect(]
  condition: sel`,
			ev:   event.Event{CommandLine: "python -c s=socket.socket()"},
			want: false,
		},
		{
			name: "absent field never matches contains",
			rule: `detection:
  sel:
    TargetFilename|contains: shadow
  condition: sel`,
			ev:   event.Event{CommandLine: "cat shadow"},
			want: false,
		},
		{
			name: "AND across fields in one selection",
			rule: `detection:
  sel:
    Image|endswith: /sudo
    CommandLine|contains: " -n "
  condition: sel`,
			ev:   event.Event{Image: "/usr/bin/sudo", CommandLine: "sudo -n true"},
			want: true,
		},
		{
			name: "AND across fields, second fails",
			rule: `detection:
  sel:
    Image|endswith: /sudo
    CommandLine|contains: rm
  condition: sel`,
			ev:   event.Event{Image: "/usr/bin/sudo", CommandLine: "sudo -n true"},
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

func TestMatchConditions(t *testing.T) {
	base := `detection:
  a:
    Image|endswith: /a
  b:
    Image|endswith: /b
  c:
    Image|endswith: /c
  condition: %s`
	cases := []struct {
		cond  string
		image string
		want  bool
	}{
		{"a and b", "/a", false},
		{"a or b", "/a", true},
		{"a and not b", "/a", true},
		{"not a", "/x", true},
		{"(a or b) and c", "/a", false},
		{"(a or b) and not c", "/a", true},
		{"1 of them", "/b", true},
		{"all of them", "/a", false},
		{"1 of them", "/x", false},
	}
	for _, c := range cases {
		t.Run(c.cond+"_"+c.image, func(t *testing.T) {
			r := compileOK(t, strings.Replace(base, "%s", c.cond, 1))
			if got := r.Match(event.Event{Image: c.image}); got != c.want {
				t.Errorf("cond %q on image %q = %v, want %v", c.cond, c.image, got, c.want)
			}
		})
	}
}

func TestMatchListSelectionIsOR(t *testing.T) {
	// A YAML list of mappings under one selection name is OR of the maps.
	r := compileOK(t, `detection:
  sel:
    - Image|endswith: /a
    - CommandLine|contains: zzz
  condition: sel`)
	if !r.Match(event.Event{Image: "/bin/a"}) {
		t.Error("first alternative should match")
	}
	if !r.Match(event.Event{CommandLine: "has zzz here"}) {
		t.Error("second alternative should match")
	}
	if r.Match(event.Event{Image: "/bin/b", CommandLine: "nope"}) {
		t.Error("neither alternative should match")
	}
}

func TestCompileErrors(t *testing.T) {
	cases := []struct {
		name string
		rule string
		want string
	}{
		{"no detection", "title: x\n", "no detection"},
		{"no condition", "detection:\n  sel:\n    Image: x\n", "no condition"},
		{"unknown selection in condition", "detection:\n  sel:\n    Image: x\n  condition: nope\n", "unknown selection"},
		{"unsupported modifier", "detection:\n  sel:\n    Image|base64offset: x\n  condition: sel\n", "unsupported modifier"},
		{"bad regexp", "detection:\n  sel:\n    Image|re: '('\n  condition: sel\n", "invalid regexp"},
		{"empty condition", "detection:\n  sel:\n    Image: x\n  condition: ''\n", "non-empty string"},
		{"dangling operator", "detection:\n  sel:\n    Image: x\n  condition: sel and\n", "unexpected end"},
		{"missing paren", "detection:\n  sel:\n    Image: x\n  condition: '(sel'\n", "closing paren"},
		{"invalid yaml", "detection: [this is: not: valid", "invalid YAML"},
		{"quantifier matches nothing", "detection:\n  sel:\n    Image: x\n  condition: 1 of zzz*\n", "matches no selection"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Compile([]byte(c.rule))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), c.want)
			}
		})
	}
}

func TestRepoRulesAllCompile(t *testing.T) {
	rules, problems := LoadTree("../../rules")
	for _, p := range problems {
		t.Errorf("rule failed to load: %v", p)
	}
	if len(rules) == 0 {
		t.Fatal("no rules loaded from ../../rules")
	}
	// Spot-check a couple of names exist (the migrated + new rules).
	byName := map[string]bool{}
	for _, r := range rules {
		byName[r.Name] = true
		if r.Title == "" {
			t.Errorf("rule %q has no title", r.Name)
		}
	}
	for _, want := range []string{
		"credential_file_read", "download_ip_to_tmp", "reverse_shell",
		"pipe_to_shell", "persistence", "privilege_escalation_attempt", "tamper_banken",
	} {
		if !byName[want] {
			t.Errorf("expected rule %q to load", want)
		}
	}
}
