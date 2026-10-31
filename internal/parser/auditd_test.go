package parser

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
)

// parseString is a convenience wrapper for the table tests.
func parseString(t *testing.T, p Parser, s string) []event.Event {
	t.Helper()
	evs, err := p.Parse(strings.NewReader(s))
	if err != nil {
		t.Fatalf("Parse() I/O error: %v", err)
	}
	return evs
}

func TestAuditdParse(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []event.Event
	}{
		{
			name: "execve with quoted argv, cwd and path",
			input: `type=SYSCALL msg=audit(1626611363.720:348): arch=c000003e syscall=59 success=yes ppid=1200 pid=1234 auid=1000 uid=1000 comm="cat" exe="/usr/bin/cat" key=(null)
type=EXECVE msg=audit(1626611363.720:348): argc=2 a0="cat" a1="/etc/shadow"
type=CWD msg=audit(1626611363.720:348): cwd="/home/u"
type=PATH msg=audit(1626611363.720:348): item=0 name="/etc/shadow" nametype=NORMAL
type=PROCTITLE msg=audit(1626611363.720:348): proctitle=636174002F6574632F736861646F77`,
			want: []event.Event{{
				Source:           "auditd",
				Time:             time.Unix(1626611363, 720*int64(time.Millisecond)).UTC(),
				Image:            "/usr/bin/cat",
				CommandLine:      "cat /etc/shadow",
				User:             "1000",
				CurrentDirectory: "/home/u",
				TargetFilename:   "/etc/shadow",
				PID:              1234,
				PPID:             1200,
			}},
		},
		{
			name: "hex-encoded argv is decoded",
			input: `type=SYSCALL msg=audit(1700000000.100:10): exe="/bin/sh" uid=0
type=EXECVE msg=audit(1700000000.100:10): argc=3 a0="sh" a1="-c" a2=6563686F20686921`,
			// a2 = "echo hi!"
			want: []event.Event{{
				Source:      "auditd",
				Time:        time.Unix(1700000000, 100*int64(time.Millisecond)).UTC(),
				Image:       "/bin/sh",
				CommandLine: "sh -c echo hi!",
				User:        "0",
			}},
		},
		{
			name: "proctitle fallback when no EXECVE",
			input: `type=SYSCALL msg=audit(1700000000.200:11): exe="/usr/bin/curl" uid=1000
type=PROCTITLE msg=audit(1700000000.200:11): proctitle=6375726C002D730068747470733A2F2F78`,
			// proctitle = "curl\0-s\0https://x"
			want: []event.Event{{
				Source:      "auditd",
				Time:        time.Unix(1700000000, 200*int64(time.Millisecond)).UTC(),
				Image:       "/usr/bin/curl",
				CommandLine: "curl -s https://x",
				User:        "1000",
			}},
		},
		{
			name: "quoted value containing spaces stays whole",
			input: `type=SYSCALL msg=audit(1700000000.300:12): exe="/usr/bin/bash" uid=1000
type=EXECVE msg=audit(1700000000.300:12): argc=3 a0="bash" a1="-c" a2="echo a b c"`,
			want: []event.Event{{
				Source:      "auditd",
				Time:        time.Unix(1700000000, 300*int64(time.Millisecond)).UTC(),
				Image:       "/usr/bin/bash",
				CommandLine: "bash -c echo a b c",
				User:        "1000",
			}},
		},
		{
			name: "(null) exe yields empty image, event still useful",
			input: `type=SYSCALL msg=audit(1700000000.400:13): exe=(null) uid=1000
type=EXECVE msg=audit(1700000000.400:13): argc=1 a0="weird"`,
			want: []event.Event{{
				Source:      "auditd",
				Time:        time.Unix(1700000000, 400*int64(time.Millisecond)).UTC(),
				CommandLine: "weird",
				User:        "1000",
			}},
		},
		{
			name:  "auid preferred over uid for User",
			input: `type=SYSCALL msg=audit(1700000000.500:14): exe="/bin/id" auid=1000 uid=0`,
			want: []event.Event{{
				Source: "auditd",
				Time:   time.Unix(1700000000, 500*int64(time.Millisecond)).UTC(),
				Image:  "/bin/id",
				User:   "1000",
			}},
		},
		{
			name: "two interleaved events grouped by id, first-seen order kept",
			input: `type=SYSCALL msg=audit(10.000:1): exe="/bin/a" uid=1
type=SYSCALL msg=audit(20.000:2): exe="/bin/b" uid=2
type=EXECVE msg=audit(10.000:1): argc=1 a0="a"
type=EXECVE msg=audit(20.000:2): argc=1 a0="b"`,
			want: []event.Event{
				{Source: "auditd", Time: time.Unix(10, 0).UTC(), Image: "/bin/a", CommandLine: "a", User: "1"},
				{Source: "auditd", Time: time.Unix(20, 0).UTC(), Image: "/bin/b", CommandLine: "b", User: "2"},
			},
		},
		{
			name: "PATH prefers an acted-on target over the exe entry",
			input: `type=SYSCALL msg=audit(30.000:3): exe="/bin/rm" uid=1
type=EXECVE msg=audit(30.000:3): argc=2 a0="rm" a1="/home/u/secret"
type=PATH msg=audit(30.000:3): item=0 name="/home/u" nametype=PARENT
type=PATH msg=audit(30.000:3): item=1 name="/home/u/secret" nametype=DELETE`,
			want: []event.Event{{
				Source: "auditd", Time: time.Unix(30, 0).UTC(),
				Image: "/bin/rm", CommandLine: "rm /home/u/secret", User: "1",
				TargetFilename: "/home/u/secret",
			}},
		},
		{
			name:  "lone unparseable lines produce no events",
			input: "garbage\nnot an audit line\n\t\n",
			want:  nil,
		},
		{
			name: "truncated/garbage lines are skipped, good ones survive",
			input: `type=SYSCALL msg=audit(40.0
random junk here
type=SYSCALL msg=audit(40.000:4): exe="/bin/ok" uid=1
type=EXECVE msg=audit(40.000:4): argc=1 a0="ok"`,
			want: []event.Event{{
				Source: "auditd", Time: time.Unix(40, 0).UTC(),
				Image: "/bin/ok", CommandLine: "ok", User: "1",
			}},
		},
		{
			name: "log-shipper prefix before type= is tolerated",
			input: `2026-10-31T00:00:00+00:00 host audispd: type=SYSCALL msg=audit(50.000:5): exe="/bin/p" uid=7
2026-10-31T00:00:00+00:00 host audispd: type=EXECVE msg=audit(50.000:5): argc=1 a0="p"`,
			want: []event.Event{{
				Source: "auditd", Time: time.Unix(50, 0).UTC(),
				Image: "/bin/p", CommandLine: "p", User: "7",
			}},
		},
		{
			name: "lone EOE/CONFIG record is not a useful event",
			input: `type=EOE msg=audit(60.000:6):
type=CONFIG_CHANGE msg=audit(61.000:7): op=add`,
			want: nil,
		},
	}

	p := Auditd{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseString(t, p, c.input)
			assertEvents(t, got, c.want)
		})
	}
}

func TestDecodeHexField(t *testing.T) {
	cases := []struct{ in, want string }{
		{"636174", "cat"},
		{"636174002F65", "cat /e"}, // NUL -> space
		{"c000003e", "\xc0  >"},    // valid hex decoded; NUL bytes render as spaces
		{"not-hex", "not-hex"},     // non-hex returns unchanged
		{"abc", "abc"},             // odd length returns unchanged
		{"", ""},                   // empty
		{"2F746D702F78", "/tmp/x"}, // path
	}
	for _, c := range cases {
		if got := decodeHexField(c.in); got != c.want {
			t.Errorf("decodeHexField(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// assertEvents compares two event slices field by field with clear diffs.
func assertEvents(t *testing.T, got, want []event.Event) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d events, want %d\ngot:  %+v\nwant: %+v", len(got), len(want), got, want)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("event %d:\n got:  %+v\n want: %+v", i, got[i], want[i])
		}
	}
}
