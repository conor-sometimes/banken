package parser

import (
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
)

func TestLaurelParse(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []event.Event
	}{
		{
			// An exec's PATH entries are the program being loaded: no target.
			name:  "exec with ARGV, CWD, UID translation, PPID; PATH is the program, not a target",
			input: `{"ID":"1626611363.720:348","SYSCALL":{"exe":"/usr/bin/cat","uid":"0","ppid":"1200"},"EXECVE":{"argc":"2","ARGV":["cat","/etc/shadow"]},"CWD":{"cwd":"/root"},"PATH":[{"name":"/usr/bin/cat","nametype":"NORMAL"}],"PPID":{"exe":"/usr/bin/bash"},"UID":{"0":"root"}}`,
			want: []event.Event{{
				Source:           "laurel",
				Time:             time.Unix(1626611363, 720*int64(time.Millisecond)).UTC(),
				Image:            "/usr/bin/cat",
				CommandLine:      "cat /etc/shadow",
				ParentImage:      "/usr/bin/bash",
				User:             "root",
				CurrentDirectory: "/root",
				PPID:             1200,
			}},
		},
		{
			// The watched read itself (no EXECVE), by NixOS's multicall coreutils.
			name:  "watched read: target from PATH, multicall Image resolved by argv[0]",
			input: `{"ID":"1626611363.721:349","SYSCALL":{"exe":"/nix/store/x-coreutils-9.11/bin/coreutils","uid":"0","pid":"1234"},"PATH":[{"name":"/etc/shadow","nametype":"NORMAL"}],"PROCTITLE":{"ARGV_STR":"cat /etc/shadow"},"UID":{"0":"root"}}`,
			want: []event.Event{{
				Source:         "laurel",
				Time:           time.Unix(1626611363, 721*int64(time.Millisecond)).UTC(),
				Image:          "/nix/store/x-coreutils-9.11/bin/cat",
				CommandLine:    "cat /etc/shadow",
				TargetFilename: "/etc/shadow",
				User:           "root",
				PID:            1234,
			}},
		},
		{
			name:  "uid with no translation falls back to numeric",
			input: `{"ID":"10.000:1","SYSCALL":{"exe":"/bin/id","uid":"1000"}}`,
			want: []event.Event{{
				Source: "laurel", Time: time.Unix(10, 0).UTC(),
				Image: "/bin/id", User: "1000",
			}},
		},
		{
			name:  "proctitle ARGV_STR fallback when no EXECVE",
			input: `{"ID":"11.000:2","SYSCALL":{"exe":"/usr/bin/curl","uid":"1000"},"PROCTITLE":{"ARGV_STR":"curl -s https://x"}}`,
			want: []event.Event{{
				Source: "laurel", Time: time.Unix(11, 0).UTC(),
				Image: "/usr/bin/curl", CommandLine: "curl -s https://x", User: "1000",
			}},
		},
		{
			name:  "hex proctitle fallback is decoded",
			input: `{"ID":"12.000:3","SYSCALL":{"exe":"/bin/sh"},"PROCTITLE":{"proctitle":"7368002D63"}}`,
			// "sh\0-c" -> "sh -c"
			want: []event.Event{{
				Source: "laurel", Time: time.Unix(12, 0).UTC(),
				Image: "/bin/sh", CommandLine: "sh -c",
			}},
		},
		{
			name:  "PATH as a single object (not an array) is tolerated",
			input: `{"ID":"13.000:4","SYSCALL":{"exe":"/bin/rm"},"PATH":{"name":"/x","nametype":"DELETE"}}`,
			want: []event.Event{{
				Source: "laurel", Time: time.Unix(13, 0).UTC(),
				Image: "/bin/rm", TargetFilename: "/x",
			}},
		},
		{
			name:  "numeric uid rendered from a JSON number",
			input: `{"ID":"14.000:5","SYSCALL":{"exe":"/bin/id","uid":1000}}`,
			want: []event.Event{{
				Source: "laurel", Time: time.Unix(14, 0).UTC(),
				Image: "/bin/id", User: "1000",
			}},
		},
		{
			name: "blank lines and invalid-JSON lines are skipped",
			input: `
not json at all
{"ID":"15.000:6","SYSCALL":{"exe":"/bin/ok"}}
{ broken
`,
			want: []event.Event{{
				Source: "laurel", Time: time.Unix(15, 0).UTC(), Image: "/bin/ok",
			}},
		},
		{
			name:  "wrong types everywhere do not panic and yield a bare event",
			input: `{"ID":123,"SYSCALL":"not an object","EXECVE":{"ARGV":"not an array"},"PATH":"nope","UID":[1,2,3]}`,
			// ID 123 is a bare number: rendered "123", parsed as epoch seconds.
			want: []event.Event{{Source: "laurel", Time: time.Unix(123, 0).UTC()}},
		},
		{
			name:  "empty object is a bare event",
			input: `{}`,
			want:  []event.Event{{Source: "laurel"}},
		},
		{
			name:  "top-level JSON array (not an object) is skipped",
			input: `[1,2,3]`,
			want:  nil,
		},
	}

	p := Laurel{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseString(t, p, c.input)
			assertEvents(t, got, c.want)
		})
	}
}
