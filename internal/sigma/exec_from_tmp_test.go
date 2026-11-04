package sigma_test

import (
	"os"
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/parser"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// TestExecFromTmpInterpAnchor pins the fix for a regex false positive in
// rules/execution/exec_from_tmp.yml branch (b): the interpreter must be argv[0]
// (anchored at the start, optional path prefix), not merely a substring of the
// command line. Before the anchor, `touch -r /bin/sh /tmp/x/ref` (a timestomp)
// matched the `sh` inside the `/bin/sh` ARGUMENT followed by the `/tmp/...`
// path, firing exec_from_tmp and breaking the distro-matrix stomp family. We
// load the real rule off disk so a future loosening of the regex is caught here
// by the fast engine gate, not only by the slow in-VM matrix.
func TestExecFromTmpInterpAnchor(t *testing.T) {
	data, err := os.ReadFile("../../rules/execution/exec_from_tmp.yml")
	if err != nil {
		t.Fatalf("read rule: %v", err)
	}
	rule, err := sigma.Compile(data)
	if err != nil {
		t.Fatalf("compile rule: %v", err)
	}
	matcher := sigma.NewMatcher([]*sigma.Rule{rule})

	cases := []struct {
		name  string
		audit string
		want  bool // whether exec_from_tmp should fire
	}{
		{
			// stomp's second TTP: touch copying /bin/sh's timestamp onto a file in
			// its own /tmp scratch dir. The interpreter name `sh` appears only inside
			// the `/bin/sh` argument, so it must NOT be read as an exec from /tmp.
			name: "touch -r /bin/sh with a /tmp target does not fire",
			audit: `type=SYSCALL msg=audit(1700000000.5:5): arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=1005 auid=1000 uid=1000 comm="touch" exe="/usr/bin/touch" key="banken-exec"
type=EXECVE msg=audit(1700000000.5:5): argc=4 a0="touch" a1="-r" a2="/bin/sh" a3="/tmp/tmp.Xk3n9a/ref"`,
			want: false,
		},
		{
			// The true positive branch (b) is meant to catch: an interpreter as
			// argv[0] handed a script path under a world-writable dir.
			name: "bash run of a /tmp script fires",
			audit: `type=SYSCALL msg=audit(1700000000.6:6): arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=1006 auid=1000 uid=1000 comm="bash" exe="/usr/bin/bash" key="banken-exec"
type=EXECVE msg=audit(1700000000.6:6): argc=2 a0="bash" a1="/tmp/payload.sh"`,
			want: true,
		},
		{
			// argv[0] by absolute path must still match (the optional path prefix).
			name: "python3 by full path on a /dev/shm script fires",
			audit: `type=SYSCALL msg=audit(1700000000.7:7): arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=1007 auid=1000 uid=1000 comm="python3" exe="/usr/bin/python3" key="banken-exec"
type=EXECVE msg=audit(1700000000.7:7): argc=2 a0="/usr/bin/python3" a1="/dev/shm/calc.py"`,
			want: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			events, err := parser.Auditd{}.Parse(strings.NewReader(c.audit))
			if err != nil {
				t.Fatalf("parse audit log: %v", err)
			}
			if len(events) != 1 {
				t.Fatalf("expected 1 folded event, got %d", len(events))
			}
			fired := len(matcher.Match(events[0])) == 1
			if fired != c.want {
				t.Fatalf("exec_from_tmp fired=%v, want %v\n  event: %+v", fired, c.want, events[0])
			}
		})
	}
}
