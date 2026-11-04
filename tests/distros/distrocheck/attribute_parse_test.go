package main

import "testing"

// TestAuditInt pins the pid/ppid overlap trap: "pid=" occurs inside "ppid=", so
// a naive search misreads the parent as the process. Space-anchoring fixes it.
func TestAuditInt(t *testing.T) {
	line := `type=SYSCALL msg=audit(1700000000.1:9): arch=c000003e syscall=59 success=yes ppid=1000 pid=1001 auid=1000 uid=1000 comm="touch" exe="/usr/bin/touch"`
	if got := auditInt(line, "pid="); got != 1001 {
		t.Errorf(`pid= = %d, want 1001 (must not read the ppid value)`, got)
	}
	if got := auditInt(line, "ppid="); got != 1000 {
		t.Errorf(`ppid= = %d, want 1000`, got)
	}
	if got := auditInt(line, "uid="); got != 1000 {
		t.Errorf(`uid= = %d, want 1000`, got)
	}
	if got := auditInt(line, "notthere="); got != 0 {
		t.Errorf(`missing key = %d, want 0`, got)
	}
}

// TestAuditExe covers both ways auditd writes exe=: quoted, and hex-encoded
// (used when the path has a space/quote/control byte). The hex here is
// /usr/bin/touch. The old extractor only read the quoted form.
func TestAuditExe(t *testing.T) {
	cases := []struct{ name, line, want string }{
		{"quoted path", `type=SYSCALL msg=audit(1:1): pid=2 exe="/usr/bin/touch" key=k`, "touch"},
		{"hex-encoded path", `type=SYSCALL msg=audit(1:1): pid=2 exe=2f7573722f62696e2f746f756368 key=k`, "touch"},
		{"null exe", `type=SYSCALL msg=audit(1:1): pid=2 exe=(null) key=k`, ""},
		{"no exe field", `type=PATH msg=audit(1:1): item=0 name="/tmp/x"`, ""},
		{"root-level name", `type=SYSCALL msg=audit(1:1): pid=2 exe="/kmod" key=k`, "kmod"},
	}
	for _, c := range cases {
		if got := auditExe(c.line); got != c.want {
			t.Errorf("%s: auditExe = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestAuditProcTree builds the pid -> ppid map from a window of audit records.
// Only SYSCALL lines contribute; EXECVE/PATH lines are ignored.
func TestAuditProcTree(t *testing.T) {
	log := `type=SYSCALL msg=audit(1700000000.1:1): syscall=59 ppid=100 pid=101 comm="bash" exe="/usr/bin/bash"
type=EXECVE msg=audit(1700000000.1:1): argc=3 a0="bash" a1="-c" a2="touch ..."
type=SYSCALL msg=audit(1700000000.2:2): syscall=59 ppid=101 pid=102 comm="touch" exe="/usr/bin/touch"
type=PATH msg=audit(1700000000.2:2): item=0 name="/tmp/x" nametype=CREATE
type=SYSCALL msg=audit(1700000000.3:3): syscall=59 ppid=900 pid=901 comm="dash" exe="/usr/bin/dash"
`
	tree := auditProcTree(log)
	want := map[int]int{101: 100, 102: 101, 901: 900}
	if len(tree) != len(want) {
		t.Fatalf("tree = %v, want %v", tree, want)
	}
	for pid, ppid := range want {
		if tree[pid] != ppid {
			t.Errorf("tree[%d] = %d, want %d", pid, tree[pid], ppid)
		}
	}
}

// TestAttributionEndToEnd wires the parsers to the core: given a window's audit
// records and a family launcher pid, the alerts whose evidence process is in the
// launcher subtree are the family's, and a cron-bled alert is not.
func TestAttributionEndToEnd(t *testing.T) {
	log := `type=SYSCALL msg=audit(1:1): syscall=59 ppid=1 pid=100 comm="runuser"
type=SYSCALL msg=audit(1:2): syscall=59 ppid=100 pid=101 comm="bash"
type=SYSCALL msg=audit(1:3): syscall=59 ppid=101 pid=102 comm="touch"
type=SYSCALL msg=audit(1:4): syscall=59 ppid=1 pid=900 comm="cron"
type=SYSCALL msg=audit(1:5): syscall=59 ppid=900 pid=901 comm="dash"
`
	subtree := descendants(auditProcTree(log), 100)

	familyAlert := `{"class_uid":2004,"evidences":[{"process":{"pid":102,"parent_process":{"pid":101}}}]}`
	cronAlert := `{"class_uid":2004,"evidences":[{"process":{"pid":901,"parent_process":{"pid":900}}}]}`

	pid, ppid := alertProcess(familyAlert)
	if !inSubtree(subtree, pid, ppid) {
		t.Errorf("family alert (pid=%d ppid=%d) not attributed to the family", pid, ppid)
	}
	pid, ppid = alertProcess(cronAlert)
	if inSubtree(subtree, pid, ppid) {
		t.Errorf("cron-bled alert (pid=%d ppid=%d) wrongly attributed to the family", pid, ppid)
	}
}

// TestAlertProcessMissing: an alert with no process evidence yields (0,0), which
// inSubtree never matches, so a malformed alert is attributed to no family.
func TestAlertProcessMissing(t *testing.T) {
	if pid, ppid := alertProcess(`{"class_uid":2004}`); pid != 0 || ppid != 0 {
		t.Errorf("no-evidence alert = (%d,%d), want (0,0)", pid, ppid)
	}
	if pid, ppid := alertProcess(`not json`); pid != 0 || ppid != 0 {
		t.Errorf("bad json = (%d,%d), want (0,0)", pid, ppid)
	}
}
