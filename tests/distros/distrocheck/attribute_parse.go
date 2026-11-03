package main

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/conor-sometimes/banken/internal/alert"
)

// auditProcTree builds a pid -> ppid map from the audit log's SYSCALL records,
// the process tree identity-based attribution walks. Only SYSCALL records carry
// both pid and ppid; EXECVE/PATH records are keyed by the same event but add no
// parentage. Order does not matter: the map is by pid.
func auditProcTree(auditLog string) map[int]int {
	tree := make(map[int]int)
	for _, line := range nonEmpty(auditLog) {
		if !strings.Contains(line, "type=SYSCALL") {
			continue
		}
		pid := auditInt(line, "pid=")
		if pid <= 0 {
			continue
		}
		tree[pid] = auditInt(line, "ppid=") // ppid may be 0/absent; fine
	}
	return tree
}

// auditInt reads the integer value of a space-delimited audit field, e.g.
// auditInt(line, "pid=") -> 1001. It anchors on a leading space so "pid=" does
// NOT match inside "ppid=" (the field before it on the same line): searching
// " pid=" cannot align with " ppid=" because the character before "pid" there
// is 'p', not a space.
func auditInt(line, key string) int {
	i := strings.Index(line, " "+key)
	if i < 0 {
		if strings.HasPrefix(line, key) {
			i = -1 // key at line start, value begins at len(key)
		} else {
			return 0
		}
	}
	j := i + 1 + len(key) // skip the leading space and the key
	k := j
	for k < len(line) && line[k] >= '0' && line[k] <= '9' {
		k++
	}
	n, _ := strconv.Atoi(line[j:k])
	return n
}

// alertProcess reads the triggering process's pid and its parent's pid from an
// OCSF alert line's evidence, the two handles identity-based attribution needs.
// 0 means "not recorded". Mirrors ocsfRule / ocsfCommandLine, which already read
// this evidence shape.
func alertProcess(line string) (pid, ppid int) {
	var f alert.OCSFFinding
	if json.Unmarshal([]byte(line), &f) != nil || len(f.Evidences) == 0 || f.Evidences[0].Process == nil {
		return 0, 0
	}
	p := f.Evidences[0].Process
	pid = p.PID
	if p.ParentProcess != nil {
		ppid = p.ParentProcess.PID
	}
	return pid, ppid
}
