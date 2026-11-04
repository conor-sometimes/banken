package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/conor-sometimes/banken/internal/alert"
)

// auditExe returns the basename of the program in an audit line's exe= field.
// auditd writes exe= two ways: quoted (exe="/usr/bin/touch"), and hex-encoded
// (exe=2F7573722F...) whenever the path holds a space, quote or control byte.
// The old diagnostic read only the quoted form, so a hex path showed as gibberish.
// Returns "" when exe is absent or "(null)".
func auditExe(line string) string {
	i := strings.Index(line, " exe=")
	if i < 0 {
		return ""
	}
	v := line[i+len(" exe="):]
	if j := strings.IndexByte(v, ' '); j >= 0 {
		v = v[:j] // the field ends at the next space (a real path with a space is hex-encoded, not here)
	}
	switch {
	case v == "" || v == "(null)":
		return ""
	case strings.HasPrefix(v, `"`):
		v = strings.Trim(v, `"`)
	case isHexStr(v):
		if b, err := hex.DecodeString(v); err == nil {
			v = string(b)
		}
	}
	return v[strings.LastIndexByte(v, '/')+1:]
}

// isHexStr reports whether s is an even-length run of hex digits, auditd's
// encoding for a field value with bytes that cannot appear raw.
func isHexStr(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

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
