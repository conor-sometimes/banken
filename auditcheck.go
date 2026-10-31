package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Where persistent audit rules live. augenrules compiles rules.d into
// audit.rules, so rules.d is what an operator edits; audit.rules is read only
// on a host without rules.d. Vars so tests can point them at a temp dir.
var (
	auditRulesDir  = "/etc/audit/rules.d"
	auditRulesFile = "/etc/audit/audit.rules"
)

// taskNever matches an audit rule that turns syscall auditing off for every
// process: "-a task,never" (auditctl -l prints it "-a never,task"). Fedora and
// openSUSE ship one in their default rules, and with it loaded the kernel
// emits no exec events at all, so banken runs cleanly and sees nothing.
var taskNever = regexp.MustCompile(`^\s*-a\s+(task,never|never,task)(\s|$)`)

// auditBlindspots names each rule that would leave banken seeing no process
// events, as "file:line: rule".
func auditBlindspots() []string {
	files, _ := filepath.Glob(filepath.Join(auditRulesDir, "*.rules"))
	if len(files) == 0 {
		files = []string{auditRulesFile}
	}
	var found []string
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // the host's own audit rule files
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			if taskNever.MatchString(line) {
				found = append(found, fmt.Sprintf("%s:%d: %s", f, i+1, strings.TrimSpace(line)))
			}
		}
	}
	return found
}
