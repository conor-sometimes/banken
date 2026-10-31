package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditBlindspots(t *testing.T) {
	dir := t.TempDir()
	oldDir, oldFile := auditRulesDir, auditRulesFile
	auditRulesDir, auditRulesFile = filepath.Join(dir, "rules.d"), filepath.Join(dir, "audit.rules")
	t.Cleanup(func() { auditRulesDir, auditRulesFile = oldDir, oldFile })

	if got := auditBlindspots(); len(got) != 0 {
		t.Errorf("no rule files: got %q", got)
	}
	// no rules.d: the compiled file is read
	if err := os.WriteFile(auditRulesFile, []byte("-D\n-a never,task\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := auditBlindspots(); len(got) != 1 || got[0] != auditRulesFile+":2: -a never,task" {
		t.Errorf("compiled file: got %q", got)
	}
	// rules.d present: it is what the operator edits, so it alone is reported
	if err := os.MkdirAll(auditRulesDir, 0o750); err != nil {
		t.Fatal(err)
	}
	stock := "## Fedora default\n-D\n-a task,never\n"
	banken := "-a always,exit -F arch=b64 -S execve -k banken-exec\n# -a task,never (commented out)\n"
	if err := os.WriteFile(filepath.Join(auditRulesDir, "audit.rules"), []byte(stock), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(auditRulesDir, "banken.rules"), []byte(banken), 0o600); err != nil {
		t.Fatal(err)
	}
	got := auditBlindspots()
	want := filepath.Join(auditRulesDir, "audit.rules") + ":3: -a task,never"
	if len(got) != 1 || got[0] != want {
		t.Errorf("rules.d: got %q, want [%q]", got, want)
	}
}
