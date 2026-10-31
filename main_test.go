package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const smokeRule = `title: Credential read
id: smoke
level: high
detection:
  reader:
    Image|endswith: [/cat, /base64]
  secret:
    CommandLine|contains: [id_rsa, /etc/shadow]
  condition: reader and secret
`

// smokeLaurelNow builds one Laurel line that should fire smokeRule and one
// benign line that should not, timestamped now so the per-day alert file is
// dated today and not pruned by the 30-day retention default.
func smokeLaurelNow() string {
	ts := time.Now().Unix()
	return fmt.Sprintf(
		`{"ID":"%d.000:1","SYSCALL":{"exe":"/usr/bin/cat","uid":"0"},"EXECVE":{"argc":"2","ARGV":["cat","/root/.ssh/id_rsa"]}}
{"ID":"%d.000:2","SYSCALL":{"exe":"/usr/bin/cat","uid":"0"},"EXECVE":{"argc":"2","ARGV":["cat","/etc/hostname"]}}
`, ts, ts+1)
}

func TestRunOneShotWritesAlertAndAdvancesCursor(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules", "credential-access")
	if err := os.MkdirAll(rulesDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "smoke.yml"), []byte(smokeRule), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(smokeLaurelNow()), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "cursor.json")
	jsonlDir := filepath.Join(dir, "alerts")

	args := []string{
		"-rules", filepath.Join(dir, "rules"),
		"-state", statePath,
		"-jsonl-dir", jsonlDir,
		"-source", "laurel:" + logPath,
	}
	var stdout, stderr bytes.Buffer
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v\nstderr:\n%s", err, stderr.String())
	}

	// Exactly one alert file line (the id_rsa read), benign line fired nothing.
	entries, err := os.ReadDir(jsonlDir)
	if err != nil {
		t.Fatalf("read alert dir: %v", err)
	}
	var alertLines int
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(jsonlDir, e.Name()))
		for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if strings.TrimSpace(l) != "" {
				alertLines++
			}
		}
	}
	if alertLines != 1 {
		t.Errorf("expected 1 alert line, got %d", alertLines)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Errorf("cursor not saved: %v", err)
	}

	// A second run reads nothing new (cursor advanced) -> no new alerts.
	var out2, err2 bytes.Buffer
	if err := run(args, &out2, &err2); err != nil {
		t.Fatalf("second run: %v", err)
	}
	alertLines = 0
	entries, _ = os.ReadDir(jsonlDir)
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(jsonlDir, e.Name()))
		for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if strings.TrimSpace(l) != "" {
				alertLines++
			}
		}
	}
	if alertLines != 1 {
		t.Errorf("after second run expected still 1 alert line (nothing new), got %d", alertLines)
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-version"}, &stdout, &stderr); err != nil {
		t.Fatalf("run -version: %v", err)
	}
	if !strings.Contains(stdout.String(), "banken") {
		t.Errorf("version output = %q", stdout.String())
	}
}

func TestRunNoRulesIsError(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.MkdirAll(empty, 0o750); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := run([]string{"-rules", empty, "-state", filepath.Join(dir, "c.json")}, &stdout, &stderr)
	if err == nil {
		t.Error("expected an error when no rules load")
	}
}
