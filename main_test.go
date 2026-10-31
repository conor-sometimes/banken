package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/engine"
	"github.com/conor-sometimes/banken/internal/parser"
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
	// The id_rsa read fires at least one rule (the on-disk smoke rule, plus
	// any embedded baseline rule it also trips); the benign line fires none.
	// The exact count is not the point -- that a rerun adds nothing is.
	if alertLines < 1 {
		t.Errorf("expected at least one alert line, got %d", alertLines)
	}
	firstRunAlerts := alertLines
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
	if alertLines != firstRunAlerts {
		t.Errorf("second run should add no new alerts (cursor advanced): was %d, now %d", firstRunAlerts, alertLines)
	}
}

// TestRunJSONLFormatOCSF is the OCSF path end to end: flags -> buildSinks ->
// the jsonl sink's encoder -> a file a SIEM shipper would tail. Every line
// must be one Detection Finding at the pinned version.
func TestRunJSONLFormatOCSF(t *testing.T) {
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
	jsonlDir := filepath.Join(dir, "alerts")
	args := []string{
		"-rules", filepath.Join(dir, "rules"),
		"-state", filepath.Join(dir, "cursor.json"),
		"-jsonl-dir", jsonlDir,
		"-jsonl-format", "ocsf",
		"-source", "laurel:" + logPath,
	}
	var stdout, stderr bytes.Buffer
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v\nstderr:\n%s", err, stderr.String())
	}
	entries, err := os.ReadDir(jsonlDir)
	if err != nil {
		t.Fatalf("read alert dir: %v", err)
	}
	var findings int
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(jsonlDir, e.Name()))
		for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var f alert.OCSFFinding
			if err := json.Unmarshal([]byte(l), &f); err != nil {
				t.Fatalf("line is not JSON: %v\n%s", err, l)
			}
			if f.ClassUID != 2004 || f.Metadata.Version != alert.OCSFVersion {
				t.Errorf("line is not an OCSF %s Detection Finding: class_uid=%d version=%q", alert.OCSFVersion, f.ClassUID, f.Metadata.Version)
			}
			findings++
		}
	}
	if findings < 1 {
		t.Errorf("expected at least one OCSF finding, got %d", findings)
	}
}

// TestRunJSONLFormatUnknownIsAnError locks the no-silent-fallback contract:
// an operator who typos "ocsf" must hear about it at startup, not discover
// banken JSON in their SIEM.
func TestRunJSONLFormatUnknownIsAnError(t *testing.T) {
	dir := t.TempDir()
	args := []string{
		"-state", filepath.Join(dir, "cursor.json"),
		"-jsonl-dir", filepath.Join(dir, "alerts"),
		"-jsonl-format", "ocfs",
		"-source", "laurel:" + filepath.Join(dir, "missing.log"),
	}
	var stdout, stderr bytes.Buffer
	err := run(args, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), `"ocfs"`) {
		t.Fatalf("want an error naming the unknown format, got %v", err)
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

// TestRunEmptyDiskRulesUsesEmbeddedBaseline is the run()-level zero-fiddle
// guarantee: pointed at an empty on-disk rules dir and a log source, banken
// still runs (and detects), because the embedded baseline is always loaded.
// This replaces an older test that expected an error when no rules loaded --
// with the embedded baseline, "no rules" no longer happens on a working binary.
func TestRunEmptyDiskRulesUsesEmbeddedBaseline(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.MkdirAll(empty, 0o750); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(smokeLaurelNow()), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"-rules", empty,
		"-state", filepath.Join(dir, "c.json"),
		"-source", "laurel:" + logPath,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run with empty disk rules should succeed on the embedded baseline: %v\n%s", err, stderr.String())
	}
	// The embedded credential rule fires on the id_rsa read.
	if !strings.Contains(stderr.String(), "alert") {
		t.Errorf("expected the embedded baseline to detect something; stderr:\n%s", stderr.String())
	}
}

// TestLoadRulesEmbeddedBaseline proves the zero-fiddle guarantee: with no
// on-disk rule dir at all, the binary still loads its embedded baseline, so
// detection works out of the box.
func TestLoadRulesEmbeddedBaseline(t *testing.T) {
	rules, problems := loadRules(nil)
	for _, p := range problems {
		t.Errorf("unexpected rule problem: %v", p)
	}
	if len(rules) == 0 {
		t.Fatal("no embedded baseline rules loaded")
	}
}

// TestLoadRulesDiskOverridesEmbedded checks an on-disk rule with the same
// name as a baseline rule replaces it (operators extend/override the
// baseline), and a new on-disk rule is added.
func TestLoadRulesDiskOverridesEmbedded(t *testing.T) {
	base, _ := loadRules(nil)
	baseByName := map[string]bool{}
	for _, r := range base {
		baseByName[r.Name] = true
	}
	// Pick an existing baseline rule name to override.
	var victim string
	for _, r := range base {
		victim = r.Name
		break
	}

	dir := t.TempDir()
	// Override the victim with a rule that has a distinctive title, and add a
	// brand-new rule.
	writeRule(t, filepath.Join(dir, victim+".yml"), "title: OVERRIDDEN\ndetection:\n  s:\n    Image: /x\n  condition: s\n")
	writeRule(t, filepath.Join(dir, "brand_new_rule.yml"), "title: New\ndetection:\n  s:\n    Image: /y\n  condition: s\n")

	got, problems := loadRules([]string{dir})
	for _, p := range problems {
		t.Errorf("unexpected rule problem: %v", p)
	}
	byName := map[string]string{}
	for _, r := range got {
		byName[r.Name] = r.Title
	}
	if byName[victim] != "OVERRIDDEN" {
		t.Errorf("on-disk rule did not override baseline %q: title=%q", victim, byName[victim])
	}
	if _, ok := byName["brand_new_rule"]; !ok {
		t.Error("on-disk brand_new_rule not loaded")
	}
	if len(got) != len(base)+1 {
		t.Errorf("expected baseline+1 rules, got %d (baseline %d)", len(got), len(base))
	}
}

func writeRule(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// BenchmarkDetectionLatency measures how long banken takes to detect a threat:
// parse one malicious log line and match it against the full shipped (embedded
// baseline) ruleset, producing the alert. This is the per-threat compute
// latency; end-to-end detection latency in a deployment is this plus at most
// one timer interval (the one-shot model) -- which --watch or a short interval
// shrinks. A clean event (no detection) is benchmarked alongside as the common
// case.
func BenchmarkDetectionLatency(b *testing.B) {
	rules, _ := loadRules(nil)
	eng := engine.New(rules, nil, nil)
	p := parser.Registry()["laurel"]

	threat := []byte(`{"ID":"1.000:1","SYSCALL":{"exe":"/usr/bin/cat","uid":"0"},"EXECVE":{"argc":"2","ARGV":["cat","/etc/shadow"]},"PATH":[{"name":"/etc/shadow"}]}` + "\n")
	clean := []byte(`{"ID":"1.000:2","SYSCALL":{"exe":"/usr/bin/ls","uid":"1000"},"EXECVE":{"argc":"2","ARGV":["ls","-la"]}}` + "\n")

	run := func(b *testing.B, line []byte, wantAlert bool) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			events, _ := p.Parse(bytes.NewReader(line))
			alerts := 0
			for _, ev := range events {
				alerts += len(eng.Match(ev))
			}
			if wantAlert && alerts == 0 {
				b.Fatal("threat not detected")
			}
		}
	}
	b.Run("threat", func(b *testing.B) { run(b, threat, true) })
	b.Run("clean", func(b *testing.B) { run(b, clean, false) })
}
