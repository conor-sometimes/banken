package main

import (
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/event"
)

func TestPinDNFRepo(t *testing.T) {
	in := `[baseos]
name=Rocky Linux $releasever - BaseOS
mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo=BaseOS-$releasever
#baseurl=http://dl.rockylinux.org/$contentdir/$releasever/BaseOS/$basearch/os/
[fedora]
metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever
# baseurl=http://download.example/pub/fedora/linux/releases/$releasever/Everything/$basearch/os/`
	want := `[baseos]
name=Rocky Linux $releasever - BaseOS
#mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo=BaseOS-$releasever
baseurl=http://dl.rockylinux.org/$contentdir/$releasever/BaseOS/$basearch/os/
[fedora]
#metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever
baseurl=http://dl.fedoraproject.org/pub/fedora/linux/releases/$releasever/Everything/$basearch/os/`
	if got := pinDNFRepo(in); got != want {
		t.Errorf("pinDNFRepo:\n got: %s\nwant: %s", got, want)
	}
}

func TestContainsRule(t *testing.T) {
	lines := []string{
		"banken: auto-detected source: auditd /var/log/audit/audit.log",
		`critical reverse_shell: Reverse shell spawned (auditd) image="/usr/bin/bash"`,
	}
	if !containsRule(lines, "reverse_shell") {
		t.Error("reverse_shell not found")
	}
	if containsRule(lines, "reverse") || containsRule(lines, "auto-detected") {
		t.Error("matched a prefix or a non-alert line")
	}
}

func TestUnexpectedLogLines(t *testing.T) {
	lines := []string{ // banken's journal at warning and above
		`high pipe_to_shell: Download piped into a shell (auditd) image="/usr/bin/bash"`,
		`critical reverse_shell: Reverse shell spawned (auditd) image="/usr/bin/bash"`,
		"banken: rule error: rules/x.yml: bad condition",
		"<3>high pipe_to_shell: an un-stripped priority prefix",
	}
	got := unexpectedLogLines(lines)
	if len(got) != 2 || got[0] != lines[2] || got[1] != lines[3] {
		t.Errorf("unexpectedLogLines = %q", got)
	}
}

func TestExposure(t *testing.T) {
	out := "  NAME  DESCRIPTION  EXPOSURE\n...\n→ Overall exposure level for banken.service: 2.1 OK :-)\n"
	if s, l, ok := exposure(out); !ok || s != "2.1" || l != "OK" {
		t.Errorf("exposure = %q %q %v", s, l, ok)
	}
	if _, _, ok := exposure("Failed to parse"); ok {
		t.Error("no score must be reported as such")
	}
}

func TestStatusAndOSRelease(t *testing.T) {
	if got := statusField("enabled 1\nfailure 1\npid 612\n", "enabled"); got != "1" {
		t.Errorf("statusField = %q", got)
	}
	if got := osRelease("NAME=\"Rocky Linux\"\nPRETTY_NAME=\"Rocky Linux 9.8 (Blue Onyx)\"\n"); got != "Rocky Linux 9.8 (Blue Onyx)" {
		t.Errorf("osRelease = %q", got)
	}
}

// TestOCSFRule decodes a line produced by banken's real OCSF encoder, so the
// matrix and the encoder cannot drift apart.
func TestOCSFRule(t *testing.T) {
	a := alert.Alert{
		Kind: alert.KindSigma, Rule: "reverse_shell", Title: "Reverse shell spawned", Level: "critical",
		Message: "rule matched", Time: time.Unix(1, 0),
		Event: event.Event{Source: "auditd", Image: "/usr/bin/bash", CommandLine: "bash -i", PID: 7},
	}
	line, err := alert.EncodeOCSF(alert.OCSFOptions{Hostname: "banken-rocky-9"})(a)
	if err != nil {
		t.Fatal(err)
	}
	rule, sev, problem := ocsfRule(string(line), "banken-rocky-9")
	if rule != "reverse_shell" || sev != 5 || problem != "" {
		t.Errorf("ocsfRule = %q %d %q", rule, sev, problem)
	}
	if _, _, problem := ocsfRule(string(line), "another-host"); problem == "" {
		t.Error("a finding from another host must be reported")
	}
	if got := ocsfCommandLine(string(line)); got != "bash -i" {
		t.Errorf("ocsfCommandLine = %q", got)
	}
	if _, _, problem := ocsfRule("not json", ""); problem == "" {
		t.Error("garbage must be reported")
	}
}

func TestFrom(t *testing.T) {
	if got := from([]string{"a", "b"}, 1); len(got) != 1 || got[0] != "b" {
		t.Errorf("from = %q", got)
	}
	if got := from([]string{"a"}, 5); got != nil {
		t.Errorf("a shrunk source must give nothing, got %q", got)
	}
}

func TestTaskNever(t *testing.T) {
	rules := "-a always,exit -F arch=b64 -S execve -k banken-exec\n-a never,task\n# -a task,never\n  -a task,never\n"
	if got := linesMatching(rules, taskNever); len(got) != 2 {
		t.Errorf("linesMatching = %q, want both orders and no comment", got)
	}
}
