package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/conor-sometimes/banken/internal/alert"
)

// Pure helpers for distrocheck: parsing the output of the tools it drives.
// Everything here is unit-tested (parse_test.go); main.go only sequences.

func nonEmpty(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// from returns lines[n:], or nothing if the source shrank (a rotated journal)
// instead of panicking on a stale count.
func from(lines []string, n int) []string {
	if n >= len(lines) {
		return nil
	}
	return lines[n:]
}

func firstLine(s string) string {
	l := nonEmpty(s)
	if len(l) == 0 {
		return ""
	}
	return l[0]
}

func lastLines(s string, n int) string {
	l := nonEmpty(s)
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, " | ")
}

func firstN(l []string, n int) []string {
	if len(l) > n {
		return l[:n]
	}
	return l
}

func linesContaining(s, sub string) []string {
	var out []string
	for _, l := range nonEmpty(s) {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return out
}

// osRelease is /etc/os-release's PRETTY_NAME.
func osRelease(s string) string {
	for _, l := range nonEmpty(s) {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// statusField reads one "name value" line of `auditctl -s`.
func statusField(status, name string) string {
	for _, l := range nonEmpty(status) {
		if f := strings.Fields(l); len(f) == 2 && f[0] == name {
			return f[1]
		}
	}
	return ""
}

// pinDNFRepo points a .repo file at the vendor's own host: mirrorlist= and
// metalink= lines are commented out, the vendor's commented baseurl= is
// restored, and Fedora's download.example placeholder becomes its master site.
func pinDNFRepo(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "mirrorlist=") || strings.HasPrefix(t, "metalink="):
			lines[i] = "#" + l
		case strings.HasPrefix(t, "#") && strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(t, "#")), "baseurl="):
			lines[i] = strings.TrimSpace(strings.TrimPrefix(t, "#"))
		}
		lines[i] = strings.ReplaceAll(lines[i], "download.example/pub/fedora/linux", "dl.fedoraproject.org/pub/fedora/linux")
	}
	return strings.Join(lines, "\n")
}

// taskNever matches an audit rule that turns syscall auditing off for every
// process, in either order auditctl accepts or prints it.
var taskNever = regexp.MustCompile(`^\s*-a\s+(task,never|never,task)(\s|$)`)

func linesMatching(s string, re *regexp.Regexp) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if re.MatchString(l) {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

// containsRule reports whether a journal alert line ("critical reverse_shell:
// Reverse shell spawned ...") for rule is among lines.
func containsRule(lines []string, rule string) bool {
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) >= 2 && alertLevels[f[0]] && strings.TrimSuffix(f[1], ":") == rule {
			return true
		}
	}
	return false
}

// alertLevels are the words a journal alert line starts with.
var alertLevels = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "informational": true}

// alertLine matches a journal alert line ("critical reverse_shell: ...").
var alertLine = regexp.MustCompile(`^(critical|high|medium|low|informational) \S+: `)

// unexpectedLogLines filters banken's journal at warning and above down to
// what is not an alert: its own warnings and errors, which a clean run has
// none of. (Progress and summary lines are logged at info and notice.)
func unexpectedLogLines(lines []string) []string {
	var out []string
	for _, l := range lines {
		if !alertLine.MatchString(l) {
			out = append(out, l)
		}
	}
	return out
}

var exposureLine = regexp.MustCompile(`Overall exposure level for \S+: ([0-9.]+) (\w+)`)

// exposure is the score and level from `systemd-analyze security UNIT`.
func exposure(out string) (score, level string, ok bool) {
	m := exposureLine.FindStringSubmatch(out)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// ocsfRule decodes one jsonl alert line with banken's own OCSF type and
// returns its rule, severity and, if it is not a valid finding for this host,
// what is wrong with it.
func ocsfRule(line, host string) (rule string, severity int, problem string) {
	var f alert.OCSFFinding
	if err := json.Unmarshal([]byte(line), &f); err != nil {
		return "", 0, "not JSON: " + err.Error()
	}
	rule = f.FindingInfo.Analytic.Name
	var problems []string
	if f.ClassUID != 2004 {
		problems = append(problems, fmt.Sprintf("class_uid %d", f.ClassUID))
	}
	if f.Metadata.Version != alert.OCSFVersion {
		problems = append(problems, "version "+f.Metadata.Version)
	}
	if host != "" && (f.Device == nil || f.Device.Hostname != host) {
		problems = append(problems, "device.hostname is not "+host)
	}
	if rule == "" {
		problems = append(problems, "no analytic name")
	}
	return rule, f.SeverityID, strings.Join(problems, ", ")
}

// ocsfCommandLine is the command line in an alert line's evidence, for
// reporting a false positive.
func ocsfCommandLine(line string) string {
	var f alert.OCSFFinding
	if json.Unmarshal([]byte(line), &f) != nil || len(f.Evidences) == 0 || f.Evidences[0].Process == nil {
		return "?"
	}
	return f.Evidences[0].Process.CmdLine
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
