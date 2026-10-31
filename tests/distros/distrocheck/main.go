// Command distrocheck runs inside one throwaway VM of the live distro matrix
// (tests/distros), as root, started by cloud-init from the seed ISO it sits on.
// It installs banken the way docs/deployment.md tells an operator to, checks
// every objective in tests/distros/README.md, writes its report to a small raw
// disk the host reads back, and powers the VM off.
//
// It must never run anywhere but such a VM: it installs packages, rewrites the
// audit rules and runs the benign malware look-alikes in tests/emulations.
package main

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/conor-sometimes/banken/tests/distros/report"
)

const (
	testUser   = "alice" // the emulations run as an ordinary user
	journalDir = "/var/log/banken"
	configPath = "/etc/banken/banken.yml"
	auditLog   = "/var/log/audit/audit.log"
)

// auditRules are banken's documented rules (docs/deployment.md, Log source)
// plus the watches its credential rule reads.
const auditRules = `-a always,exit -F arch=b64 -S execve,execveat -k banken-exec
-a always,exit -F arch=b32 -S execve -k banken-exec
-w /etc/shadow -p rwa -k banken-watch
-w /etc/gshadow -p rwa -k banken-watch
`

// bankenConfig turns the jsonl sink on, in OCSF, for the detection and output
// objectives; everything before it runs with no config file at all (A2).
const bankenConfig = `alerts:
  journal: {enable: true}
  jsonl: {enable: true, dir: /var/log/banken, retentionDays: 30, format: ocsf}
`

func main() {
	seed := flag.String("seed", "/mnt/seed", "where the seed ISO is mounted")
	flag.Parse()
	var cfg report.Config
	data, err := os.ReadFile(filepath.Join(*seed, "config.json"))
	if err == nil {
		err = json.Unmarshal(data, &cfg)
	}
	if err != nil {
		fatal(fmt.Errorf("read config.json: %w", err))
	}

	c := &checker{cfg: cfg, seed: *seed, rep: report.Report{Distro: cfg.Distro, Info: map[string]string{}}}
	c.run()
	emit(c.rep)
	_ = exec.Command("systemctl", "poweroff").Run()
}

// fatal reports a guest that could not even start checking, so the host sees
// a reason instead of a timeout.
func fatal(err error) {
	emit(report.Report{Checks: []report.Check{{ID: "A1", Detail: "distrocheck: " + err.Error()}}})
	_ = exec.Command("systemctl", "poweroff").Run()
	os.Exit(1)
}

// emit writes the report to the report disk (see report.Disk) and to stdout
// for the guest's own journal. The disk is raw: the JSON, a newline, and the
// host stops reading at the first NUL.
func emit(r report.Report) {
	data, err := json.Marshal(r)
	if err != nil {
		data = []byte(`{"checks":[{"id":"A1","detail":"distrocheck: cannot encode report"}]}`)
	}
	data = append(data, '\n')
	if f, err := os.OpenFile(reportDisk(), os.O_WRONLY, 0); err == nil {
		_, _ = f.Write(data)
		_ = f.Sync()
		_ = f.Close()
	}
	_, _ = os.Stdout.Write(data)
}

// reportDisk finds the report disk by its virtio serial in sysfs, which needs
// no udev rule (the /dev/disk/by-id link does, and not every image has it).
func reportDisk() string {
	serials, _ := filepath.Glob("/sys/block/*/serial")
	for _, f := range serials {
		if data, err := os.ReadFile(f); err == nil && strings.TrimSpace(string(data)) == report.Disk { //nolint:gosec // sysfs
			return "/dev/" + filepath.Base(filepath.Dir(f))
		}
	}
	return "/dev/disk/by-id/virtio-" + report.Disk
}

type checker struct {
	cfg  report.Config
	seed string
	rep  report.Report
	// unitFailures counts banken.service runs that did not succeed (A4).
	unitFailures []string
	workDir      string // for shIn
}

// packageDir maps a suite binary's name back to its package directory:
// internal_sigma.test -> internal/sigma; banken.test (the root) -> ".".
func packageDir(bin string) string {
	name := strings.TrimSuffix(bin, ".test")
	if name == "banken" {
		return "."
	}
	return strings.ReplaceAll(name, "_", "/")
}

// untar unpacks a tar archive into dir, refusing any entry that would land
// outside it.
func untar(archive, dir string) error {
	f, err := os.Open(archive) //nolint:gosec // our own seed file
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, h.Name) // #nosec G305 -- checked on the next line
		if !strings.HasPrefix(dst, filepath.Clean(dir)+string(os.PathSeparator)) && dst != filepath.Clean(dir) {
			return fmt.Errorf("tar entry %q escapes %s", h.Name, dir)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil { //nolint:gosec // a source tree, world-readable
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // as above
				return err
			}
			out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, h.FileInfo().Mode().Perm()) //nolint:gosec // as above
			if err != nil {
				return err
			}
			_, err = io.Copy(out, io.LimitReader(tr, h.Size))
			if err := errors.Join(err, out.Close()); err != nil {
				return err
			}
		}
	}
}

func (c *checker) check(id string, pass bool, detail string) {
	if len(detail) > 400 {
		detail = detail[:400] + "..."
	}
	c.rep.Checks = append(c.rep.Checks, report.Check{ID: id, Pass: pass, Detail: detail})
	emit(c.rep) // a partial report after every check: if the guest dies, the host sees how far it got
}

// objectives lists every check ID in run order, so a setup failure can report
// the rest as not reached rather than leave them out.
func (c *checker) objectives() []string {
	ids := []string{"A1", "A2", "A3"}
	for _, f := range c.families() {
		ids = append(ids, "B1/"+f)
	}
	return append(ids, "B2", "C1", "C2", "A4", "D1", "D2", "E1")
}

func (c *checker) families() []string {
	fams := make([]string, 0, len(c.cfg.Expected))
	for f := range c.cfg.Expected {
		fams = append(fams, f)
	}
	sort.Strings(fams)
	return fams
}

func (c *checker) run() {
	c.recordPlatform()
	for _, step := range []func() error{c.installPackages, c.loadAuditRules, c.installBanken} {
		if err := step(); err != nil {
			c.check("A1", false, err.Error())
			for _, id := range c.objectives()[1:] {
				c.check(id, false, "not reached: install (A1) failed")
			}
			return
		}
	}
	c.check("A1", true, "")
	defer c.recordAuditState()
	c.zeroConfig()
	c.timerFires()
	c.detection()
	c.benignDay()
	c.cleanLogs()
	c.sandbox()
	c.mac()
	c.testSuite()
}

// --- commands ---

// sh runs a command with the host's proxy (if any) in its environment and
// returns its combined output. On timeout the command's whole process group
// is killed (an emulation's curl or nc would otherwise outlive its shell),
// and WaitDelay stops the wait for output a straggler still holds open.
func (c *checker) sh(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- running the distro's tools is this program's job, in a throwaway VM
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	cmd.Dir = c.workDir
	cmd.Env = os.Environ()
	if c.cfg.Proxy != "" {
		for _, k := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
			cmd.Env = append(cmd.Env, k+"="+c.cfg.Proxy)
		}
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("%s: timed out after %s", name, timeout)
	}
	return string(out), err
}

// shIn is sh in a working directory.
func (c *checker) shIn(dir string, timeout time.Duration, name string, args ...string) (string, error) {
	c.workDir = dir
	defer func() { c.workDir = "" }()
	return c.sh(timeout, name, args...)
}

// asUser runs a shell command as the test user. runuser, not su or sudo: those
// would (rightly) fire privilege_escalation_attempt.
func (c *checker) asUser(command string) {
	_, _ = c.sh(time.Minute, "runuser", "-u", testUser, "--", "bash", "-c", command)
}

func have(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// scan runs one banken scan through its unit, as the timer would.
func (c *checker) scan() {
	if out, err := c.sh(2*time.Minute, "systemctl", "start", "banken.service"); err != nil {
		tail, _ := c.sh(time.Minute, "journalctl", "-u", "banken.service", "-n", "8", "--no-pager", "-o", "cat")
		c.unitFailures = append(c.unitFailures, strings.TrimSpace(out+" "+tail))
	}
}

// journal is banken's own output in the journal at or above prio, one line each.
func (c *checker) journal(prio string) []string {
	out, _ := c.sh(time.Minute, "journalctl", "_SYSTEMD_UNIT=banken.service", "_COMM=banken",
		"-p", prio, "--no-pager", "-o", "cat")
	return nonEmpty(out)
}

// alertLines is the jsonl sink's output so far.
func alertLines() []string {
	files, _ := filepath.Glob(filepath.Join(journalDir, "alerts-*.jsonl"))
	sort.Strings(files)
	var lines []string
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // our own alert files, inside the test VM
		if err == nil {
			lines = append(lines, nonEmpty(string(data))...)
		}
	}
	return lines
}

// --- install (A1) ---

func (c *checker) recordPlatform() {
	info := c.rep.Info
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		info["os"] = osRelease(string(data))
	}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info["kernel"] = strings.TrimSpace(string(data))
	}
	if out, err := c.sh(time.Minute, "systemctl", "--version"); err == nil {
		info["systemd"] = firstLine(out)
	}
	if data, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		info["lsm"] = strings.TrimSpace(string(data))
	}
	if have("getenforce") {
		out, _ := c.sh(time.Minute, "getenforce")
		info["selinux"] = strings.TrimSpace(out)
	}
	if data, err := os.ReadFile("/proc/cmdline"); err == nil {
		info["cmdline"] = strings.TrimSpace(string(data))
	}
}

// recordAuditState notes what a reader needs when detection comes up empty:
// whether auditd runs, what it last said, how much it has logged, and what
// banken last reported reading.
func (c *checker) recordAuditState() {
	info := c.rep.Info
	out, _ := c.sh(time.Minute, "systemctl", "is-active", "auditd")
	info["auditd"] = strings.TrimSpace(out)
	if fi, err := os.Stat(auditLog); err == nil {
		info["audit_log_bytes"] = strconv.FormatInt(fi.Size(), 10)
	} else {
		info["audit_log_bytes"] = "missing"
	}
	out, _ = c.sh(time.Minute, "journalctl", "-u", "auditd", "-n", "3", "--no-pager", "-o", "cat")
	info["auditd_log"] = lastLines(out, 3)
	if data, err := os.ReadFile(auditLog); err == nil {
		lines := nonEmpty(string(data))
		if len(lines) > 2 {
			lines = lines[len(lines)-2:]
		}
		info["audit_log_tail"] = strings.Join(lines, " | ")
	}
	out, _ = c.sh(time.Minute, "journalctl", "_SYSTEMD_UNIT=banken.service", "_COMM=banken",
		"-p", "info", "--no-pager", "-o", "cat", "-g", "events")
	info["banken_last_read"] = lastLines(out, 1)
}

func (c *checker) installPackages() error {
	if c.cfg.Proxy != "" {
		if err := c.useProxy(); err != nil {
			return fmt.Errorf("configure %s for the proxy: %w", c.cfg.PM, err)
		}
	}
	var missing []string
	for cmd, pkg := range c.cfg.Packages {
		if !have(cmd) {
			missing = append(missing, pkg)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	c.rep.Info["installed"] = strings.Join(missing, " ")
	var out string
	var err error
	switch c.cfg.PM {
	case "dnf":
		out, err = c.sh(15*time.Minute, "dnf", append([]string{"-y", "install"}, missing...)...)
	case "apt":
		if out, err = c.sh(15*time.Minute, "apt-get", "update"); err == nil {
			out, err = c.sh(15*time.Minute, "apt-get", append([]string{"install", "-y"}, missing...)...)
		}
	case "zypper":
		out, err = c.sh(15*time.Minute, "zypper", append([]string{"-n", "--gpg-auto-import-keys", "install"}, missing...)...)
	case "pacman":
		out, err = c.sh(15*time.Minute, "pacman", append([]string{"-Sy", "--noconfirm", "--needed"}, missing...)...)
	default:
		return fmt.Errorf("unknown package manager %q", c.cfg.PM)
	}
	if err != nil {
		return fmt.Errorf("install %s: %w: %s", strings.Join(missing, " "), err, lastLines(out, 3))
	}
	for cmd := range c.cfg.Packages {
		if !have(cmd) {
			return fmt.Errorf("%s still missing after installing %s", cmd, strings.Join(missing, " "))
		}
	}
	return nil
}

// useProxy points the package manager at the host's proxy and, for dnf and
// zypper, pins repos to the vendor's own host: a mirror list hands out
// third-party mirrors a proxy allow-list cannot name in advance.
func (c *checker) useProxy() error {
	p := c.cfg.Proxy
	switch c.cfg.PM {
	case "apt":
		return os.WriteFile("/etc/apt/apt.conf.d/99banken-proxy",
			[]byte(fmt.Sprintf("Acquire::http::Proxy %q;\nAcquire::https::Proxy %q;\n", p, p)), 0o600)
	case "dnf":
		if err := appendFile("/etc/dnf/dnf.conf", "proxy="+p+"\n"); err != nil {
			return err
		}
		return rewriteRepos("/etc/yum.repos.d/*.repo", pinDNFRepo)
	case "zypper":
		conf := fmt.Sprintf("PROXY_ENABLED=\"yes\"\nHTTP_PROXY=%q\nHTTPS_PROXY=%q\n", p, p)
		if err := os.WriteFile("/etc/sysconfig/proxy", []byte(conf), 0o600); err != nil {
			return err
		}
		return rewriteRepos("/etc/zypp/repos.d/*.repo", func(s string) string {
			return strings.ReplaceAll(s, "download.opensuse.org", "downloadcontent.opensuse.org")
		})
	}
	return nil // pacman reads the proxy from the environment sh sets
}

func (c *checker) loadAuditRules() error {
	if err := os.MkdirAll("/etc/audit/rules.d", 0o750); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/audit/rules.d/banken.rules", []byte(auditRules), 0o600); err != nil {
		return err
	}
	// docs/deployment.md: a stock "-a task,never" turns syscall auditing off
	// (Fedora, openSUSE); the operator removes it, and so does this.
	removed, err := dropTaskNever("/etc/audit/rules.d/*.rules")
	if err != nil {
		return err
	}
	if len(removed) > 0 {
		c.rep.Info["audit_task_never_removed"] = strings.Join(removed, " ")
	}
	if _, err := c.sh(2*time.Minute, "systemctl", "enable", "--now", "auditd"); err != nil {
		_, _ = c.sh(2*time.Minute, "service", "auditd", "start")
	}
	if have("augenrules") {
		_, _ = c.sh(2*time.Minute, "augenrules", "--load")
	} else {
		_, _ = c.sh(2*time.Minute, "auditctl", "-R", "/etc/audit/rules.d/banken.rules")
	}
	_, _ = c.sh(time.Minute, "auditctl", "-e", "1")
	rules, rerr := c.sh(time.Minute, "auditctl", "-l")
	status, serr := c.sh(time.Minute, "auditctl", "-s")
	if rerr != nil || serr != nil {
		c.rep.Info["auditctl_error"] = fmt.Sprintf("-l: %v; -s: %v", rerr, serr)
	}
	c.rep.Info["audit_rules"] = strconv.Itoa(len(nonEmpty(rules)))
	c.rep.Info["audit_task_never"] = strconv.FormatBool(len(linesMatching(rules, taskNever)) > 0)
	c.rep.Info["audit_enabled"] = statusField(status, "enabled")
	if !strings.Contains(rules, "banken-exec") {
		c.recordAuditState()
		return fmt.Errorf("banken's audit rules did not load (auditctl -s: %s; auditd: %s; %s)",
			strings.Join(nonEmpty(status), "; "), c.rep.Info["auditd"], c.rep.Info["auditd_log"])
	}
	return nil
}

func (c *checker) installBanken() error {
	if err := copyFile(filepath.Join(c.seed, "banken"), "/usr/bin/banken", 0o755); err != nil {
		return err
	}
	for _, unit := range []string{"banken.service", "banken.timer"} {
		if err := copyFile(filepath.Join(c.seed, unit), "/etc/systemd/system/"+unit, 0o644); err != nil {
			return err
		}
	}
	if out, err := c.sh(time.Minute, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w: %s", err, out)
	}
	if out, err := c.sh(time.Minute, "useradd", "-m", testUser); err != nil && !strings.Contains(out, "exists") {
		return fmt.Errorf("useradd %s: %w: %s", testUser, err, out)
	}
	return nil
}

// --- the objectives ---

// zeroConfig (A2): no config file at all; the unit must run, find the audit
// log by itself and journal a critical alert.
func (c *checker) zeroConfig() {
	c.scan() // drain: setup's own events are not judged
	if len(c.unitFailures) > 0 {
		c.check("A2", false, "banken.service failed with no config: "+c.unitFailures[0])
		return
	}
	before := len(c.journal("err"))
	c.runFamily("revshell")
	c.scan()
	fresh := from(c.journal("err"), before)
	c.check("A2", containsRule(fresh, "reverse_shell"),
		"no config file; want a reverse_shell alert in the journal, got: "+strings.Join(fresh, " | "))
}

// timerFires (A3): with the shipped timer enabled and nobody starting the
// unit, an attack is journalled within one interval (2 min) plus slack.
func (c *checker) timerFires() {
	if out, err := c.sh(time.Minute, "systemctl", "enable", "--now", "banken.timer"); err != nil {
		c.check("A3", false, "enable banken.timer: "+out)
		return
	}
	defer func() { _, _ = c.sh(time.Minute, "systemctl", "disable", "--now", "banken.timer") }()
	before := len(c.journal("err"))
	c.runFamily("xmrig")
	deadline := time.Now().Add(200 * time.Second)
	for time.Now().Before(deadline) {
		if containsRule(from(c.journal("err"), before), "pipe_to_shell") {
			c.check("A3", true, "")
			return
		}
		time.Sleep(5 * time.Second)
	}
	c.check("A3", false, "the timer did not journal pipe_to_shell within 200s of the attack")
}

func (c *checker) runFamily(family string) {
	c.asUser("bash " + filepath.Join(c.seed, "emulations", family+".sh"))
	time.Sleep(time.Second) // let auditd write the family's records
}

// detection (B1, C1, C2): with the jsonl sink on (config at the default path,
// read without -config), each family fires exactly its expected rules, every
// alert line is a valid OCSF finding, and each high/critical one is journalled.
func (c *checker) detection() {
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err == nil {
		err = os.WriteFile(configPath, []byte(bankenConfig), 0o600) // banken reads it as root
		if err != nil {
			c.unitFailures = append(c.unitFailures, "write config: "+err.Error())
		}
	}
	c.scan() // drain the A2/A3 activity
	host, _ := os.Hostname()
	var badOCSF, unjournalled []string
	for _, family := range c.families() {
		before, beforeJ := len(alertLines()), len(c.journal("err"))
		c.runFamily(family)
		c.scan()
		fired := map[string]bool{}
		journalled := from(c.journal("err"), beforeJ)
		for _, line := range from(alertLines(), before) {
			rule, sev, problem := ocsfRule(line, host)
			if problem != "" {
				badOCSF = append(badOCSF, family+": "+problem)
			}
			fired[rule] = true
			if sev >= 4 && !containsRule(journalled, rule) {
				unjournalled = append(unjournalled, family+": "+rule)
			}
		}
		got := keys(fired)
		want := c.cfg.Expected[family]
		c.check("B1/"+family, equal(got, want), fmt.Sprintf("fired %v, expected %v", got, want))
	}
	c.check("C1", len(badOCSF) == 0, strings.Join(badOCSF, "; "))
	c.check("C2", len(unjournalled) == 0, "high/critical alerts missing from the journal: "+strings.Join(unjournalled, ", "))
}

// benignWorkload is an ordinary day on a server: what users and admins do
// that must never raise an alert. sudo is absent on purpose: banken alerts on
// every privilege-escalation attempt by design (docs/writing-rules.md).
var benignWorkload = struct{ user, root []string }{
	user: []string{
		"ls -la ~", "cat /etc/os-release", "ps aux", "df -h", "uname -a", "id", "date",
		"grep root /etc/passwd", "head -n 3 /etc/hosts", "echo hello | base64",
		"tar czf /tmp/benign-home.tgz -C ~ . && rm -f /tmp/benign-home.tgz",
		"python3 -c 'print(sum(range(10)))'", "curl --version", "crontab -l",
	},
	root: []string{
		"systemctl status auditd --no-pager", "journalctl -n 20 --no-pager", "ip addr", "ss -tln",
		"useradd -M benign-tmp && userdel benign-tmp", "logger banken benign-day check",
		"cp /etc/hosts /tmp/hosts.bak && rm /tmp/hosts.bak",
	},
}

// benignDay (B2): a normal day's commands, as a user and as root, fire nothing.
func (c *checker) benignDay() {
	before := len(alertLines())
	for _, cmd := range benignWorkload.user {
		c.asUser(cmd)
	}
	for _, cmd := range benignWorkload.root {
		_, _ = c.sh(time.Minute, "bash", "-c", cmd)
	}
	time.Sleep(time.Second)
	c.scan()
	fresh := from(alertLines(), before)
	fps := make([]string, 0, len(fresh))
	for _, line := range fresh {
		rule, _, _ := ocsfRule(line, "")
		fps = append(fps, rule+" on "+ocsfCommandLine(line))
	}
	c.check("B2", len(fps) == 0, "false positives: "+strings.Join(fps, "; "))
}

// cleanLogs (A4): every run succeeded, and banken's journal at warning and
// above holds nothing but alerts (its own problems are logged at warning or
// err, its progress at info).
func (c *checker) cleanLogs() {
	noise := unexpectedLogLines(c.journal("warning"))
	var problems []string
	if len(c.unitFailures) > 0 {
		problems = append(problems, fmt.Sprintf("%d failed runs: %s", len(c.unitFailures), c.unitFailures[0]))
	}
	if len(noise) > 0 {
		problems = append(problems, "unexpected log lines: "+strings.Join(firstN(noise, 5), " | "))
	}
	c.check("A4", len(problems) == 0, strings.Join(problems, "; "))
}

// sandbox (D1): the unit's hardening takes effect on this distro's systemd,
// by systemd's own measure.
func (c *checker) sandbox() {
	out, _ := c.sh(time.Minute, "systemd-analyze", "security", "banken.service", "--no-pager")
	score, level, ok := exposure(out)
	if !ok {
		c.check("D1", false, "no exposure score from systemd-analyze security: "+lastLines(out, 2))
		return
	}
	c.rep.Info["exposure"] = score + " " + level
	c.check("D1", level == "SAFE" || level == "OK", "exposure "+score+" "+level)
}

// mac (D2): the distro's mandatory access control, as shipped, denies banken
// nothing.
func (c *checker) mac() {
	var denials []string
	if have("ausearch") {
		out, _ := c.sh(time.Minute, "ausearch", "-m", "AVC,USER_AVC", "-ts", "boot", "-i")
		denials = append(denials, linesContaining(out, "banken")...)
	}
	out, _ := c.sh(time.Minute, "journalctl", "-k", "--no-pager", "-g", `apparmor="DENIED"`)
	denials = append(denials, linesContaining(out, "banken")...)
	c.check("D2", len(denials) == 0, fmt.Sprintf("lsm=%s selinux=%s; denials: %s",
		c.rep.Info["lsm"], c.rep.Info["selinux"], strings.Join(firstN(denials, 3), " | ")))
}

// testSuite (E1): banken's own Go test suite -- every package's tests, with
// their fixtures and goldens -- passes on this distro. Each package's test
// binary runs from its package directory, as `go test` runs it.
func (c *checker) testSuite() {
	const srcDir = "/opt/banken-src"
	if err := untar(filepath.Join(c.seed, "src.tar"), srcDir); err != nil {
		c.check("E1", false, "unpack the source: "+err.Error())
		return
	}
	bins, _ := filepath.Glob(filepath.Join(c.seed, "suite", "*.test"))
	if len(bins) == 0 {
		c.check("E1", false, "no test binaries on the seed")
		return
	}
	var failed []string
	for _, bin := range bins {
		pkg := packageDir(filepath.Base(bin))
		local := filepath.Join(srcDir, pkg, filepath.Base(bin))
		if err := copyFile(bin, local, 0o755); err != nil {
			failed = append(failed, pkg+": "+err.Error())
			continue
		}
		cmd := []string{"-test.count=1", "-test.timeout=10m"}
		out, err := c.shIn(filepath.Join(srcDir, pkg), 15*time.Minute, local, cmd...)
		if err != nil {
			failed = append(failed, pkg+": "+lastLines(out, 4))
		}
	}
	c.rep.Info["test_packages"] = strconv.Itoa(len(bins))
	c.check("E1", len(failed) == 0, fmt.Sprintf("%d of %d packages failed: %s",
		len(failed), len(bins), strings.Join(failed, "; ")))
}

// --- files ---

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src) //nolint:gosec // our own seed files
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, mode); err != nil { // #nosec G703 -- dst is always one of this file's constant paths
		return err
	}
	return os.Chmod(dst, mode) // WriteFile keeps an existing file's mode
}

func appendFile(path, text string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // a system config path constant in this file
	if err != nil {
		return err
	}
	_, err = f.WriteString(text)
	return errors.Join(err, f.Close())
}

// dropTaskNever comments out every "-a task,never" rule in the matching
// files and reports where each was.
func dropTaskNever(glob string) ([]string, error) {
	var removed []string
	err := rewriteRepos(glob, func(text string) string {
		lines := strings.Split(text, "\n")
		for i, l := range lines {
			if taskNever.MatchString(l) {
				removed = append(removed, strings.TrimSpace(l))
				lines[i] = "# removed for banken (turns syscall auditing off): " + l
			}
		}
		return strings.Join(lines, "\n")
	})
	return removed, err
}

func rewriteRepos(glob string, edit func(string) string) error {
	files, _ := filepath.Glob(glob)
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(f) //nolint:gosec // the distro's own repo files
		if err != nil {
			return err
		}
		if err := os.WriteFile(f, []byte(edit(string(data))), fi.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}
