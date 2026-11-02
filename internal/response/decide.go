package response

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/conor-sometimes/banken/internal/alert"
)

// builtinDenyNames are process basenames banken never acts on: the init
// system, the login path, the audit pipeline, the message bus. The policy
// can add to this (Denylist) but never remove from it. Names drift
// (sshd-session arrived in OpenSSH 9.8), so the executor also re-checks the
// live process by cgroup unit; this is the portable decision-layer half.
var builtinDenyNames = map[string]bool{
	"systemd":          true,
	"init":             true,
	"sshd":             true,
	"sshd-session":     true,
	"auditd":           true,
	"laurel":           true,
	"systemd-journald": true,
	"dbus-daemon":      true,
	"dbus-broker":      true,
	"login":            true,
	"agetty":           true,
}

// Decide is pure and deterministic: same Input, same Decision, with no clock,
// no filesystem and no /proc read. It never returns an error -- a malformed
// input is a decision of none with a rail and a reason, because a response
// layer that can "error out" is a response layer that can be made to skip.
//
// The order of evaluation is part of the contract (tests depend on it):
// policy match, min level, trusted source, targetable, denylist, duplicate,
// rate limit, kill-switch, then mode. Rails before the mode check run first
// deliberately, so an observe-mode ledger shows exactly which rail would have
// stopped an enforce-mode action.
func Decide(in Input) Decision {
	a := in.Alert
	p := in.Policy

	entry, ok := matchEntry(p, a)
	if !ok {
		return Decision{
			Intended: ActionNone,
			Action:   ActionNone,
			Rail:     RailNoPolicyMatch,
			Reason:   "no policy entry selects this alert",
		}
	}

	d := Decision{
		Intended: entry.Action,
		Action:   ActionNone,
		Entry:    entry.Name,
		Scope:    entry.Scope,
		Target:   buildTarget(entry, a),
	}
	// Record a name-vs-path masquerade on the target regardless of the verdict,
	// so the ledger shows the cloak was seen through even when a later rail
	// (rate limit, observe) stops the action for another reason.
	if d.Target.Process != nil {
		d.Masquerade = isMasquerade(d.Target.Process)
	}

	// An entry that explicitly maps to none never acts; no rail is needed.
	if entry.Action == ActionNone {
		d.Reason = fmt.Sprintf("policy entry %q maps to none", entry.Name)
		return d
	}

	if rail, reason := railFor(in, entry, d.Target); rail != RailNone {
		d.Rail = rail
		d.Reason = reason
		return d
	}

	if p.Mode == ModeObserve {
		d.Rail = RailObserve
		d.Reason = fmt.Sprintf("mode=observe: would %s %s", entry.Action, describeTarget(d.Target))
		return d
	}

	d.Action = entry.Action
	d.Reason = fmt.Sprintf("%s %s per entry %q", entry.Action, describeTarget(d.Target), entry.Name)
	return d
}

// railFor evaluates rails 2-8 in order and returns the first that fires.
func railFor(in Input, e Entry, t Target) (Rail, string) {
	a := in.Alert
	p := in.Policy

	// 2. min level.
	if levelRank[a.Level] < levelRank[p.MinLevel] {
		return RailBelowMinLevel, fmt.Sprintf("alert level %q is below minLevel %q", a.Level, p.MinLevel)
	}

	// 3. trusted source.
	if !contains(p.EnforceSources, a.Source) {
		return RailUntrustedSource, fmt.Sprintf("source %q is not in enforceSources", a.Source)
	}

	// 4. targetable.
	if rail, reason := targetable(p, e, t); rail != RailNone {
		return rail, reason
	}

	// 5. denylist (process targets; file targets are bounded by allowPaths above).
	if t.Process != nil {
		if rail, reason := denylisted(in, t.Process); rail != RailNone {
			return rail, reason
		}
	}

	// 6. duplicate.
	key := targetKey(t)
	for _, s := range in.Seen {
		if targetKey(s) == key {
			return RailDuplicate, "target already decided this run"
		}
	}

	// 7. rate limit.
	if p.RateLimit.PerRun > 0 && in.Budget.RunUsed >= p.RateLimit.PerRun {
		return RailRateLimit, fmt.Sprintf("per-run budget exhausted (%d/%d)", in.Budget.RunUsed, p.RateLimit.PerRun)
	}
	if p.RateLimit.PerHour > 0 && in.Budget.HourUsed >= p.RateLimit.PerHour {
		return RailRateLimit, fmt.Sprintf("per-hour budget exhausted (%d/%d)", in.Budget.HourUsed, p.RateLimit.PerHour)
	}

	// 8. kill-switch.
	if in.KillSwitch {
		return RailKillSwitch, "kill-switch present: " + p.KillSwitchPath
	}

	return RailNone, ""
}

func targetable(p Policy, e Entry, t Target) (Rail, string) {
	switch e.Action {
	case ActionFreeze, ActionKill, ActionCollect:
		if t.Process == nil || t.Process.PID <= 0 {
			return RailUntargetable, "no process id on the event (source carried none)"
		}
	case ActionQuarantine:
		if t.File == nil || t.File.Path == "" {
			return RailUntargetable, "no file path on the event for quarantine"
		}
		path := t.File.Path
		if pfx, bad := underNeverTouch(path); bad {
			return RailUntargetable, fmt.Sprintf("path %q is under never-touch prefix %q", path, pfx)
		}
		if !underAllowPaths(p.Quarantine.AllowPaths, path) {
			return RailUntargetable, fmt.Sprintf("path %q is not under quarantine.allowPaths", path)
		}
	}
	return RailNone, ""
}

func denylisted(in Input, pr *ProcessRef) (Rail, string) {
	p := in.Policy
	if pr.PID == 1 || pr.PID == 2 {
		return RailDenylist, fmt.Sprintf("pid %d is init/kthreadd", pr.PID)
	}
	if pr.PPID == 0 || pr.PPID == 2 {
		return RailDenylist, fmt.Sprintf("ppid %d is a kernel thread", pr.PPID)
	}
	// A built-in protected NAME shields a process only when its image path is
	// under a trusted system prefix. A payload named after a daemon in a
	// world-writable dir (/tmp/.x/sshd) is a masquerade, not a protected
	// process, and must stay actionable -- shielding it by name would let any
	// attacker make malware un-killable just by naming it `sshd` (F2). The
	// executor re-checks this against the LIVE exe realpath before acting.
	if builtinDenyNames[filepath.Base(pr.Image)] && underTrustedExePrefix(pr.Image) {
		return RailDenylist, fmt.Sprintf("image %q is a built-in protected process", pr.Image)
	}
	if in.Self.Exe != "" && pr.Image == in.Self.Exe {
		return RailDenylist, "target is banken itself"
	}
	if !p.AllowRoot && isRoot(pr.User) {
		return RailDenylist, "process runs as uid 0 and allowRoot is false"
	}
	if contains(p.Denylist.Users, pr.User) {
		return RailDenylist, fmt.Sprintf("user %q is in the policy denylist", pr.User)
	}
	if contains(p.Denylist.Images, pr.Image) {
		return RailDenylist, fmt.Sprintf("image %q is in the policy denylist", pr.Image)
	}
	return RailNone, ""
}

func matchEntry(p Policy, a alert.Alert) (Entry, bool) {
	for _, e := range p.Actions {
		if len(e.Rules) > 0 && !contains(e.Rules, a.Rule) {
			continue
		}
		if e.Tag != "" && !contains(a.Tags, e.Tag) {
			continue
		}
		return e, true
	}
	return Entry{}, false
}

func buildTarget(e Entry, a alert.Alert) Target {
	switch e.Action {
	case ActionFreeze, ActionKill, ActionCollect:
		ev := a.Event
		return Target{Process: &ProcessRef{
			PID:       ev.PID,
			PPID:      ev.PPID,
			StartTime: ev.ProcessStart,
			Image:     ev.Image,
			User:      ev.User,
			EventTime: ev.Time,
		}}
	case ActionQuarantine:
		path := a.Event.TargetFilename
		if e.Target == "image" {
			path = a.Event.Image
		}
		return Target{File: &FileRef{Path: path}}
	default:
		return Target{}
	}
}

func targetKey(t Target) string {
	if t.Process != nil {
		return fmt.Sprintf("p:%d:%s", t.Process.PID, t.Process.Image)
	}
	if t.File != nil {
		return "f:" + t.File.Path
	}
	return ""
}

func describeTarget(t Target) string {
	if t.Process != nil {
		return fmt.Sprintf("pid %d (%s)", t.Process.PID, t.Process.Image)
	}
	if t.File != nil {
		return "file " + t.File.Path
	}
	return "nothing"
}

func underAllowPaths(allow []string, path string) bool {
	clean := filepath.Clean(path)
	for _, a := range allow {
		a = filepath.Clean(a)
		if clean == a || strings.HasPrefix(clean, a+"/") {
			return true
		}
	}
	return false
}

// trustedExePrefixes are the on-disk locations a genuine system binary lives
// under. A process earns name-based built-in protection only if its image path
// is under one of these; a protected name anywhere else is a masquerade. This
// is NOT the never-touch list (that bounds quarantine): /home and /tmp are not
// here because a daemon never legitimately runs from them.
var trustedExePrefixes = []string{
	"/nix/store",
	"/usr",
	"/bin",
	"/sbin",
	"/run/current-system/sw/bin",
	"/run/wrappers/bin",
}

func underTrustedExePrefix(path string) bool {
	clean := filepath.Clean(path)
	for _, pfx := range trustedExePrefixes {
		if clean == pfx || strings.HasPrefix(clean, pfx+"/") {
			return true
		}
	}
	return false
}

// isMasquerade reports a target that carries a built-in protected name but
// runs from an untrusted path: a cloak (T1036.005), seen through and left
// actionable.
func isMasquerade(pr *ProcessRef) bool {
	return builtinDenyNames[filepath.Base(pr.Image)] && !underTrustedExePrefix(pr.Image)
}

func isRoot(user string) bool { return user == "root" || user == "0" }

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
