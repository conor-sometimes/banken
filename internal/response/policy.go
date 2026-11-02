package response

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode is the response mode. observe (the default) decides and records but
// nothing acts; enforce lets a decided action through to the executor -- and
// even then only once the executor is explicitly armed, which is a separate,
// off-by-default gate (see internal/response/exec).
type Mode string

const (
	ModeObserve Mode = "observe"
	ModeEnforce Mode = "enforce"
)

// Policy is the operator config: which rule/tag maps to which action, the
// mode, the rails. It is loaded from YAML (the bare response block) and
// validated with the Sigma loader's discipline -- an unknown key, action,
// mode or target is a load error naming it, never a silent default.
type Policy struct {
	Mode           Mode       `yaml:"mode"`
	KillSwitchPath string     `yaml:"killSwitchPath"`
	MinLevel       string     `yaml:"minLevel"`
	EnforceSources []string   `yaml:"enforceSources"`
	AllowRoot      bool       `yaml:"allowRoot"` // default-refuse uid 0 unless true (research section 4)
	RateLimit      RateLimit  `yaml:"rateLimit"`
	Denylist       Denylist   `yaml:"denylist"`
	Quarantine     Quarantine `yaml:"quarantine"`
	Actions        []Entry    `yaml:"actions"`

	// hash is the sha256 of the canonical policy, computed at load, written on
	// every ledger line so a decision is tied to the exact policy that made it.
	hash string
}

// RateLimit bounds how many actions a run may request and the drain may
// perform in an hour; the caller tracks usage in the Budget it passes Decide.
type RateLimit struct {
	PerRun  int `yaml:"perRun"`
	PerHour int `yaml:"perHour"`
}

// Denylist is the operator's additions to the built-in never-touch list. It
// can only add; it can never remove a built-in entry.
type Denylist struct {
	Images []string `yaml:"images"`
	Users  []string `yaml:"users"`
}

// Quarantine configures where quarantined files go and which paths may be
// quarantined at all.
type Quarantine struct {
	Dir        string   `yaml:"dir"`
	AllowPaths []string `yaml:"allowPaths"`
	// MaxFileBytes bounds the sha256 (and the later YARA scan), never the
	// rename: 256 MiB by default -- a hash of a larger file costs seconds the
	// drain cannot spend; the rename costs nothing, so the file is still taken
	// (its sha256 recorded "unhashed"). A hung mount or a 1 TiB sparse dropper
	// must not block the drain.
	MaxFileBytes int64 `yaml:"maxFileBytes"`
}

// Entry is one policy rule: a selector (rules and/or tag) and the action to
// take when it matches. Entries are evaluated in file order; the first whose
// selector matches an alert wins.
type Entry struct {
	Name   string   `yaml:"name"`
	Rules  []string `yaml:"rules"` // exact rule names (file basename)
	Tag    string   `yaml:"tag"`   // a Sigma tags: entry the rule carries
	Action Action   `yaml:"action"`
	Scope  Scope    `yaml:"scope"`  // process | tree (freeze/kill/collect)
	Target string   `yaml:"target"` // image | targetFilename (quarantine)
}

// validLevels ranks the Sigma severities so "below minLevel" is a comparison.
var levelRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// implementedActions are the actions the executor can perform in this phase.
// ActionIsolate is deliberately absent: it is reserved for a later phase and
// the loader rejects it.
var implementedActions = map[Action]bool{
	ActionNone:       true,
	ActionFreeze:     true,
	ActionKill:       true,
	ActionQuarantine: true,
	ActionCollect:    true,
}

// reversibleActions may be reached by a tag-only selector. kill is not here:
// a remote rule can tag itself, so a tag-only entry must never earn a kill
// (it must be pinned to an exact rule name). This is the one asymmetry.
var reversibleActions = map[Action]bool{
	ActionFreeze:     true,
	ActionQuarantine: true,
	ActionCollect:    true,
}

// builtinNeverTouchPrefixes are paths a quarantine allowPath may never lie
// under, and the single source of that list for the whole subsystem (the
// executor calls UnderNeverTouch rather than keeping its own copy). Evaluated
// at policy load so a bad policy fails there, not at the first alert.
//
// /dev is here so the intent -- never act on a device node -- lives in the
// list, not in a downstream S_IFREG check (Q14). /dev/shm is a tmpfs scratch
// area and a legitimate allowPath, so it is carved out in UnderNeverTouch.
var builtinNeverTouchPrefixes = []string{
	"/nix/store", "/usr", "/bin", "/sbin", "/lib", "/lib64",
	"/etc", "/boot", "/proc", "/sys", "/run", "/dev",
}

// devShmCarveOut is the one path under a never-touch prefix (/dev) that is
// still actionable: the /dev/shm tmpfs. It is an exact prefix-with-boundary,
// so /dev/shm and /dev/shm/x are carved out while /dev/shmx and /dev/shma are
// not (they remain under never-touch /dev).
const devShmCarveOut = "/dev/shm"

// ParsePolicy decodes the bare response-policy YAML block, applies defaults
// and validates it. An unknown field is a load error (strict decoding), as
// is any failed validation rule. The returned Policy carries its canonical
// hash.
func ParsePolicy(data []byte) (Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("response: parse policy: %w", err)
	}
	p.applyDefaults()
	if err := p.validate(); err != nil {
		return Policy{}, err
	}
	p.hash = p.computeHash()
	return p, nil
}

// LoadPolicy reads and parses a policy file.
func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied policy path
	if err != nil {
		return Policy{}, fmt.Errorf("response: read policy %s: %w", path, err)
	}
	return ParsePolicy(data)
}

// Hash is the "sha256:<hex>" of the canonical policy, for the ledger.
func (p Policy) Hash() string { return p.hash }

func (p *Policy) applyDefaults() {
	if p.Mode == "" {
		p.Mode = ModeObserve
	}
	if p.MinLevel == "" {
		p.MinLevel = "high"
	}
	if p.KillSwitchPath == "" {
		p.KillSwitchPath = "/run/banken/disable"
	}
	if len(p.EnforceSources) == 0 {
		p.EnforceSources = []string{"auditd", "laurel"}
	}
	if p.RateLimit.PerRun == 0 && p.RateLimit.PerHour == 0 {
		p.RateLimit.PerRun = 3
		p.RateLimit.PerHour = 10
	}
	if p.Quarantine.MaxFileBytes == 0 {
		// 256 MiB: a hash of a larger file costs seconds the drain cannot spend;
		// the rename costs nothing, so the file is still taken.
		p.Quarantine.MaxFileBytes = 268435456
	}
	for i := range p.Actions {
		e := &p.Actions[i]
		if e.Scope == "" && (e.Action == ActionFreeze) {
			// freeze defaults to the whole tree: a reverse shell's children are
			// the point. kill/collect default to the single process.
			e.Scope = ScopeTree
		} else if e.Scope == "" && (e.Action == ActionKill || e.Action == ActionCollect) {
			e.Scope = ScopeProcess
		}
		if e.Action == ActionQuarantine && e.Target == "" {
			e.Target = "targetFilename"
		}
	}
}

func (p Policy) validate() error {
	switch p.Mode {
	case ModeObserve, ModeEnforce:
	default:
		return fmt.Errorf("response: invalid mode %q (want observe or enforce)", p.Mode)
	}
	if _, ok := levelRank[p.MinLevel]; !ok {
		return fmt.Errorf("response: invalid minLevel %q (want low|medium|high|critical)", p.MinLevel)
	}
	if p.RateLimit.PerRun < 0 || p.RateLimit.PerHour < 0 {
		return fmt.Errorf("response: rateLimit must be >= 0 (got perRun=%d perHour=%d)", p.RateLimit.PerRun, p.RateLimit.PerHour)
	}
	if p.Quarantine.MaxFileBytes < 0 {
		return fmt.Errorf("response: quarantine.maxFileBytes must be >= 0 (got %d)", p.Quarantine.MaxFileBytes)
	}
	for _, ap := range p.Quarantine.AllowPaths {
		if !filepath.IsAbs(ap) {
			return fmt.Errorf("response: quarantine.allowPaths entry %q is not absolute", ap)
		}
		if pfx, bad := UnderNeverTouch(ap); bad {
			return fmt.Errorf("response: quarantine.allowPaths entry %q lies under never-touch prefix %q", ap, pfx)
		}
	}
	names := make(map[string]bool, len(p.Actions))
	for i, e := range p.Actions {
		where := fmt.Sprintf("actions[%d]", i)
		if e.Name == "" {
			return fmt.Errorf("response: %s has no name", where)
		}
		if names[e.Name] {
			return fmt.Errorf("response: duplicate action name %q", e.Name)
		}
		names[e.Name] = true
		if !implementedActions[e.Action] {
			if e.Action == ActionIsolate {
				return fmt.Errorf("response: action %q (entry %q) is reserved, not implemented in this version", e.Action, e.Name)
			}
			return fmt.Errorf("response: unknown action %q (entry %q)", e.Action, e.Name)
		}
		if len(e.Rules) == 0 && e.Tag == "" {
			return fmt.Errorf("response: entry %q has no selector (set rules: or tag:)", e.Name)
		}
		if e.Action == ActionKill && len(e.Rules) == 0 {
			return fmt.Errorf("response: entry %q: kill requires rules: (a tag-only kill is refused; a remote rule can tag itself)", e.Name)
		}
		if e.Tag != "" && len(e.Rules) == 0 && !reversibleActions[e.Action] && e.Action != ActionNone {
			return fmt.Errorf("response: entry %q: a tag-only selector may only map to a reversible action (freeze, quarantine, collect)", e.Name)
		}
		switch e.Action {
		case ActionQuarantine:
			if e.Target != "image" && e.Target != "targetFilename" {
				return fmt.Errorf("response: entry %q: quarantine target must be image or targetFilename (got %q)", e.Name, e.Target)
			}
			if e.Scope != "" {
				return fmt.Errorf("response: entry %q: scope is not valid for quarantine", e.Name)
			}
		case ActionFreeze, ActionKill:
			if e.Target != "" {
				return fmt.Errorf("response: entry %q: target is not valid for a process action (%s)", e.Name, e.Action)
			}
			if e.Scope != ScopeProcess && e.Scope != ScopeTree {
				return fmt.Errorf("response: entry %q: invalid scope %q (want process or tree)", e.Name, e.Scope)
			}
		case ActionCollect:
			if e.Target != "" {
				return fmt.Errorf("response: entry %q: target is not valid for collect", e.Name)
			}
		}
	}
	return nil
}

// UnderNeverTouch reports whether path lies on a built-in never-touch prefix,
// returning the matched prefix. It is the one definition the decision layer,
// the policy validator and the executor all share. The /dev/shm carve-out is
// evaluated first so a path under it is never treated as never-touch, with an
// exact boundary so /dev/shmx stays under never-touch /dev.
func UnderNeverTouch(path string) (string, bool) {
	clean := filepath.Clean(path)
	if clean == devShmCarveOut || strings.HasPrefix(clean, devShmCarveOut+"/") {
		return "", false
	}
	for _, pfx := range builtinNeverTouchPrefixes {
		if clean == pfx || strings.HasPrefix(clean, pfx+"/") {
			return pfx, true
		}
	}
	return "", false
}

// computeHash marshals the policy back to canonical YAML (stable field order)
// and hashes it, so the hash depends on the policy's meaning, not its on-disk
// formatting or comments.
func (p Policy) computeHash() string {
	// Sort slice fields that are order-insensitive so reordering does not
	// change the hash; action order is significant and left as-is.
	clone := p
	clone.hash = ""
	es := append([]string(nil), clone.EnforceSources...)
	sort.Strings(es)
	clone.EnforceSources = es
	out, err := yaml.Marshal(clone)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(out)
	return "sha256:" + hex.EncodeToString(sum[:])
}
