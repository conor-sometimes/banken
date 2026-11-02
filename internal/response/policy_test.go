package response

import (
	"strings"
	"testing"
)

func TestParsePolicyDefaults(t *testing.T) {
	p, err := ParsePolicy([]byte(`
actions:
  - name: f
    rules: [reverse_shell]
    action: freeze
`))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.Mode != ModeObserve {
		t.Errorf("default mode = %q, want observe", p.Mode)
	}
	if p.MinLevel != "high" {
		t.Errorf("default minLevel = %q, want high", p.MinLevel)
	}
	if p.KillSwitchPath != "/run/banken/disable" {
		t.Errorf("default killSwitchPath = %q", p.KillSwitchPath)
	}
	if p.RateLimit.PerRun != 3 || p.RateLimit.PerHour != 10 {
		t.Errorf("default rateLimit = %+v", p.RateLimit)
	}
	if len(p.EnforceSources) != 2 {
		t.Errorf("default enforceSources = %v", p.EnforceSources)
	}
	if p.Actions[0].Scope != ScopeTree {
		t.Errorf("freeze default scope = %q, want tree", p.Actions[0].Scope)
	}
	if p.Hash() == "" || !strings.HasPrefix(p.Hash(), "sha256:") {
		t.Errorf("hash = %q, want sha256:...", p.Hash())
	}
}

func TestParsePolicyInvalid(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name:    "unknown field",
			yaml:    "modez: enforce\nactions: []\n",
			wantSub: "parse policy",
		},
		{
			name:    "bad mode",
			yaml:    "mode: paranoid\nactions:\n  - {name: f, rules: [r], action: freeze}\n",
			wantSub: "invalid mode",
		},
		{
			name:    "bad minLevel",
			yaml:    "minLevel: screaming\nactions:\n  - {name: f, rules: [r], action: freeze}\n",
			wantSub: "invalid minLevel",
		},
		{
			name:    "unknown action",
			yaml:    "actions:\n  - {name: f, rules: [r], action: nuke}\n",
			wantSub: "unknown action",
		},
		{
			name:    "isolate reserved",
			yaml:    "actions:\n  - {name: f, rules: [r], action: isolate}\n",
			wantSub: "reserved, not implemented",
		},
		{
			name:    "tag-only kill refused",
			yaml:    "actions:\n  - {name: k, tag: attack.t1, action: kill}\n",
			wantSub: "kill requires rules",
		},
		{
			name:    "tag-only non-reversible refused",
			yaml:    "actions:\n  - {name: k, tag: attack.t1, action: kill}\n",
			wantSub: "kill requires rules",
		},
		{
			name:    "no selector",
			yaml:    "actions:\n  - {name: f, action: freeze}\n",
			wantSub: "no selector",
		},
		{
			name:    "no name",
			yaml:    "actions:\n  - {rules: [r], action: freeze}\n",
			wantSub: "has no name",
		},
		{
			name:    "duplicate name",
			yaml:    "actions:\n  - {name: f, rules: [r], action: freeze}\n  - {name: f, rules: [r2], action: freeze}\n",
			wantSub: "duplicate action name",
		},
		{
			name:    "quarantine bad target",
			yaml:    "actions:\n  - {name: q, rules: [r], action: quarantine, target: process}\n",
			wantSub: "quarantine target must be",
		},
		{
			name:    "process action with target",
			yaml:    "actions:\n  - {name: f, rules: [r], action: freeze, target: targetFilename}\n",
			wantSub: "target is not valid for a process action",
		},
		{
			name:    "quarantine with scope",
			yaml:    "actions:\n  - {name: q, rules: [r], action: quarantine, scope: tree}\n",
			wantSub: "scope is not valid for quarantine",
		},
		{
			name:    "allowPaths relative",
			yaml:    "quarantine:\n  allowPaths: [tmp]\nactions:\n  - {name: f, rules: [r], action: freeze}\n",
			wantSub: "is not absolute",
		},
		{
			name:    "allowPaths under never-touch",
			yaml:    "quarantine:\n  allowPaths: [/nix/store/x]\nactions:\n  - {name: f, rules: [r], action: freeze}\n",
			wantSub: "never-touch prefix",
		},
		{
			name:    "negative rate limit",
			yaml:    "rateLimit:\n  perRun: -1\nactions:\n  - {name: f, rules: [r], action: freeze}\n",
			wantSub: "rateLimit must be >= 0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("ParsePolicy(%q) = nil error, want error containing %q", tt.name, tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestParsePolicyValidActions(t *testing.T) {
	// Every implemented action must load, and a tag-only reversible action is
	// accepted while a tag-only kill is not (covered above).
	p, err := ParsePolicy([]byte(`
mode: enforce
quarantine:
  allowPaths: [/tmp]
actions:
  - {name: a, rules: [r1], action: none}
  - {name: b, rules: [r2], action: freeze, scope: process}
  - {name: c, rules: [r3], action: kill, scope: tree}
  - {name: d, rules: [r4], action: quarantine, target: image}
  - {name: e, rules: [r5], action: collect}
  - {name: g, tag: attack.command-and-control, action: freeze}
  - {name: h, tag: attack.t1105, action: quarantine}
`))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if len(p.Actions) != 7 {
		t.Fatalf("got %d actions", len(p.Actions))
	}
}

func TestPolicyHashStableAcrossFormatting(t *testing.T) {
	a := mustParse(t, "mode: enforce\nenforceSources: [auditd, laurel]\nactions:\n  - {name: f, rules: [r], action: freeze}\n")
	// Same meaning, reordered enforceSources and extra whitespace/comments.
	b := mustParse(t, "# a comment\nmode: enforce\n\nenforceSources:  [laurel, auditd]\nactions:\n  - {name: f, rules: [r], action: freeze}\n")
	if a.Hash() != b.Hash() {
		t.Errorf("hash differs for equivalent policies:\n a=%s\n b=%s", a.Hash(), b.Hash())
	}
	c := mustParse(t, "mode: observe\nenforceSources: [auditd, laurel]\nactions:\n  - {name: f, rules: [r], action: freeze}\n")
	if a.Hash() == c.Hash() {
		t.Errorf("hash should differ when mode differs")
	}
}

func mustParse(t *testing.T, yml string) Policy {
	t.Helper()
	p, err := ParsePolicy([]byte(yml))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return p
}

// TestNeverTouchDevWithShmCarveOut pins the Q14 intent: /dev is never-touch so
// a device node is refused by the list, not by a downstream S_IFREG check,
// while the /dev/shm tmpfs is carved out with an exact boundary (so /dev/shmx
// is NOT treated as under the carve-out).
func TestNeverTouchDevWithShmCarveOut(t *testing.T) {
	cases := map[string]bool{
		"/dev":          true,  // the device dir itself
		"/dev/null":     true,  // a device node
		"/dev/sda":      true,  // a block device
		"/dev/shm":      false, // tmpfs carve-out
		"/dev/shm/x":    false, // under the carve-out
		"/dev/shmx":     true,  // NOT the carve-out (boundary): still never-touch
		"/dev/shma":     true,  // NOT the carve-out (boundary): still never-touch
		"/tmp/x":        false, // a scratch path, untouched by the list
		"/nix/store/ab": true,  // a pre-existing never-touch prefix still holds
	}
	for path, wantBad := range cases {
		pfx, bad := UnderNeverTouch(path)
		if bad != wantBad {
			t.Errorf("UnderNeverTouch(%q) bad = %v (prefix %q), want %v", path, bad, pfx, wantBad)
		}
		if bad && pfx == "" {
			t.Errorf("UnderNeverTouch(%q) reported never-touch with empty prefix", path)
		}
	}
}
