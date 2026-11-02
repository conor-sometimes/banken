package main

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/config"
	"github.com/conor-sometimes/banken/internal/engine"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// ruleByName returns the rule with the given name from a set, or nil.
func ruleByName(rules []*sigma.Rule, name string) *sigma.Rule {
	for _, r := range rules {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// pathOf is r.Path, or "<nil>" for a nil rule (for test failure messages).
func pathOf(r *sigma.Rule) string {
	if r == nil {
		return "<nil>"
	}
	return r.Path
}

// baselineRuleName is a rule shipped in the embedded baseline; a disk rule of
// the same filename overrides it, which the audit must report.
const baselineRuleName = "network_service_scan"

// TestResourceGuardRejectsOverCapAndKeepsOldSet proves the resource guard turns
// an over-cap refresh into a whole-set failure: the previously-good rule set
// stays live and the new rule never loads, so a pathological push cannot blind
// or swamp the host.
func TestResourceGuardRejectsOverCapAndKeepsOldSet(t *testing.T) {
	refreshDir := t.TempDir()
	stateDir := t.TempDir()
	base := config.Config{
		RefreshDirs: []string{refreshDir},
		StatePath:   filepath.Join(stateDir, "cursor.json"),
	}

	cs, err := buildCandidate(base)
	if err != nil {
		t.Fatalf("buildCandidate: %v", err)
	}
	eng := engine.New(cs.rules, cs.iocs, nil)

	// First refresh (generous caps): the probe rule goes live.
	putRule(t, refreshDir, "probe.yml", reloadProbeRule)
	reloadRules(eng, base, io.Discard)
	if n := len(eng.Match(probeEvent())); n != 1 {
		t.Fatalf("probe rule not live after the first refresh (got %d)", n)
	}

	// Second refresh with MaxRules = 1: baseline + probes blow past the cap, so
	// the guard must refuse the swap and keep the old (probe-live) set.
	overCap := base
	overCap.Refresh.MaxRules = 1
	putRule(t, refreshDir, "probe2.yml", reloadProbeRule2)
	var log bytes.Buffer
	reloadRules(eng, overCap, &log)

	if !strings.Contains(log.String(), "resource guard") {
		t.Fatalf("over-cap refresh did not report the guard rejection; log:\n%s", log.String())
	}
	// Old set kept: the first probe still fires...
	if n := len(eng.Match(probeEvent())); n != 1 {
		t.Fatalf("the previously-good probe rule was dropped by a rejected refresh (got %d)", n)
	}
	// ...and the new probe2, part of the rejected set, did NOT load.
	ev2 := probeEvent()
	ev2.CommandLine = "/bin/echo BANKENPROBETWO"
	if n := len(eng.Match(ev2)); n != 0 {
		t.Fatalf("probe2 loaded despite the refresh being rejected over-cap (got %d)", n)
	}

	// The status file records the rejection as kept-old.
	st, err := readRefreshStatus(refreshStatusPath(overCap))
	if err != nil {
		t.Fatalf("readRefreshStatus: %v", err)
	}
	if st.Outcome != refreshKeptOld {
		t.Fatalf("status outcome %q, want %q", st.Outcome, refreshKeptOld)
	}
	if st.Reason == "" {
		t.Fatal("kept-old status has no reason recorded")
	}
}

// TestGuardCheckPatternBytes proves the pattern-byte cap trips independently of
// the rule-count cap, and that generous caps pass.
func TestGuardCheckPatternBytes(t *testing.T) {
	cs, err := buildCandidate(config.Config{})
	if err != nil {
		t.Fatalf("buildCandidate: %v", err)
	}
	if len(cs.rules) == 0 {
		t.Fatal("no baseline rules loaded; cannot test the guard")
	}

	tiny := refreshGuard{maxRules: 1 << 20, maxPatternBytes: 1, timeout: time.Second}
	if err := tiny.check(cs); err == nil || !strings.Contains(err.Error(), "pattern bytes") {
		t.Fatalf("1-byte pattern cap should reject, got %v", err)
	}
	generous := refreshGuard{maxRules: 1 << 20, maxPatternBytes: 1 << 30, timeout: time.Second}
	if err := generous.check(cs); err != nil {
		t.Fatalf("generous caps rejected a normal set: %v", err)
	}
}

// TestRefreshStatusWrittenOnSwap proves a successful refresh writes a status
// file recording the swap, the rule count and the dirs.
func TestRefreshStatusWrittenOnSwap(t *testing.T) {
	refreshDir := t.TempDir()
	stateDir := t.TempDir()
	cfg := config.Config{
		RefreshDirs: []string{refreshDir},
		StatePath:   filepath.Join(stateDir, "cursor.json"),
	}

	cs, err := buildCandidate(cfg)
	if err != nil {
		t.Fatalf("buildCandidate: %v", err)
	}
	eng := engine.New(cs.rules, cs.iocs, nil)

	putRule(t, refreshDir, "probe.yml", reloadProbeRule)
	reloadRules(eng, cfg, io.Discard)

	st, err := readRefreshStatus(refreshStatusPath(cfg))
	if err != nil {
		t.Fatalf("readRefreshStatus: %v", err)
	}
	if st.Outcome != refreshSwapped {
		t.Fatalf("status outcome %q, want %q", st.Outcome, refreshSwapped)
	}
	if st.RulesLoaded < 1 {
		t.Fatalf("status rulesLoaded = %d, want >= 1", st.RulesLoaded)
	}
	found := false
	for _, d := range st.Dirs {
		if d == refreshDir {
			found = true
		}
	}
	if !found {
		t.Fatalf("status dirs %v does not include the refresh dir %s", st.Dirs, refreshDir)
	}
}

// TestBaselineOverrideAudited proves a disk rule that shadows a baseline rule
// by filename is recorded as an override, and that protectBaseline turns it
// into a blocked override with the baseline kept (the disk rule does not win).
func TestBaselineOverrideAudited(t *testing.T) {
	refreshDir := t.TempDir()
	// A disk rule sharing a baseline rule's filename, with distinct content.
	putRule(t, refreshDir, baselineRuleName+".yml", reloadProbeRule)

	// Overrides allowed (default): one override, not blocked, disk rule wins.
	allow := config.Config{RefreshDirs: []string{refreshDir}}
	cs, err := buildCandidate(allow)
	if err != nil {
		t.Fatalf("buildCandidate: %v", err)
	}
	if len(cs.overrides) != 1 {
		t.Fatalf("got %d overrides, want 1: %+v", len(cs.overrides), cs.overrides)
	}
	if cs.overrides[0].name != baselineRuleName || cs.overrides[0].blocked {
		t.Fatalf("override not recorded correctly: %+v", cs.overrides[0])
	}
	if got := ruleByName(cs.rules, baselineRuleName); got == nil || !strings.HasPrefix(got.Path, refreshDir) {
		t.Fatalf("disk rule did not win the override; rule path = %q", pathOf(got))
	}

	// protectBaseline on: the override is blocked and the baseline kept.
	protect := allow
	protect.Refresh.ProtectBaseline = true
	cs2, err := buildCandidate(protect)
	if err != nil {
		t.Fatalf("buildCandidate (protect): %v", err)
	}
	if len(cs2.overrides) != 1 || !cs2.overrides[0].blocked {
		t.Fatalf("protectBaseline did not record a blocked override: %+v", cs2.overrides)
	}
	if got := ruleByName(cs2.rules, baselineRuleName); got == nil || strings.HasPrefix(got.Path, refreshDir) {
		t.Fatalf("protectBaseline let the disk rule win; rule path = %q", pathOf(got))
	}
}
