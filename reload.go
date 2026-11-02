package main

import (
	"io"

	"github.com/conor-sometimes/banken/internal/config"
	"github.com/conor-sometimes/banken/internal/engine"
	"github.com/conor-sometimes/banken/internal/ioc"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// ruleDirs is the full, ordered list of rule-tree directories banken reads: the
// store-baked Rules first, then the runtime-refreshable RefreshDirs. The order
// is the precedence: loadRules / loadIOCs load later dirs last, and a later dir
// wins a name clash, so RefreshDirs override Rules which override the embedded
// baseline (docs/design/rule-refresh.md section 2). Both the startup build and
// every refresh walk exactly this list, so the daemon's live set and a
// `banken check` preflight over the same dirs can never disagree.
func ruleDirs(cfg config.Config) []string {
	dirs := make([]string, 0, len(cfg.Rules)+len(cfg.RefreshDirs))
	dirs = append(dirs, cfg.Rules...)
	dirs = append(dirs, cfg.RefreshDirs...)
	return dirs
}

// candidateSet is a fully built rule + IOC set, ready to install in the engine.
// buildCandidate produces it with no side effects on any live set, so it is the
// one builder shared by startup (engine.New) and runtime refresh
// (engine.SetRules) -- the single source of truth that keeps the two paths in
// lockstep (the preflight-parity risk in the design, section 11).
type candidateSet struct {
	rules         []*sigma.Rule     // active rules, after optional-rule selection
	iocs          *ioc.Set          // IOC set from the dirs plus the embedded baseline
	problems      []sigma.RuleError // per-file compile errors (non-fatal: those rules are simply absent)
	sel           selection         // optional-rule selection outcome (held back, observing, unknown names)
	overrides     []ruleOverride    // on-disk rules shadowing baseline rules (audited; some blocked by protectBaseline)
	intelAdded    int               // indicators ingested from external threat-intel feeds
	intelProblems []error           // per-feed failures (non-fatal; never-die)
}

// buildCandidate rebuilds banken's full rule + IOC set from the configured dirs
// and threat-intel feeds. It is a pure rebuild: it reads the embedded baseline
// and the on-disk dirs and returns a fresh set, touching nothing live. The
// returned problems are per-file and non-fatal by design (a bad rule is
// reported and skipped, the good ones load) -- the caller decides what an empty
// result or a problem list means (startup errors out with no rules; a refresh
// keeps the old set). err is reserved for a hard failure of IOC loading.
func buildCandidate(cfg config.Config) (candidateSet, error) {
	dirs := ruleDirs(cfg)

	rules, problems, overrides := loadRules(dirs, cfg.Refresh.ProtectBaseline)
	rules, sel := selectActive(rules, optionalSet(cfg.OptionalRules), optionalSet(cfg.ObserveRules))

	iocs, err := loadIOCs(dirs)
	if err != nil {
		return candidateSet{}, err
	}
	added, iprobs := loadIntel(cfg.Intel, iocs)

	return candidateSet{
		rules:         rules,
		iocs:          iocs,
		problems:      problems,
		sel:           sel,
		overrides:     overrides,
		intelAdded:    added,
		intelProblems: iprobs,
	}, nil
}

// reloadRules performs a runtime rule refresh on a running daemon: it rebuilds
// the candidate set off to the side, validates it, and only then swaps it in.
// The invariant it protects is the one that must not be wrong (design section
// 6): a refresh never crashes the daemon, never drops the currently-good set,
// and never leaves it with zero rules.
//
//   - A build error (IOC load failure) or a candidate with zero rules is a
//     whole-set failure: the old set is kept, logged loudly at levelErr, and the
//     daemon keeps running against the rules it already had.
//   - Per-file compile errors are non-fatal: those rules are named in the
//     journal and skipped, the good rules load, exactly as startup does.
//
// It never returns an error because there is nothing a caller could do with one
// that reloadRules has not already done (keep the good set, log the problem).
func reloadRules(eng *engine.Engine, cfg config.Config, stderr io.Writer) {
	guard := guardFromConfig(cfg)

	// Build the candidate under the compile deadline. A build that overruns is a
	// whole-set failure: a pathological tree can never stall the daemon mid-swap.
	cs, err := buildCandidateWithDeadline(cfg, guard.timeout)
	if err != nil {
		logAt(stderr, levelErr, "banken: reload failed, keeping current rule set: %v", err)
		recordRefresh(cfg, refreshKeptOld, err.Error(), candidateSet{}, stderr)
		return
	}
	// Per-file errors are reported but never block the swap -- the good rules
	// still load, matching startup's behaviour.
	for _, p := range cs.problems {
		logAt(stderr, levelErr, "banken: reload rule error: %s", p.Error())
	}
	// Whole-set gate: refuse to install an empty set. The embedded baseline
	// should always compile, so a zero-rule candidate means the build itself is
	// wrong; keeping the old set is strictly safer than going ruleless.
	if len(cs.rules) == 0 {
		logAt(stderr, levelErr, "banken: reload produced zero rules, keeping the current set (host is NOT left ruleless)")
		recordRefresh(cfg, refreshKeptOld, "candidate produced zero rules", cs, stderr)
		return
	}
	// Resource guard: a candidate over the rule-count or pattern-byte cap is a
	// whole-set failure -- old set kept -- so a hostile or accidental "ten
	// million rules" push cannot exhaust memory or blind the host.
	if gerr := guard.check(cs); gerr != nil {
		logAt(stderr, levelErr, "banken: reload rejected by resource guard, keeping current rule set: %v", gerr)
		recordRefresh(cfg, refreshKeptOld, gerr.Error(), cs, stderr)
		return
	}
	// Audit every on-disk rule that shadows a baseline rule (a shadowing push
	// can weaken a detection). A blocked override (protectBaseline) is louder
	// still: it was refused and the baseline kept.
	logOverrides(cs.overrides, stderr)
	for _, name := range cs.sel.unknown {
		logAt(stderr, levelWarning, "banken: %q is named in optionalRules/observeRules but is not an optional rule; it will not run (check the spelling)", name)
	}
	for _, p := range cs.intelProblems {
		logAt(stderr, levelWarning, "banken: intel feed: %v", p)
	}

	eng.SetRules(cs.rules, cs.iocs)
	logAt(stderr, levelInfo, "banken: rules reloaded: %d rules, %d indicators, %d file error(s), %d baseline override(s), swapped",
		len(cs.rules), cs.iocs.Len(), len(cs.problems), len(cs.overrides))
	recordRefresh(cfg, refreshSwapped, "", cs, stderr)
}

// logOverrides reports every baseline-override audit entry: a warning for an
// allowed override (a disk rule now shadows a baseline rule) and an error for a
// blocked one (protectBaseline refused it and kept the baseline). Shared by the
// reload path and startup so the audit reads the same in both.
func logOverrides(overrides []ruleOverride, stderr io.Writer) {
	for _, ov := range overrides {
		if ov.blocked {
			logAt(stderr, levelErr, "banken: protectBaseline refused on-disk rule %q (%s) overriding baseline %s; baseline kept",
				ov.name, ov.winnerPath, ov.overriddenPath)
			continue
		}
		logAt(stderr, levelWarning, "banken: rule %q (%s) overrides baseline %s (a disk rule shadowing a baseline detection)",
			ov.name, ov.winnerPath, ov.overriddenPath)
	}
}
