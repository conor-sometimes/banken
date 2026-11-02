package main

import (
	"fmt"
	"time"

	"github.com/conor-sometimes/banken/internal/config"
)

// defaultRefreshTimeout is the deadline on a whole refresh build when the
// config names none. Generous: a real fleet rules repo compiles in
// milliseconds to low tens of milliseconds, so 30s only ever trips on a
// genuinely pathological tree.
const defaultRefreshTimeout = 30 * time.Second

// refreshGuard bounds a runtime refresh so a pathological or hostile rules tree
// cannot exhaust memory or stall the daemon mid-swap (docs/design/rule-refresh.md
// section 6). It caps the rule count and the total literal pattern bytes, and
// puts a deadline on the build. A candidate over any cap is a whole-set failure:
// the caller keeps the currently-good set.
type refreshGuard struct {
	maxRules        int
	maxPatternBytes int
	timeout         time.Duration
}

// guardFromConfig reads the guard limits from the config, applying the generous
// defaults for any that are unset (or, for the timeout, unparseable) so the
// zero value is a working, safe guard.
func guardFromConfig(cfg config.Config) refreshGuard {
	g := refreshGuard{
		maxRules:        cfg.Refresh.MaxRules,
		maxPatternBytes: cfg.Refresh.MaxPatternBytes,
		timeout:         defaultRefreshTimeout,
	}
	if g.maxRules <= 0 {
		g.maxRules = config.DefaultMaxRules
	}
	if g.maxPatternBytes <= 0 {
		g.maxPatternBytes = config.DefaultMaxPatternBytes
	}
	if s := cfg.Refresh.CompileTimeout; s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			g.timeout = d
		}
	}
	return g
}

// check reports whether a candidate is within the guard's caps. Over-cap is an
// error (the caller keeps the old set); within-cap is nil. It is a cheap pass
// over already-parsed rules, run before the engine builds the automaton, so a
// too-large set is refused before any expensive work.
func (g refreshGuard) check(cs candidateSet) error {
	if n := len(cs.rules); n > g.maxRules {
		return fmt.Errorf("%d rules exceeds the cap of %d (refresh.maxRules)", n, g.maxRules)
	}
	total := 0
	for _, r := range cs.rules {
		total += r.PatternBytes()
	}
	if total > g.maxPatternBytes {
		return fmt.Errorf("%d pattern bytes exceeds the cap of %d (refresh.maxPatternBytes)", total, g.maxPatternBytes)
	}
	return nil
}

// buildCandidateWithDeadline runs buildCandidate under a deadline. If the build
// finishes in time, its result is returned; if it overruns, a deadline error is
// returned and the caller keeps the old set. The build goroutine is abandoned
// on timeout (it finishes and its result is discarded) rather than cancelled --
// buildCandidate is a pure read with no live side effects, so a late finisher
// harms nothing, and the point of the deadline is only to stop a stall from
// blocking the swap, not to interrupt the parse.
func buildCandidateWithDeadline(cfg config.Config, timeout time.Duration) (candidateSet, error) {
	if timeout <= 0 {
		timeout = defaultRefreshTimeout
	}
	type result struct {
		cs  candidateSet
		err error
	}
	ch := make(chan result, 1)
	go func() {
		cs, err := buildCandidate(cfg)
		ch <- result{cs, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.cs, r.err
	case <-timer.C:
		return candidateSet{}, fmt.Errorf("refresh build exceeded the %s deadline (refresh.compileTimeout)", timeout)
	}
}
