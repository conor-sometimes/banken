// Package sigma loads the rules/**/*.yml Sigma tree and evaluates the
// subset of Sigma these rules use against a normalised event: the field
// modifiers |contains, |startswith, |endswith, |re and |all, plain
// equality value-lists, and a condition of and / or / not / parens (plus
// "N of ..." / "all of ...") over named selections. Anything outside that
// subset, and any structural mistake in a rule, is a load-time error with
// the offending file and reason named -- a malformed rule is never
// silently dropped, because a rule that silently fails to load is a
// detection that silently is not running.
package sigma

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/conor-sometimes/banken/internal/event"
)

// Rule is one compiled Sigma rule, ready to match events.
type Rule struct {
	// Name is the file basename without .yml -- the stable identifier
	// fixtures (NAME.expect-<name>.json) and alerts key off, independent
	// of the human-facing Title.
	Name string
	// Path is the file the rule was loaded from, for error messages.
	Path string

	Title       string
	ID          string
	Level       string
	Description string
	// Tags are the rule's `tags:` (e.g. attack.t1059.004); carried to the
	// alert for ATT&CK mapping (OCSF) and response-action selectors.
	Tags []string

	// Optional marks an opt-in rule: it is loaded and validated like any
	// other, but held out of the active set unless the operator names it (or
	// "*") in the config's optionalRules / the -optional flag. It is for
	// policy detections that are noisy or environment-specific -- netcat use,
	// a password cracker -- which one host wants and another never would, so
	// they ship in the binary but off, rather than bloating the baseline's
	// signal. The flag is authoritative; the rules/optional/ directory is
	// only where the shipped pack lives for discoverability.
	Optional bool

	// Observe is a runtime disposition (not from the YAML): an optional rule
	// the operator put in observeRules runs, but its alerts are recorded only
	// -- marked Observed so the paging sinks (journal, webhook) skip them --
	// so a host can measure a rule's noise before letting it page. Set by
	// selectActive at load time, never by the rule file.
	Observe bool

	// Sources restricts which sensor sources (event.Source) this rule is
	// evaluated against, derived from the rule's logsource through the pipeline
	// (see pipeline.go). nil means "no restriction" (a rule with no logsource,
	// or one whose logsource matched no pipeline entry) and matches every
	// source; a non-nil slice -- even an empty one -- restricts to exactly those
	// sources. An event whose Source is empty (an ad-hoc `banken check`, a
	// replay with no provenance) always matches, so routing never changes a
	// source-agnostic verdict.
	Sources []string

	selections map[string]selection
	cond       condNode
}

// AppliesTo reports whether this rule should be evaluated against an event from
// the given source. It is the logsource routing gate: a rule scoped by its
// pipeline to one set of sensors is skipped for events from any other, so an
// upstream Windows/Sysmon rule never fires on a Linux auditd event. An empty
// source (source-agnostic check/replay) and a rule with no restriction both
// match.
func (r *Rule) AppliesTo(source string) bool {
	if source == "" || r.Sources == nil {
		return true
	}
	for _, s := range r.Sources {
		if s == source {
			return true
		}
	}
	return false
}

// PatternBytes is the total length, in bytes, of every literal match pattern
// in the rule: each value across every field of every selection alternative
// (equality literals, contains/startswith/endswith substrings, the raw regexp
// and CIDR source strings alike). It is the per-rule cost the refresh resource
// guard sums and bounds (docs/design/rule-refresh.md section 6): it tracks the
// work NewMatcher does folding literals into the shared automaton, so capping
// the total stops a pathological rule tree from blowing up the build. It is a
// cheap pass over already-parsed values, independent of the match path.
func (r *Rule) PatternBytes() int {
	n := 0
	for _, sel := range r.selections {
		for _, alt := range sel.alts {
			for _, fm := range alt.fields {
				// A presence test (|exists / `field: null`) compares no literal --
				// its stored value is just the true/false sense -- so it is not a
				// match pattern and does not count toward the build cost.
				if fm.op == opExists {
					continue
				}
				for _, v := range fm.values {
					n += len(v)
				}
			}
		}
	}
	return n
}

// selection is a named block under detection:. It matches if any of its
// alternatives matches (a plain mapping is one alternative; a YAML list of
// mappings is several, OR'd -- standard Sigma).
type selection struct {
	alts []selMap
}

// selMap is one mapping of field -> matcher; it matches when every field
// matcher matches (AND across fields, standard Sigma).
type selMap struct {
	fields []fieldMatch
}

type matchOp int

const (
	opEquals matchOp = iota
	opContains
	opStartsWith
	opEndsWith
	opRegexp
	opCIDR
	opExists // Sigma `field: null` / `field|exists`: tests field presence, not a value
)

// fieldMatch is one `field|mods: value(s)` entry.
type fieldMatch struct {
	field  string
	op     matchOp
	all    bool // |all: every value must match, not just one
	values []string
	res    []*regexp.Regexp // compiled, parallel to values, for opRegexp
	nets   []netip.Prefix   // parsed, parallel to values, for opCIDR
	// existsWant is the sense of an opExists test: true for `field|exists: true`
	// (field must be present), false for `field: null` and `field|exists: false`
	// (field must be absent). Sigma's null and exists:false are the same test.
	existsWant bool
}

// Match reports whether the rule fires on the event.
func (r *Rule) Match(e event.Event) bool {
	if r.cond == nil {
		return false
	}
	if !r.AppliesTo(e.Source) {
		return false
	}
	results := make(map[string]bool, len(r.selections))
	return r.cond.eval(func(name string) bool {
		if v, ok := results[name]; ok {
			return v
		}
		sel, ok := r.selections[name]
		v := ok && sel.match(e)
		results[name] = v
		return v
	})
}

func (s selection) match(e event.Event) bool {
	for _, alt := range s.alts {
		if alt.match(e) {
			return true
		}
	}
	return false
}

func (m selMap) match(e event.Event) bool {
	for _, fm := range m.fields {
		if !fm.match(e) {
			return false
		}
	}
	return len(m.fields) > 0
}

func (fm fieldMatch) match(e event.Event) bool {
	// Presence test (`field: null` / `field|exists`): no value is compared, only
	// whether the field is present on the event. banken treats an absent field
	// and a present-but-empty named field alike as "no value", which is the same
	// notion of absence the rest of the matcher uses.
	if fm.op == opExists {
		present := len(e.Values(fm.field)) > 0
		return present == fm.existsWant
	}
	if len(fm.values) == 0 {
		return false
	}
	// A field-less matcher (empty field name) is a Sigma "keyword": it matches
	// if any of the event's text fields matches. Used for bare string-list
	// selections; see compileKeywords.
	if fm.field == "" {
		return fm.matchKeyword(e)
	}
	// A field may carry several values (the folded audit sources: `type`,
	// `name`, ...). Sigma matches when ANY of them satisfies the field
	// condition; for a single-valued field this is the one value.
	vals := e.Values(fm.field)
	if len(vals) == 0 {
		return false
	}
	for _, val := range vals {
		if fm.matchValues(val) {
			return true
		}
	}
	return false
}

// matchKeyword is the field-less (keyword) match over all of the event's text
// fields: with |all every value must appear in SOME field (not necessarily the
// same one); otherwise any one value in any field suffices.
func (fm fieldMatch) matchKeyword(e event.Event) bool {
	texts := e.AllText()
	if fm.all {
		for i := range fm.values {
			found := false
			for _, text := range texts {
				if fm.matchOne(text, i) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	for _, text := range texts {
		for i := range fm.values {
			if fm.matchOne(text, i) {
				return true
			}
		}
	}
	return false
}

// matchValues applies the field's value list to one string: with |all every
// value must match, otherwise any one does.
func (fm fieldMatch) matchValues(val string) bool {
	if fm.all {
		for i := range fm.values {
			if !fm.matchOne(val, i) {
				return false
			}
		}
		return true
	}
	for i := range fm.values {
		if fm.matchOne(val, i) {
			return true
		}
	}
	return false
}

func (fm fieldMatch) matchOne(fieldVal string, i int) bool {
	switch fm.op {
	case opRegexp:
		if fm.res[i] == nil {
			return false
		}
		return fm.res[i].MatchString(fieldVal)
	case opContains:
		return strings.Contains(fold(fieldVal), fold(fm.values[i]))
	case opStartsWith:
		return strings.HasPrefix(fold(fieldVal), fold(fm.values[i]))
	case opEndsWith:
		return strings.HasSuffix(fold(fieldVal), fold(fm.values[i]))
	case opCIDR:
		addr, err := netip.ParseAddr(strings.TrimSpace(fieldVal))
		return err == nil && fm.nets[i].Contains(addr)
	default: // opEquals
		return fold(fieldVal) == fold(fm.values[i])
	}
}

// fold lower-cases for the case-insensitive string comparisons Sigma uses
// by default. Regexp matches honour their own pattern's casing instead and
// never pass through here.
func fold(s string) string { return strings.ToLower(s) }
