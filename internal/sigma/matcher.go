package sigma

import (
	"strconv"

	"github.com/conor-sometimes/banken/internal/event"
)

// Matcher evaluates a whole rule set against an event far more cheaply than
// calling Rule.Match on every rule. It is a sound prefilter in front of the
// unchanged Rule.Match, not a replacement for it:
//
//  1. Every string literal across every rule (|contains/startswith/endswith
//     and plain equality) is compiled into one Aho-Corasick automaton.
//  2. For an event, one pass per field finds the set of literals present
//     anywhere in it -- cost independent of the number of rules.
//  3. Only rules that *could* match given that set (an inverted literal->rule
//     index plus a per-rule upper-bound test) have the authoritative
//     Rule.Match run on them.
//
// Soundness: Rule.Match(ev) == true implies the rule's upperBound over the
// present-literal set is true (every literal op is matched only if its
// folded value occurs as a substring, which the automaton therefore finds;
// |all requires all its values present; `not` subtrees are treated as true;
// and the condition's upperBound is monotone above eval). So a rule the
// prefilter skips can never have matched. The automaton can only *over*-admit
// -- causing a wasted Rule.Match -- never miss a detection.
type Matcher struct {
	rules []*Rule
	ac    *acMatcher
	pre   []rulePrefilter // parallel to rules
	inv   map[int][]int   // literal id -> indices of rules that reference it
	// always holds indices of rules that could match with no literal present
	// at all (a regexp-only selection, or a condition reachable through `not`);
	// they are evaluated on every event.
	always []int
}

// rulePrefilter is the literal-presence view of one rule's detection logic.
type rulePrefilter struct {
	cond condNode
	sels map[string]selPrefilter
}

type selPrefilter struct{ alts []selMapPrefilter }

type selMapPrefilter struct{ fields []fieldPrefilter }

type fieldPrefilter struct {
	wild   bool  // regexp, or an empty literal: always could-match, un-prefilterable
	all    bool  // |all: every literal must be present, not just one
	litIDs []int // literal ids of this field's values (non-wild)
}

// NewMatcher compiles rules into a prefiltered matcher. The rules slice is
// retained (matches are reported in its order); pass it already sorted if a
// stable alert order matters, as LoadTree does.
func NewMatcher(rules []*Rule) *Matcher {
	m := &Matcher{rules: rules, inv: map[int][]int{}}
	intern := map[string]int{}
	var patterns [][]byte
	id := func(litFolded string) int {
		if n, ok := intern[litFolded]; ok {
			return n
		}
		n := len(patterns)
		intern[litFolded] = n
		patterns = append(patterns, []byte(litFolded))
		return n
	}

	m.pre = make([]rulePrefilter, len(rules))
	for ri, r := range rules {
		rp := rulePrefilter{cond: r.cond, sels: make(map[string]selPrefilter, len(r.selections))}
		refd := map[int]struct{}{} // literal ids this rule references, deduped
		for name, sel := range r.selections {
			sp := selPrefilter{alts: make([]selMapPrefilter, 0, len(sel.alts))}
			for _, alt := range sel.alts {
				smp := selMapPrefilter{fields: make([]fieldPrefilter, 0, len(alt.fields))}
				for _, fm := range alt.fields {
					fp := fieldPrefilter{all: fm.all}
					if fm.op == opRegexp || fm.op == opCIDR || fm.op == opExists {
						// Not a literal substring test: a regexp/CIDR carries no
						// folded literal, and a presence test (opExists) can match
						// an event with no literal present at all (field absent).
						// Either way the prefilter cannot gate on it, so it always
						// could-match -- sound (over-admits, never misses).
						fp.wild = true
					} else {
						for _, v := range fm.values {
							folded := fold(v)
							if folded == "" {
								// An empty literal is contained in everything.
								// Under OR it makes the field always could-match;
								// under |all it is trivially satisfied, so skip it.
								if !fm.all {
									fp.wild = true
								}
								continue
							}
							lid := id(folded)
							fp.litIDs = append(fp.litIDs, lid)
							refd[lid] = struct{}{}
						}
						// A |all field whose only values were empty still matches
						// everything; treat it as wild so it never wrongly gates.
						if fm.all && len(fp.litIDs) == 0 && !fp.wild {
							fp.wild = true
						}
					}
					smp.fields = append(smp.fields, fp)
				}
				sp.alts = append(sp.alts, smp)
			}
			rp.sels[name] = sp
		}
		m.pre[ri] = rp

		// A rule that could pass with nothing present (regexp-only or a
		// negation-reachable condition) must be tried on every event.
		if rp.upperBound(map[int]struct{}{}) {
			m.always = append(m.always, ri)
			continue
		}
		// Otherwise it can only fire when one of its literals is present, so
		// index it under each literal it references.
		for lid := range refd {
			m.inv[lid] = append(m.inv[lid], ri)
		}
	}

	m.ac = newACMatcher(patterns)
	return m
}

// Match returns the rules that fire on ev, in rule order. It finds the
// present literals once, assembles the candidate set, and runs the
// authoritative Rule.Match only on candidates.
func (m *Matcher) Match(ev event.Event) []*Rule {
	if len(m.rules) == 0 {
		return nil
	}
	present := make(map[int]struct{})
	m.scanEvent(ev, present)

	// Candidate rule indices: always-on rules plus every rule indexed under a
	// present literal. A set keeps each rule once even if several of its
	// literals hit.
	cand := make(map[int]struct{}, len(m.always))
	for _, ri := range m.always {
		cand[ri] = struct{}{}
	}
	for lid := range present {
		for _, ri := range m.inv[lid] {
			cand[ri] = struct{}{}
		}
	}
	if len(cand) == 0 {
		return nil
	}

	var hits []*Rule
	for ri, r := range m.rules { // rule order, so alert order is stable
		if _, ok := cand[ri]; !ok {
			continue
		}
		if !m.pre[ri].upperBound(present) {
			continue // precise gate catches "N of" / |all that the index over-admits
		}
		if r.Match(ev) {
			hits = append(hits, r)
		}
	}
	return hits
}

// scanEvent runs the automaton over every matchable field of the event,
// folding to the same casing the literals were compiled with so substring
// relationships are preserved. It uses event.AllText -- the same definition of
// "matchable fields" a field-less keyword match uses -- so the prefilter and
// the authoritative match can never disagree about which text an event has.
func (m *Matcher) scanEvent(ev event.Event, present map[int]struct{}) {
	for _, v := range ev.AllText() {
		m.ac.scanInto(fold(v), present)
	}
	// ProcessId / ParentProcessId are matchable via Event.Field but are not in
	// AllText (they are ids, not keyword text), so scan them here too -- the
	// prefilter must cover EVERY value Field() can return, or a rule keying on
	// them would be wrongly skipped. Keyword matching still ignores them.
	if ev.PID > 0 {
		m.ac.scanInto(fold(strconv.Itoa(ev.PID)), present)
	}
	if ev.PPID > 0 {
		m.ac.scanInto(fold(strconv.Itoa(ev.PPID)), present)
	}
}

// Len reports how many rules the matcher holds.
func (m *Matcher) Len() int { return len(m.rules) }

// upperBound evaluates the rule's condition against the present-literal set,
// resolving each selection reference to "could this selection match".
func (rp rulePrefilter) upperBound(present map[int]struct{}) bool {
	if rp.cond == nil {
		return false
	}
	return rp.cond.upperBound(func(name string) bool {
		sp, ok := rp.sels[name]
		return ok && sp.couldMatch(present)
	})
}

func (sp selPrefilter) couldMatch(present map[int]struct{}) bool {
	for _, alt := range sp.alts {
		if alt.couldMatch(present) {
			return true
		}
	}
	return false
}

func (smp selMapPrefilter) couldMatch(present map[int]struct{}) bool {
	if len(smp.fields) == 0 {
		return false
	}
	for _, fp := range smp.fields {
		if !fp.couldMatch(present) {
			return false
		}
	}
	return true
}

func (fp fieldPrefilter) couldMatch(present map[int]struct{}) bool {
	if fp.wild {
		return true
	}
	if len(fp.litIDs) == 0 {
		return false
	}
	if fp.all {
		for _, lid := range fp.litIDs {
			if _, ok := present[lid]; !ok {
				return false
			}
		}
		return true
	}
	for _, lid := range fp.litIDs {
		if _, ok := present[lid]; ok {
			return true
		}
	}
	return false
}
