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

	selections map[string]selection
	cond       condNode
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
)

// fieldMatch is one `field|mods: value(s)` entry.
type fieldMatch struct {
	field  string
	op     matchOp
	all    bool // |all: every value must match, not just one
	values []string
	res    []*regexp.Regexp // compiled, parallel to values, for opRegexp
}

// Match reports whether the rule fires on the event.
func (r *Rule) Match(e event.Event) bool {
	if r.cond == nil {
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
	if len(fm.values) == 0 {
		return false
	}
	// A field-less matcher (empty field name) is a Sigma "keyword": it matches
	// if any of the event's text fields matches. Used for bare string-list
	// selections; see compileKeywords.
	if fm.field == "" {
		for _, text := range e.AllText() {
			if fm.matchValues(text) {
				return true
			}
		}
		return false
	}
	val, present := e.Field(fm.field)
	if !present {
		return false
	}
	return fm.matchValues(val)
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
	default: // opEquals
		return fold(fieldVal) == fold(fm.values[i])
	}
}

// fold lower-cases for the case-insensitive string comparisons Sigma uses
// by default. Regexp matches honour their own pattern's casing instead and
// never pass through here.
func fold(s string) string { return strings.ToLower(s) }
