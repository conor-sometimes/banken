package sigma

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// condNode is a node in a parsed condition expression. eval is given a
// resolver that reports whether a named selection matched.
type condNode interface {
	eval(sel func(name string) bool) bool
}

type condRef struct{ name string }

func (c condRef) eval(sel func(string) bool) bool { return sel(c.name) }

type condNot struct{ x condNode }

func (c condNot) eval(sel func(string) bool) bool { return !c.x.eval(sel) }

type condAnd struct{ l, r condNode }

func (c condAnd) eval(sel func(string) bool) bool { return c.l.eval(sel) && c.r.eval(sel) }

type condOr struct{ l, r condNode }

func (c condOr) eval(sel func(string) bool) bool { return c.l.eval(sel) || c.r.eval(sel) }

// condQuant is "N of <pattern>" / "all of <pattern>": it matches when at
// least n (or every, for all) of the selections whose name matches pattern
// matched. pattern is either "them" (all selections) or a prefix glob
// like "sel*".
type condQuant struct {
	all     bool
	n       int
	pattern string
	names   []string // selection names this quantifier ranges over
}

func (c condQuant) eval(sel func(string) bool) bool {
	need := c.n
	if c.all {
		need = len(c.names)
	}
	if need == 0 {
		return false
	}
	got := 0
	for _, name := range c.names {
		if sel(name) {
			got++
			if got >= need {
				return true
			}
		}
	}
	return false
}

// parseCondition parses a Sigma condition string into a tree. selNames is
// the set of selection names declared in the rule, used to expand "of"
// quantifiers and to reject a reference to an undeclared selection. It
// returns a clear error for any malformed or unsupported condition.
func parseCondition(s string, selNames map[string]struct{}) (condNode, error) {
	toks, err := lexCondition(s)
	if err != nil {
		return nil, err
	}
	p := &condParser{toks: toks, selNames: selNames}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected %q in condition %q", p.toks[p.pos], s)
	}
	if node == nil {
		return nil, errors.New("empty condition")
	}
	return node, nil
}

func lexCondition(s string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch r {
		case '(', ')':
			flush()
			toks = append(toks, string(r))
		case ' ', '\t', '\n', '\r':
			flush()
		case '|':
			return nil, fmt.Errorf("pipe %q is not valid in a condition", s)
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks, nil
}

type condParser struct {
	toks     []string
	pos      int
	selNames map[string]struct{}
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *condParser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *condParser) parseOr() (condNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = condOr{left, right}
	}
	return left, nil
}

func (p *condParser) parseAnd() (condNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = condAnd{left, right}
	}
	return left, nil
}

func (p *condParser) parseNot() (condNode, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.next()
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return condNot{x}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (condNode, error) {
	tok := p.peek()
	switch {
	case tok == "":
		return nil, errors.New("unexpected end of condition")
	case tok == "(":
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("missing closing paren in condition")
		}
		p.next()
		return inner, nil
	case tok == ")":
		return nil, errors.New("unexpected ) in condition")
	case strings.EqualFold(tok, "all") || isIntTok(tok):
		return p.parseQuant()
	case strings.EqualFold(tok, "and") || strings.EqualFold(tok, "or") || strings.EqualFold(tok, "not"):
		return nil, fmt.Errorf("unexpected operator %q in condition", tok)
	default:
		p.next()
		if _, ok := p.selNames[tok]; !ok {
			return nil, fmt.Errorf("condition references unknown selection %q", tok)
		}
		return condRef{tok}, nil
	}
}

// parseQuant handles "1 of them", "all of them", "1 of sel*", "all of sel".
func (p *condParser) parseQuant() (condNode, error) {
	head := p.next() // "all" or an integer
	q := condQuant{}
	if strings.EqualFold(head, "all") {
		q.all = true
	} else {
		n, err := strconv.Atoi(head)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("invalid quantifier %q in condition", head)
		}
		q.n = n
	}
	if !strings.EqualFold(p.next(), "of") {
		return nil, fmt.Errorf("expected 'of' after %q in condition", head)
	}
	pattern := p.next()
	if pattern == "" {
		return nil, errors.New("missing pattern after 'of' in condition")
	}
	q.pattern = pattern
	q.names = p.expandPattern(pattern)
	if len(q.names) == 0 {
		return nil, fmt.Errorf("condition quantifier %q matches no selection", pattern)
	}
	return q, nil
}

func (p *condParser) expandPattern(pattern string) []string {
	var names []string
	if strings.EqualFold(pattern, "them") {
		for name := range p.selNames {
			names = append(names, name)
		}
		return names
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		for name := range p.selNames {
			if strings.HasPrefix(name, prefix) {
				names = append(names, name)
			}
		}
		return names
	}
	if _, ok := p.selNames[pattern]; ok {
		names = append(names, pattern)
	}
	return names
}

func isIntTok(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.Atoi(s)
	return err == nil
}
