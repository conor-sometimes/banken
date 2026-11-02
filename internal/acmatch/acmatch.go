// Package acmatch is banken's one literal-set matcher: a byte-level
// Aho-Corasick automaton, built once from a fixed set of string literals, that
// finds every literal present in a piece of text in a single O(len(text)) pass,
// no matter how many literals were compiled in. That is what lets a rule or
// indicator count grow without the per-event cost growing with it.
//
// Two callers share it so there is one implementation, not two:
//
//   - internal/sigma compiles every rule's string literals into one Matcher
//     and uses the found set to gate which rules get the authoritative
//     Rule.Match (see internal/sigma/matcher.go).
//   - internal/ioc compiles every filename/path indicator into one Matcher and
//     uses the found set as the indicator hits for an event.
//
// It carries no detection logic of its own: it answers only "which of these
// literals occur in this text". A bug here can at worst report a literal that
// is not really present (wasted downstream work) or miss one; the set it
// returns is exactly the literals that occur as a substring, so for the sigma
// prefilter it is always a superset of the true match set (over-admit, never
// miss -- proof in internal/sigma/matcher.go), and for ioc it is the substring
// hit set directly.
package acmatch

// Matcher is a compiled Aho-Corasick automaton over a fixed literal set.
type Matcher struct {
	next []map[byte]int // goto edges per node; node 0 is the root
	fail []int          // failure links
	out  [][]int        // literal ids whose pattern ends at (or via) this node
}

// New builds an automaton over the given patterns. Each pattern's index in the
// slice is the literal id reported for it; empty patterns are skipped (a caller
// that needs "empty matches everything" handles that itself), and the remaining
// patterns must already be folded to the casing used at scan time. Duplicate
// patterns are allowed (each keeps its own id).
func New(patterns [][]byte) *Matcher {
	ac := &Matcher{
		next: []map[byte]int{{}}, // root
		fail: []int{0},
		out:  [][]int{nil},
	}
	for id, pat := range patterns {
		if len(pat) == 0 {
			continue // an empty literal is handled as "wild" by the caller, never fed here
		}
		ac.add(pat, id)
	}
	ac.buildFail()
	return ac
}

func (ac *Matcher) add(pat []byte, id int) {
	s := 0
	for _, b := range pat {
		nxt, ok := ac.next[s][b]
		if !ok {
			nxt = len(ac.next)
			ac.next = append(ac.next, map[byte]int{})
			ac.fail = append(ac.fail, 0)
			ac.out = append(ac.out, nil)
			ac.next[s][b] = nxt
		}
		s = nxt
	}
	ac.out[s] = append(ac.out[s], id)
}

// buildFail sets the failure links and merges outputs with a BFS over the
// trie (standard Aho-Corasick construction).
func (ac *Matcher) buildFail() {
	queue := make([]int, 0, len(ac.next))
	for _, v := range ac.next[0] {
		ac.fail[v] = 0
		queue = append(queue, v)
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for b, v := range ac.next[u] {
			// fail[v] follows fail[u] until an edge on b exists, else root.
			f := ac.fail[u]
			for f != 0 {
				if _, ok := ac.next[f][b]; ok {
					break
				}
				f = ac.fail[f]
			}
			if nf, ok := ac.next[f][b]; ok && nf != v {
				ac.fail[v] = nf
			} else {
				ac.fail[v] = 0
			}
			// A match ending at fail[v] also ends at v, so inherit its outputs.
			ac.out[v] = append(ac.out[v], ac.out[ac.fail[v]]...)
			queue = append(queue, v)
		}
	}
}

// step advances the automaton one byte from state s, following failure
// links as needed, and returns the new state.
func (ac *Matcher) step(s int, b byte) int {
	for s != 0 {
		if nxt, ok := ac.next[s][b]; ok {
			return nxt
		}
		s = ac.fail[s]
	}
	if nxt, ok := ac.next[0][b]; ok {
		return nxt
	}
	return 0
}

// ScanInto runs the automaton over text and records every literal id found
// into present. The caller supplies present so one set can accumulate hits
// across several fields of the same event without reallocation.
func (ac *Matcher) ScanInto(text string, present map[int]struct{}) {
	if ac == nil || len(ac.next) <= 1 {
		return // no patterns compiled
	}
	s := 0
	for i := 0; i < len(text); i++ {
		s = ac.step(s, text[i])
		for _, id := range ac.out[s] {
			present[id] = struct{}{}
		}
	}
}
