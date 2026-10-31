package sigma

// acMatcher is a byte-level Aho-Corasick automaton: built once from every
// string literal across every rule, it finds all literals present in a
// piece of text in a single O(len(text)) pass, no matter how many literals
// were compiled in. That is what lets the rule count grow without the
// per-event cost growing with it -- see matcher.go for how the found set
// gates which rules are evaluated.
//
// It carries no detection logic of its own: it answers only "which of these
// literals occur in this text", and the authoritative Rule.Match decides
// whether a rule actually fires. A bug here can at worst cause a rule to be
// evaluated that would not match (wasted work) -- never a missed match --
// because the set it returns is always a superset of the true literals
// (proof in matcher.go).
type acMatcher struct {
	next []map[byte]int // goto edges per node; node 0 is the root
	fail []int          // failure links
	out  [][]int        // literal ids whose pattern ends at (or via) this node
}

// newACMatcher builds an automaton over the given patterns. Each pattern's
// index in the slice is the literal id reported for it; patterns must be
// non-empty and already folded to the casing used at scan time. Duplicate
// patterns are allowed (each keeps its own id).
func newACMatcher(patterns [][]byte) *acMatcher {
	ac := &acMatcher{
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

func (ac *acMatcher) add(pat []byte, id int) {
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
func (ac *acMatcher) buildFail() {
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
func (ac *acMatcher) step(s int, b byte) int {
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

// scanInto runs the automaton over text and records every literal id found
// into present. The caller supplies present so one set can accumulate hits
// across several fields of the same event without reallocation.
func (ac *acMatcher) scanInto(text string, present map[int]struct{}) {
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
