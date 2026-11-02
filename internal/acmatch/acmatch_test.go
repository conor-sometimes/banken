package acmatch

import (
	"sort"
	"testing"
)

func found(m *Matcher, text string) []int {
	present := map[int]struct{}{}
	m.ScanInto(text, present)
	ids := make([]int, 0, len(present))
	for id := range present {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func eq(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestScanInto(t *testing.T) {
	// id 0 "he", 1 "she", 2 "his", 3 "hers" -- the classic overlapping set,
	// which exercises the failure links and the merged outputs.
	m := New([][]byte{[]byte("he"), []byte("she"), []byte("his"), []byte("hers")})

	cases := []struct {
		text string
		want []int
	}{
		{"ushers", []int{0, 1, 3}}, // "she" (via u-s-h-e), "he", "hers"
		{"his", []int{2}},
		{"nothing here", []int{0}}, // "he" in "here"
		{"", nil},
		{"xyz", nil},
	}
	for _, c := range cases {
		if got := found(m, c.text); !eq(got, c.want) {
			t.Errorf("ScanInto(%q) = %v, want %v", c.text, got, c.want)
		}
	}
}

func TestScanIntoAccumulates(t *testing.T) {
	// present is supplied by the caller so hits accumulate across several pieces
	// of text, which is how both sigma and ioc scan an event's fields.
	m := New([][]byte{[]byte("alpha"), []byte("beta")})
	present := map[int]struct{}{}
	m.ScanInto("an alpha value", present)
	m.ScanInto("and a beta too", present)
	if _, ok := present[0]; !ok {
		t.Errorf("expected alpha (id 0) present after two scans")
	}
	if _, ok := present[1]; !ok {
		t.Errorf("expected beta (id 1) present after two scans")
	}
}

func TestEmptyPatternsSkipped(t *testing.T) {
	// An empty pattern keeps its id slot but is never fed to the trie, so it is
	// simply never reported; a non-empty pattern beside it still matches.
	m := New([][]byte{[]byte(""), []byte("mal")})
	if got := found(m, "a malware sample"); !eq(got, []int{1}) {
		t.Errorf("ScanInto with an empty pattern = %v, want [1]", got)
	}
}

func TestNoPatterns(t *testing.T) {
	if got := found(New(nil), "anything"); len(got) != 0 {
		t.Errorf("empty matcher found %v, want none", got)
	}
	var nilM *Matcher
	// A nil matcher is inert, never a panic.
	nilM.ScanInto("anything", map[int]struct{}{})
}
