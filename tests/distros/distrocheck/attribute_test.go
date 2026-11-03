package main

import (
	"sort"
	"testing"
)

// TestDescendants builds a process tree and checks the launcher subtree is
// exactly the launcher plus everything under it, and nothing that runs beside
// it. This is the core of identity-based B1 attribution: a periodic daemon that
// fires inside a family's scan window must NOT be in that family's subtree.
func TestDescendants(t *testing.T) {
	// A family launcher (100) runs: bash (101) -> its emulation's touch (102)
	// and a grandchild rm (103). Beside it, cron (900) spawns a dash (901) that
	// reads a credential file -- the classic bleed. systemd (1) is the root.
	ppidOf := map[int]int{
		100: 1,   // runuser (the launcher)
		101: 100, // bash running the family script
		102: 101, // touch
		103: 102, // rm (grandchild)
		900: 1,   // cron, beside the family
		901: 900, // dash spawned by cron
	}
	got := descendants(ppidOf, 100)

	want := []int{100, 101, 102, 103}
	var keys []int
	for p := range got {
		keys = append(keys, p)
	}
	sort.Ints(keys)
	if len(keys) != len(want) {
		t.Fatalf("subtree = %v, want %v", keys, want)
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("subtree missing %d", w)
		}
	}
	for _, bled := range []int{900, 901, 1} {
		if got[bled] {
			t.Errorf("subtree wrongly includes %d (a process beside the family)", bled)
		}
	}
}

// TestInSubtree is the attribution decision: an alert is the family's iff its
// evidence process (by pid, or by ppid for a short-lived exec) is in the
// subtree. The cron-bled alert is rejected by identity, no timing involved.
func TestInSubtree(t *testing.T) {
	subtree := map[int]bool{100: true, 101: true, 102: true, 103: true}
	cases := []struct {
		name      string
		pid, ppid int
		want      bool
	}{
		{"family exec by pid", 102, 101, true},
		{"family grandchild by pid", 103, 102, true},
		{"the launcher itself", 100, 1, true},
		{"short-lived family exec, only ppid resolves", 0, 101, true},
		{"cron-bled alert (different subtree)", 901, 900, false},
		{"cron itself", 900, 1, false},
		{"unrecorded process (pid and ppid 0)", 0, 0, false},
		{"straggler whose pid happens to be high but ppid is cron", 999, 900, false},
	}
	for _, c := range cases {
		if got := inSubtree(subtree, c.pid, c.ppid); got != c.want {
			t.Errorf("%s: inSubtree(pid=%d, ppid=%d) = %v, want %v", c.name, c.pid, c.ppid, got, c.want)
		}
	}
}

// TestAttributionIsOrderIndependent is the whole point: the same audit records
// in any flush order produce the same attribution, because it is by parentage,
// not by when the record appeared. A shuffled ppid map must give the same
// subtree as the in-order one.
func TestAttributionIsOrderIndependent(t *testing.T) {
	inOrder := map[int]int{100: 1, 101: 100, 102: 101, 103: 102}
	// Same edges, inserted/observed in a different order (maps are unordered in
	// Go anyway; this asserts the algorithm does not depend on insertion order).
	shuffled := map[int]int{103: 102, 101: 100, 102: 101, 100: 1}

	a := descendants(inOrder, 100)
	b := descendants(shuffled, 100)
	if len(a) != len(b) {
		t.Fatalf("subtree size differs by order: %d vs %d", len(a), len(b))
	}
	for p := range a {
		if !b[p] {
			t.Errorf("subtree differs by order at %d", p)
		}
	}
}
