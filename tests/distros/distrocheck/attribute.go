package main

// Identity-based attribution for the detection matrix (B1).
//
// The old method scored a family by diffing the shared alert sink across a
// wall-clock window: run the family, scan, and blame it for any alert that
// appeared since the last scan. auditd flushes records asynchronously and can
// complete them out of order, so one family's exec bleeds into the next
// family's window. The sleeps, the quiescence drain and the daemon-masking all
// just lowered that probability; they could not remove it.
//
// This attributes by IDENTITY instead. Every family runs under its own launcher
// process (runuser -> bash). Every exec auditd records carries pid and ppid, and
// every banken alert's evidence carries the triggering process's pid and its
// parent's pid. So an alert belongs to a family if and only if its process is in
// that family's launcher subtree. A periodic daemon (cron, fwupd) runs under a
// different subtree and is simply not attributed to any family - no masking, no
// settle, no drain. Async flush cannot change a process's parentage.

// descendants returns the launcher and every process whose parent chain reaches
// it, from a pid -> ppid map built from the window's audit EXECVE/SYSCALL
// records. The launcher itself is included so a direct child of it attributes.
func descendants(ppidOf map[int]int, launcher int) map[int]bool {
	children := make(map[int][]int, len(ppidOf))
	for pid, ppid := range ppidOf {
		children[ppid] = append(children[ppid], pid)
	}
	seen := map[int]bool{launcher: true}
	stack := []int{launcher}
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, c := range children[p] {
			if !seen[c] {
				seen[c] = true
				stack = append(stack, c)
			}
		}
	}
	return seen
}

// inSubtree reports whether an alert whose evidence process has the given pid
// and ppid belongs to the family subtree. The pid is checked first; ppid is the
// fallback for a short-lived exec that had already exited (so only its parent is
// still resolvable in the tree). A pid of 0 means "not recorded" and never
// matches.
func inSubtree(subtree map[int]bool, pid, ppid int) bool {
	if pid > 0 && subtree[pid] {
		return true
	}
	if ppid > 0 && subtree[ppid] {
		return true
	}
	return false
}
