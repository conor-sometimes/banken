//go:build linux && amd64

package exec

// renameat2 has an arch-specific syscall number (unlike the pidfd calls,
// which are on the generic table and share a number across arches). x86_64.
const sysRenameat2 = 316
