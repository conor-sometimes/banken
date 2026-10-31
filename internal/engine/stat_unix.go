//go:build unix

package engine

import (
	"os"
	"syscall"
)

// fileIno returns the inode number of a stat result on Unix, used to detect
// log rotation (a changed inode for the same path means the file was
// replaced). The bool is false if the platform stat does not expose it.
func fileIno(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Ino, true // ino_t is uint64 on the unix targets banken builds for
}
