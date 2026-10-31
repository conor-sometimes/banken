//go:build !unix

package engine

import "os"

// fileIno has no portable inode on non-Unix platforms, so rotation detection
// there falls back to the size heuristic in OpenAt. Returning false keeps the
// code compiling everywhere without a syscall dependency.
func fileIno(os.FileInfo) (uint64, bool) { return 0, false }
