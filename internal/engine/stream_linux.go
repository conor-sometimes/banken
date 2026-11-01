//go:build linux

package engine

import (
	"context"
	"path/filepath"
	"sync"
	"syscall"
)

// watcher blocks until a followed file changes, using inotify, so StreamFollow reacts to a write
// rather than polling on an interval. It watches the file for appends and its directory for a
// same-name replacement (log rotation), the two ways mimi's sink grows.
type watcher struct {
	fd   int
	once sync.Once
}

func newWatcher(path string) (*watcher, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	// The file: appends and close-after-write; moves/deletes of the file itself (rotation).
	_, _ = syscall.InotifyAddWatch(fd, path,
		syscall.IN_MODIFY|syscall.IN_CLOSE_WRITE|syscall.IN_MOVE_SELF|syscall.IN_DELETE_SELF)
	// The directory: a new file arriving under the same name after rotation.
	if dir := filepath.Dir(path); dir != "" && dir != path {
		_, _ = syscall.InotifyAddWatch(fd, dir, syscall.IN_CREATE|syscall.IN_MOVED_TO)
	}
	return &watcher{fd: fd}, nil
}

// wait blocks until the watched path reports a change, or ctx is cancelled. Cancellation closes the
// inotify fd, which unblocks the read.
func (w *watcher) wait(ctx context.Context) error {
	stop := context.AfterFunc(ctx, w.closeFd)
	defer stop()
	buf := make([]byte, 4096)
	for {
		_, err := syscall.Read(w.fd, buf)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == syscall.EINTR {
			continue
		}
		return err // nil on a real event (caller drains), or a genuine error
	}
}

func (w *watcher) close()   { w.closeFd() }
func (w *watcher) closeFd() { w.once.Do(func() { _ = syscall.Close(w.fd) }) }
