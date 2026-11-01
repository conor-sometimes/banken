//go:build !linux

package engine

import (
	"context"
	"time"
)

// watcher is the non-Linux fallback: it polls on a short interval (there is no inotify). banken runs
// on Linux in practice (it reads auditd), so this exists to keep the package building and testable
// elsewhere; the latency is then bounded by the poll interval rather than event-driven.
type watcher struct{}

func newWatcher(string) (*watcher, error) { return &watcher{}, nil }

func (w *watcher) wait(ctx context.Context) error {
	t := time.NewTimer(100 * time.Millisecond)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (w *watcher) close() {}
