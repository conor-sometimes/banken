//go:build !linux

package exec

import (
	"context"

	"github.com/conor-sometimes/banken/internal/response"
)

// newExecutor on a non-Linux platform: a dry-run executor is always available
// (so `go test ./...` and `respond explain` work on a Mac), but arming real
// enforcement is unsupported -- there is no pidfd, cgroup freezer or
// renameat2 here.
func newExecutor(cfg Config) (Executor, error) {
	if cfg.Enforce {
		return nil, ErrUnsupported
	}
	return dryRun{cfg: cfg}, nil
}

// dryRun performs nothing and reports DryRun on every handle. It exists only
// off Linux; on Linux the real executor honours dry-run itself (so Verify can
// still read /proc truthfully), see exec_linux.go.
type dryRun struct{ cfg Config }

func (dryRun) Enforcing() bool { return false }

func (d dryRun) Verify(_ context.Context, p response.ProcessRef) (Live, error) {
	d.cfg.Logf("response/exec: DRY-RUN verify pid %d (%s) [non-Linux: no /proc]", p.PID, p.Image)
	return Live{PID: p.PID}, nil
}

func (d dryRun) Freeze(_ context.Context, p response.ProcessRef, scope response.Scope) (Handle, error) {
	d.cfg.Logf("response/exec: DRY-RUN would freeze %s pid %d (%s)", scope, p.PID, p.Image)
	return Handle{Kind: response.ActionFreeze, PID: p.PID, DryRun: true, Method: "dry-run"}, nil
}

func (d dryRun) Thaw(_ context.Context, h Handle) error {
	d.cfg.Logf("response/exec: DRY-RUN would thaw %s", h.ID)
	return nil
}

func (d dryRun) Kill(_ context.Context, p response.ProcessRef, scope response.Scope) (Handle, error) {
	d.cfg.Logf("response/exec: DRY-RUN would kill %s pid %d (%s)", scope, p.PID, p.Image)
	return Handle{Kind: response.ActionKill, PID: p.PID, DryRun: true, Method: "dry-run"}, nil
}

func (d dryRun) Quarantine(_ context.Context, f response.FileRef) (Handle, error) {
	d.cfg.Logf("response/exec: DRY-RUN would quarantine %s", f.Path)
	return Handle{Kind: response.ActionQuarantine, DryRun: true, Method: "dry-run"}, nil
}

func (d dryRun) Restore(_ context.Context, h Handle, to string) error {
	d.cfg.Logf("response/exec: DRY-RUN would restore %s to %s", h.ID, orOrig(to))
	return nil
}

func (d dryRun) Collect(_ context.Context, p response.ProcessRef) (Handle, error) {
	d.cfg.Logf("response/exec: DRY-RUN would collect evidence for pid %d (%s)", p.PID, p.Image)
	return Handle{Kind: response.ActionCollect, PID: p.PID, DryRun: true, Method: "dry-run"}, nil
}
