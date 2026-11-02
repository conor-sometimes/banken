// Package exec is banken's response execution layer: the only package that
// can signal, freeze, kill, rename or neuter anything. It is imported by the
// drain, never by the decision layer (internal/response), so the pure
// decision cannot reach a destructive primitive even by accident.
//
// # SAFETY: real enforcement is DISABLED by default and is NOT armed anywhere
//
// Every Executor method is a DRY-RUN unless Config.Enforce is explicitly set
// true. In the default (zero-value) configuration NOTHING is killed, frozen,
// quarantined or neutered: the methods verify the target, log what they would
// do, and return a Handle marked DryRun. Real enforcement -- the actual
// pidfd_send_signal(SIGKILL), the cgroup freeze, the renameat2, the immutable
// bit -- happens only when Config.Enforce is true.
//
// Config.Enforce is OFF by default and this package does NOT turn it on
// anywhere: not in any constructor default, not in the NixOS module, and not
// in any test that runs against a process or file it does not itself own.
// Arming real enforcement is gated for Conor's design-session review; see
// docs/design/response-actions.md. Do not flip this default without that
// review.
//
// Tests exercise the executor in DRY-RUN, or against throwaway scratch that
// the test itself spawns and owns (a `sleep` child it then kills, a file it
// created under t.TempDir()), never against anything real.
package exec

import (
	"context"
	"errors"
	"time"

	"github.com/conor-sometimes/banken/internal/response"
)

var (
	// ErrStaleTarget means the live process is not the one the alert described
	// (the pid was reused, or the start-time/identity check failed). Refusing
	// is always preferred to acting on the wrong process.
	ErrStaleTarget = errors.New("exec: target is not the process the alert described")
	// ErrGone means the target already exited.
	ErrGone = errors.New("exec: target already exited")
	// ErrUnsupported means the primitive is not available on this platform or
	// kernel (e.g. any real enforcement on non-Linux).
	ErrUnsupported = errors.New("exec: not supported on this platform")
	// ErrDenied means a built-in or live safety rail refused the target.
	ErrDenied = errors.New("exec: target refused by a safety rail")
)

// Handle is what the ledger stores to describe and (where reversible) undo an
// action. Undo is opaque to everyone but the executor that wrote it.
type Handle struct {
	ID     string          `json:"id"`
	Kind   response.Action `json:"kind"`
	PID    int             `json:"pid,omitempty"`
	Method string          `json:"method,omitempty"` // cgroup|sigstop|pidfd|cgroup-kill|rename|neuter
	Undo   string          `json:"undo,omitempty"`   // executor-private handle for Thaw/Restore
	DryRun bool            `json:"dryRun"`           // true = NOTHING was actually done
	Note   string          `json:"note,omitempty"`
}

// Live is what Verify established about the process right now.
type Live struct {
	PID        int       `json:"pid"`
	StartTime  time.Time `json:"startTime,omitzero"`
	Exe        string    `json:"exe,omitempty"`
	CgroupPath string    `json:"cgroupPath,omitempty"`
}

// Executor performs one primitive. Every mutating method is a dry-run unless
// the executor was built with Config.Enforce == true. Methods are idempotent
// on their target where that is meaningful (freezing a frozen tree, killing a
// dead pid), so a crashed-and-rerun drain is safe.
type Executor interface {
	// Enforcing reports whether this executor will perform REAL actions. False
	// means every mutating call is a dry-run. The drain logs this loudly.
	Enforcing() bool

	// Verify re-identifies the process (pidfd + start-time, no action) and is
	// always real and read-only, so `respond explain` can show the target even
	// in dry-run.
	Verify(ctx context.Context, p response.ProcessRef) (Live, error)

	Freeze(ctx context.Context, p response.ProcessRef, scope response.Scope) (Handle, error)
	Thaw(ctx context.Context, h Handle) error

	Kill(ctx context.Context, p response.ProcessRef, scope response.Scope) (Handle, error)

	Quarantine(ctx context.Context, f response.FileRef) (Handle, error)
	Restore(ctx context.Context, h Handle) error

	Collect(ctx context.Context, p response.ProcessRef) (Handle, error)
}

// Config configures a platform executor.
type Config struct {
	// Enforce, when true, ARMS real enforcement. The zero value is false: a
	// dry-run executor that performs no real action. See the package doc.
	Enforce bool

	// CgroupRoot is the cgroup v2 directory under which frozen/kill trees get
	// their own child cgroup. Default "/sys/fs/cgroup/banken.quarantine".
	CgroupRoot string
	// QuarantineDir is where quarantined files are moved. Default
	// "/var/lib/banken/quarantine".
	QuarantineDir string
	// EvidenceDir is where collect writes snapshots. Default
	// "/var/lib/banken/evidence".
	EvidenceDir string
	// QuarantineAllowPaths is the executor-side re-check of which paths may be
	// quarantined (the decision layer checks this too; the executor checks the
	// live path). Empty means refuse every quarantine.
	QuarantineAllowPaths []string
	// SkewTolerance bounds the start-time check for sources that carry no
	// process start time (auditd/Laurel): a live process whose start time is
	// after EventTime+SkewTolerance is a reuser and is refused. Default 2s.
	SkewTolerance time.Duration
	// Logf logs what the executor does (and, in dry-run, what it would do).
	// Defaults to a no-op.
	Logf func(format string, args ...any)
}

func (c Config) withDefaults() Config {
	if c.CgroupRoot == "" {
		c.CgroupRoot = "/sys/fs/cgroup/banken.quarantine"
	}
	if c.QuarantineDir == "" {
		c.QuarantineDir = "/var/lib/banken/quarantine"
	}
	if c.EvidenceDir == "" {
		c.EvidenceDir = "/var/lib/banken/evidence"
	}
	if c.SkewTolerance == 0 {
		c.SkewTolerance = 2 * time.Second
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	return c
}

// New returns the platform executor. With Config.Enforce false (the default)
// it returns a dry-run executor on every platform. With Config.Enforce true
// it returns the real executor on Linux and ErrUnsupported elsewhere.
func New(cfg Config) (Executor, error) {
	return newExecutor(cfg.withDefaults())
}
