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

	// Exe and StartTime are the verified process identity the executor bound to
	// before acting (the exe it resolved and start time it confirmed in §5.1).
	// They are ledgered so the chain of custody records WHICH process was
	// touched, not just its (reusable) pid. Empty/zero for file actions.
	Exe       string    `json:"exe,omitempty"`
	StartTime time.Time `json:"startTime,omitzero"`
}

// Live is what Verify established about the process right now.
type Live struct {
	PID        int       `json:"pid"`
	StartTime  time.Time `json:"startTime,omitzero"`
	Exe        string    `json:"exe,omitempty"`
	CgroupPath string    `json:"cgroupPath,omitempty"`
	UID        int       `json:"uid"`
	// Masquerade is true when the live exe carries a built-in protected NAME
	// but its realpath is not under a trusted system prefix: the name-based
	// shield is deliberately NOT applied, so the process stays actionable.
	Masquerade bool `json:"masquerade,omitempty"`
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
	// Restore reverses a quarantine from its store entry. to is the operator's
	// -to destination (empty = the manifest's original path); a non-empty to is
	// bounded by the same allowPaths/never-touch lists the forward path uses and
	// may not land under the store. The entry is KEPT and a tombstone written, so
	// a second restore is a clean no-op (Q3).
	Restore(ctx context.Context, h Handle, to string) error

	Collect(ctx context.Context, p response.ProcessRef) (Handle, error)
}

// RecoveryResult is one repair a store-backed executor's startup recovery pass
// made (a pending manifest finalised or rolled back, a leaked cgroup dir
// removed), for the drain to record as a `recovered` ledger line. It is defined
// here (not in the Linux file) so the drain's recoverer interface is one shape
// on every platform.
type RecoveryResult struct {
	ID      string
	Order   string
	Kind    response.Action
	Outcome string // finalised | rolled-back | cgroup-removed
}

// Config configures a platform executor.
type Config struct {
	// Enforce, when true, ARMS real enforcement. The zero value is false: a
	// dry-run executor that performs no real action. See the package doc.
	Enforce bool

	// AllowRoot, when false (the default), makes the executor refuse to act on
	// a process whose LIVE uid is 0 -- the live-rail mirror of the decision
	// layer's allowRoot gate (Policy.AllowRoot). The caller sets it from the
	// policy. Fail-closed: a target whose uid cannot be read is refused too.
	AllowRoot bool

	// CgroupRoot is the cgroup v2 directory under which frozen/kill trees get
	// their own child cgroup. Default "/sys/fs/cgroup/banken.quarantine".
	CgroupRoot string
	// FreezeDir is the freeze store: one directory per freeze handle, each with
	// a manifest.json (the pids, their original cgroups, the idempotency order
	// id) written before migration and a thawed.json tombstone on undo. Thaw
	// works from this store alone. Default "/var/lib/banken/freeze".
	FreezeDir string
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
	// MaxFileBytes bounds the sha256 of a quarantined file (and the later YARA
	// scan), never the rename/neuter: over the cap the file is still taken but
	// its hash is recorded "unhashed" and YARA skipped, so a 1 TiB sparse file
	// or a hung mount cannot block the drain. The caller sets it from
	// Policy.Quarantine.MaxFileBytes; the default is 256 MiB.
	MaxFileBytes int64
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
	if c.FreezeDir == "" {
		c.FreezeDir = "/var/lib/banken/freeze"
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
	if c.MaxFileBytes == 0 {
		// 256 MiB, mirroring Policy.Quarantine.MaxFileBytes's default so a
		// directly-built executor (a test, an operator undo) caps the same way.
		c.MaxFileBytes = 268435456
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

// orOrig renders a restore destination for a log line: the -to path, or
// "original path" when none was given. Platform-neutral so both the real and
// the dry-run executors share one wording.
func orOrig(to string) string {
	if to == "" {
		return "original path"
	}
	return to
}

// orderIDCtxKey is the context key under which the drain carries the work order
// id into a store-backed call.
type orderIDCtxKey struct{}

// WithOrderID returns a context carrying the work order id for a single
// store-backed call. The store-backed executor stamps it into the manifest it
// writes, so a replayed order is matched by its id and the drain records
// already-applied instead of acting twice (the idempotency key of
// docs/design/response-architecture.md section 2.7). It is request-scoped
// metadata -- one order id per Freeze/Collect call -- which is exactly what a
// context value is for; the executor interface stays a clean verb-per-method
// shape rather than growing an id parameter every method must thread. A call
// made without it (an operator-driven Thaw, a test) simply writes no order id,
// and such an entry is never matched as already-applied.
func WithOrderID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, orderIDCtxKey{}, id)
}

// orderIDFromContext returns the work order id carried by WithOrderID, or "".
func orderIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(orderIDCtxKey{}).(string)
	return id
}
