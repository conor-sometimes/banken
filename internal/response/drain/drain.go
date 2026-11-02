// Package drain is the privileged half of banken's two-process response split:
// `banken respond drain` reads work orders the daemon wrote to the spool and is
// the trust boundary. For each order it loads the policy FROM DISK, re-runs the
// same pure Decide with its OWN fresh kill-switch/budget/seen state, and acts
// via the executor ONLY if its verdict equals the order's. An order can only
// ever LOWER an action, never raise it: a forged kill for a rule the policy
// maps to freeze (or to nothing) is downgraded, not honoured.
//
// This is the only package besides the operator undo commands that imports
// internal/response/exec. The daemon (the alert path, internal/response/respond)
// does not, so a compromised daemon cannot reach a primitive; its only lever is
// a JSON order re-decided here under rails it does not control. See
// docs/design/response-architecture.md §2.4.
package drain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/conor-sometimes/banken/internal/response"
	"github.com/conor-sometimes/banken/internal/response/exec"
)

// Phase names for the action ledger (the §2.4/§2.6 vocabulary). executed and
// failed come from the executor; the rest are the drain's own classifications.
const (
	phaseExecuted       = "executed"
	phaseFailed         = "failed"
	phaseExpired        = "expired"
	phaseDowngraded     = "downgraded"
	phaseAlreadyApplied = "already-applied"
)

// Notes qualify a failed/expired phase with a short machine-stable reason, so a
// reader classifies on the note, never by parsing the error string.
const (
	noteMalformed  = "malformed"
	noteKillSwitch = "kill-switch"
	noteExpired    = "expired"
)

// Options are the drain's injected dependencies. The real wiring (main's
// `banken respond drain`) builds them from banken.yml and the policy; the unit
// tests build them with a fake executor and a scratch spool/ledger. Everything
// the drain reads is here -- it keeps no hidden clock or global.
type Options struct {
	Spool    *response.Spool
	Policy   response.Policy
	Executor exec.Executor
	Ledger   *response.Ledger
	Self     response.SelfIdentity

	// Armed is the drain's response.enforce: the Armed input to Decide and the
	// executor's second belt. False means a drain run by hand on an unarmed host
	// re-decides to not-armed and writes no order outcome beyond that.
	Armed bool

	// MaxAge is response.spool.maxAge: an order older than this is expired and
	// unlinked, never acted on. The caller applies the 10m default.
	MaxAge time.Duration

	// QuarantineAllowPaths is response.quarantineAllowPaths from banken.yml: the
	// list the module also rendered into the helper unit's ReadWritePaths. Every
	// policy.Quarantine.AllowPaths entry must lie under one of these, else the
	// rename would fail with EROFS at the first real alert (silent disarm), so
	// the drain refuses at startup instead.
	QuarantineAllowPaths []string

	Version string
	Now     func() time.Time // injected clock; defaults to time.Now
	Logf    func(string, ...any)
}

func (o *Options) applyDefaults() {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
}

// applier is implemented by an executor that keeps an order-keyed store, so a
// replayed order (a crash between act and unlink, or an operator copying an
// order back in) is a no-op. The real store-backed executor gains this with the
// freeze/quarantine stores (build items 4-5); until then a drain over the plain
// executor simply re-dispatches, which is safe (kill/collect are idempotent on
// a gone pid, and the store-less actions have nothing to double-apply). The
// drain type-asserts rather than widening exec.Executor so the store lands with
// its own code, not here.
type applier interface {
	Applied(ctx context.Context, orderID string) (exec.Handle, bool, error)
}

// Run is the drain entry point: startup checks (fail closed), a sweep of
// abandoned tmp orders, then the order loop until the spool is empty. The only
// fatal error after startup is a failure to unlink a processed order (it cannot
// be made idempotent by force; the unit's StartLimitBurst stops the retry storm
// while the journal says why). Every other per-order problem is a ledger line
// and an unlink.
func Run(ctx context.Context, o Options) error {
	o.applyDefaults()

	// Startup: every policy quarantine path must lie under a sandbox path, or a
	// rename would EROFS at the first alert (the silent-disarm failure). Refuse
	// here, naming both, and touch nothing.
	for _, ap := range o.Policy.Quarantine.AllowPaths {
		if !underAny(o.QuarantineAllowPaths, ap) {
			return fmt.Errorf("drain: policy quarantine.allowPaths entry %q is not under any response.quarantineAllowPaths sandbox path %v; "+
				"the helper unit's ReadWritePaths would not let the rename succeed (fix the module or the policy)", ap, o.QuarantineAllowPaths)
		}
	}

	if swept, err := o.Spool.SweepTmp(o.MaxAge); err != nil {
		// A sweep error is worth the journal but not fatal: the abandoned tmp
		// order is retried next run and the real orders still drain.
		o.Logf("drain: sweep spool tmp: %v", err)
	} else if swept > 0 {
		o.Logf("drain: swept %d abandoned tmp order(s)", swept)
	}

	// The recovery pass over the stores (pending manifests, empty cgroups) lands
	// with the stores themselves (build item 4); it is intentionally absent here.

	st := &state{o: o}
	for {
		names, err := o.Spool.List()
		if err != nil {
			return fmt.Errorf("drain: %w", err)
		}
		if len(names) == 0 {
			return nil
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := st.one(ctx, name); err != nil {
				return err
			}
		}
	}
}

// state is the drain's run-local accounting: the budget and dedupe set the
// helper's own Decide consults (§2.4: "two counters, one authority" -- this is
// the authority within a run).
type state struct {
	o        Options
	seen     []response.Target
	runUsed  int
	hourUsed int
}

// one processes a single order: classify, re-decide, dispatch, record, unlink.
// It returns a non-nil error only for a fatal condition (an unreadable order
// file, or a failed unlink) that must stop the drain non-zero.
func (st *state) one(ctx context.Context, name string) error {
	o := st.o
	order, err := o.Spool.Read(name)
	if err != nil {
		if errors.Is(err, response.ErrMalformed) {
			id := strings.TrimSuffix(name, ".json")
			o.Logf("drain: order %s malformed: %v", id, err)
			st.record(response.ActionRecord{
				Phase:      phaseFailed,
				Note:       noteMalformed,
				DecisionID: id,
				Error:      err.Error(),
				Policy:     o.Policy.Hash(),
			})
			return o.Spool.Remove(name)
		}
		// A transient read fault (the file vanished, an I/O error): fail closed so
		// the unit's rate limit catches a persistent problem rather than silently
		// dropping an order.
		return fmt.Errorf("drain: read order %s: %w", name, err)
	}

	// Expired: older than maxAge. A kill landing this late is one the operator
	// did not expect; drop it (not a failure, an intended expiry).
	if o.Now().UTC().Sub(order.Time) > o.MaxAge {
		o.Logf("drain: order %s expired (age %s > %s)", order.ID, o.Now().UTC().Sub(order.Time).Round(time.Second), o.MaxAge)
		st.record(response.ActionRecord{
			Alert:       order.Alert,
			Phase:       phaseExpired,
			Note:        noteExpired,
			DecisionID:  order.ID,
			Action:      order.Decision.Action,
			Scope:       order.Decision.Scope,
			Target:      order.Decision.Target,
			Policy:      o.Policy.Hash(),
			OrderPolicy: order.Policy,
		})
		return o.Spool.Remove(name)
	}

	// Kill-switch: a fresh stat, the drain's own (the daemon never stat'ed this).
	if o.killSwitchPresent() {
		o.Logf("drain: order %s refused: kill-switch present (%s)", order.ID, o.Policy.KillSwitchPath)
		st.record(response.ActionRecord{
			Alert:       order.Alert,
			Phase:       phaseFailed,
			Note:        noteKillSwitch,
			DecisionID:  order.ID,
			Action:      order.Decision.Action,
			Scope:       order.Decision.Scope,
			Target:      order.Decision.Target,
			Error:       "kill-switch present: " + o.Policy.KillSwitchPath,
			Policy:      o.Policy.Hash(),
			OrderPolicy: order.Policy,
		})
		return o.Spool.Remove(name)
	}

	// Already-applied: a store entry whose manifest carries this order id makes a
	// replay a no-op (idempotent). Only a store-backed executor answers; see the
	// applier doc.
	if ap, ok := o.Executor.(applier); ok {
		if h, found, aerr := ap.Applied(ctx, order.ID); aerr != nil {
			o.Logf("drain: order %s store lookup: %v", order.ID, aerr)
		} else if found {
			o.Logf("drain: order %s already applied (handle %s)", order.ID, h.ID)
			st.record(response.ActionRecord{
				Alert:       order.Alert,
				Phase:       phaseAlreadyApplied,
				DecisionID:  order.ID,
				Action:      order.Decision.Action,
				Scope:       order.Decision.Scope,
				Target:      order.Decision.Target,
				Enforced:    o.Executor.Enforcing(),
				Handle:      handleInfo(h),
				Policy:      o.Policy.Hash(),
				OrderPolicy: order.Policy,
			})
			return o.Spool.Remove(name)
		}
	}

	// Re-decide from the order's alert against the policy FROM DISK, with the
	// drain's own fresh budget/seen/armed. The kill-switch was already checked
	// above (and classified distinctly), so it is not re-fed here.
	in := response.Input{
		Alert:      order.Alert,
		Policy:     o.Policy,
		Self:       o.Self,
		KillSwitch: false,
		Budget:     response.Budget{RunUsed: st.runUsed, HourUsed: st.hourUsed},
		Seen:       append([]response.Target(nil), st.seen...),
		Armed:      o.Armed,
	}
	d := response.Decide(in)
	if d.Target.Process != nil || d.Target.File != nil {
		st.seen = append(st.seen, d.Target)
	}

	// An order can only LOWER what happens, never raise it. If the helper's own
	// verdict is not the same action on the same target, it is downgraded and
	// unlinked without acting (the classic case: a forged kill for a rule the
	// policy maps to freeze or to nothing).
	if d.Action != order.Decision.Action || targetKey(d.Target) != targetKey(order.Decision.Target) {
		o.Logf("drain: order %s downgraded: requested %s, helper decided %s (rail=%s)", order.ID, order.Decision.Action, d.Action, d.Rail)
		st.record(response.ActionRecord{
			Alert:       order.Alert,
			Phase:       phaseDowngraded,
			DecisionID:  order.ID,
			Action:      d.Action,
			Requested:   order.Decision.Action,
			Scope:       order.Decision.Scope,
			Target:      order.Decision.Target,
			Error:       d.Reason,
			Policy:      o.Policy.Hash(),
			OrderPolicy: order.Policy,
		})
		return o.Spool.Remove(name)
	}

	// Verdicts agree: dispatch to the executor exactly as the daemon used to.
	h, aerr := st.dispatch(ctx, d)
	phase, errStr := phaseExecuted, ""
	if aerr != nil {
		phase, errStr = phaseFailed, aerr.Error()
	} else {
		st.runUsed++
		st.hourUsed++
	}
	st.record(response.ActionRecord{
		Alert:       order.Alert,
		Phase:       phase,
		DecisionID:  order.ID,
		Action:      d.Action,
		Scope:       d.Scope,
		Target:      d.Target,
		Enforced:    o.Executor.Enforcing(),
		Handle:      handleInfo(h),
		Live:        liveInfo(h),
		Error:       errStr,
		Policy:      o.Policy.Hash(),
		OrderPolicy: order.Policy,
	})
	if aerr != nil {
		o.Logf("drain: order %s %s FAILED: %v", order.ID, d.Action, aerr)
	} else {
		o.Logf("drain: order %s %s -> handle %s", order.ID, d.Action, h.ID)
	}
	return o.Spool.Remove(name)
}

// dispatch hands a decided action to the executor. The decision layer has
// already guaranteed the target shape, so a nil target here is a drain bug,
// surfaced as an error rather than a panic.
func (st *state) dispatch(ctx context.Context, d response.Decision) (exec.Handle, error) {
	ex := st.o.Executor
	switch d.Action {
	case response.ActionKill:
		if d.Target.Process == nil {
			return exec.Handle{}, errors.New("drain: kill decision with no process target")
		}
		return ex.Kill(ctx, *d.Target.Process, d.Scope)
	case response.ActionFreeze:
		if d.Target.Process == nil {
			return exec.Handle{}, errors.New("drain: freeze decision with no process target")
		}
		return ex.Freeze(ctx, *d.Target.Process, d.Scope)
	case response.ActionCollect:
		if d.Target.Process == nil {
			return exec.Handle{}, errors.New("drain: collect decision with no process target")
		}
		return ex.Collect(ctx, *d.Target.Process)
	case response.ActionQuarantine:
		if d.Target.File == nil {
			return exec.Handle{}, errors.New("drain: quarantine decision with no file target")
		}
		return ex.Quarantine(ctx, *d.Target.File)
	default:
		return exec.Handle{}, fmt.Errorf("drain: unsupported action %q reached the executor", d.Action)
	}
}

func (st *state) record(rec response.ActionRecord) {
	rec.Version = st.o.Version
	if _, err := st.o.Ledger.RecordAction(rec); err != nil {
		st.o.Logf("drain: action-ledger write failed: %v", err)
	}
}

func (o Options) killSwitchPresent() bool {
	if o.Policy.KillSwitchPath == "" {
		return false
	}
	_, err := os.Stat(o.Policy.KillSwitchPath)
	return err == nil
}

// handleInfo translates the executor's Handle into the ledger's plain-field
// HandleInfo, so internal/response never imports internal/response/exec.
func handleInfo(h exec.Handle) *response.HandleInfo {
	if h.ID == "" && h.Method == "" && h.PID == 0 {
		return nil
	}
	return &response.HandleInfo{
		ID:     h.ID,
		Kind:   h.Kind,
		PID:    h.PID,
		Method: h.Method,
		DryRun: h.DryRun,
		Undo:   h.Undo,
		Note:   h.Note,
	}
}

// liveInfo records the process identity the executor bound before acting (the
// exe it resolved, the start time it confirmed), from the returned handle, so
// the ledger records WHICH process was touched, not just its reusable pid. Nil
// for file actions and for a handle that carries no process identity.
func liveInfo(h exec.Handle) *response.LiveInfo {
	if h.Exe == "" && h.StartTime.IsZero() {
		return nil
	}
	return &response.LiveInfo{
		PID:       h.PID,
		Exe:       h.Exe,
		StartTime: h.StartTime,
	}
}

// targetKey mirrors the decision layer's dedupe key, so "same target" in the
// downgrade check means exactly what it means to Decide. (A duplicated small
// helper rather than exporting one from internal/response; build item 3
// consolidates the shared list/key helpers.)
func targetKey(t response.Target) string {
	if t.Process != nil {
		return fmt.Sprintf("p:%d:%s", t.Process.PID, t.Process.Image)
	}
	if t.File != nil {
		return "f:" + t.File.Path
	}
	return ""
}

// underAny reports whether path is at or under any of the given prefixes, by
// cleaned path-component prefix (so /tmpfoo is not under /tmp). The same shape
// as the decision layer's allowPaths check; build item 3 exports one copy.
func underAny(prefixes []string, path string) bool {
	clean := filepath.Clean(path)
	for _, p := range prefixes {
		p = filepath.Clean(p)
		if clean == p || strings.HasPrefix(clean, p+"/") {
			return true
		}
	}
	return false
}
