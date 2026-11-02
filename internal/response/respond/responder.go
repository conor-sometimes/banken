// Package respond wires banken's response layer into the alert dispatch point:
// it is the alert.Responder that, for every dispatched alert, runs the pure
// decision (internal/response.Decide) against a loaded policy, records the
// verdict to the ledger, and -- when the policy decided a real action -- hands
// that action to the executor (internal/response/exec) and records the outcome.
//
// It sits ABOVE both layers on purpose: the decision layer stays pure and never
// imports the executor, and the executor never imports the alert stream; this
// orchestrator is the one place that depends on all three, so the dependency
// arrows below it never cross.
//
// # SAFETY: nothing here is armed by default
//
// Decide returns a real (non-none) Action only when the policy mode is enforce
// and every safety rail passed; in observe mode (the default) it returns none
// and this responder never calls the executor. Even when it does, the executor
// is a DRY-RUN unless it was built with Config.Enforce == true, which the NixOS
// module keeps false on every real host. The only configuration that both
// decides a kill AND performs it is the throwaway VM integration test. See
// docs/design/response-actions.md.
package respond

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/response"
	"github.com/conor-sometimes/banken/internal/response/exec"
)

// Responder implements alert.Responder. One instance serves one banken process;
// the dispatcher serialises Respond, but the mutex guards the run-local budget
// and dedupe state regardless.
type Responder struct {
	mu       sync.Mutex
	policy   response.Policy
	self     response.SelfIdentity
	exec     exec.Executor
	ledger   *response.Ledger
	version  string
	logf     func(string, ...any)
	seen     []response.Target
	runUsed  int
	hourUsed int
}

// New builds a responder over a loaded policy, an executor and a ledger. logf
// may be nil (a no-op is used); now may be nil (time.Now).
func New(p response.Policy, self response.SelfIdentity, ex exec.Executor, led *response.Ledger, version string, logf func(string, ...any)) *Responder {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Responder{
		policy:  p,
		self:    self,
		exec:    ex,
		ledger:  led,
		version: version,
		logf:    logf,
	}
}

// Respond runs for every dispatched alert. It never returns an error that
// should suppress the alert: a bug here is recovered and logged, because a
// response layer that can "error out" is one an attacker can make skip. It
// returns an error only to report a recovered panic to the dispatcher's error
// collection, which does not stop the sinks.
func (r *Responder) Respond(a alert.Alert) (retErr error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	defer func() {
		if rec := recover(); rec != nil {
			r.logf("response: recovered from panic in Respond: %v", rec)
			retErr = fmt.Errorf("response: panic in Respond: %v", rec)
		}
	}()

	in := response.Input{
		Alert:      a,
		Policy:     r.policy,
		Self:       r.self,
		KillSwitch: r.killSwitchPresent(),
		Budget:     response.Budget{RunUsed: r.runUsed, HourUsed: r.hourUsed},
		Seen:       append([]response.Target(nil), r.seen...),
	}
	d := response.Decide(in)

	decID, lerr := r.ledger.RecordDecision(a, d, r.policy.Hash(), r.policy.Mode, in.KillSwitch, r.version)
	if lerr != nil {
		// A decision we could not record must not then be acted on: an action
		// without a record is worse than no action. Stop here, report the write.
		r.logf("response: ledger write failed, not acting: %v", lerr)
		return lerr
	}

	// Record every matched target for run-local dedupe, acted or not.
	if d.Target.Process != nil || d.Target.File != nil {
		r.seen = append(r.seen, d.Target)
	}

	if d.Action == response.ActionNone {
		r.logf("response: %s -> %s (rail=%s): %s", a.Rule, d.Intended, d.Rail, d.Reason)
		return nil
	}

	// Committed to acting: count it toward the budget before the call so a
	// burst cannot outrun the limit even if a call blocks.
	r.runUsed++
	r.hourUsed++

	h, aerr := r.invoke(d)
	phase := "executed"
	errStr := ""
	if aerr != nil {
		phase = "failed"
		errStr = aerr.Error()
	}
	hi := handleInfo(h)
	if _, werr := r.ledger.RecordAction(a, d, phase, decID, r.exec.Enforcing(), hi, errStr, r.policy.Hash(), r.version); werr != nil {
		r.logf("response: action-ledger write failed: %v", werr)
	}

	gate := "dry-run"
	if r.exec.Enforcing() {
		gate = "ENFORCE"
	}
	if aerr != nil {
		r.logf("response: %s %s pid %d FAILED [%s]: %v", d.Action, d.Scope, targetPID(d), gate, aerr)
	} else {
		r.logf("response: %s %s pid %d -> handle %s [%s]", d.Action, d.Scope, targetPID(d), h.ID, gate)
	}
	return nil
}

// invoke dispatches a decided action to the executor. The decision layer has
// already guaranteed the target shape (a process ref for freeze/kill/collect, a
// file ref for quarantine), so a nil target here is a bug, surfaced as an error.
func (r *Responder) invoke(d response.Decision) (exec.Handle, error) {
	ctx := context.Background()
	switch d.Action {
	case response.ActionKill:
		if d.Target.Process == nil {
			return exec.Handle{}, errors.New("response: kill decision with no process target")
		}
		return r.exec.Kill(ctx, *d.Target.Process, d.Scope)
	case response.ActionFreeze:
		if d.Target.Process == nil {
			return exec.Handle{}, errors.New("response: freeze decision with no process target")
		}
		return r.exec.Freeze(ctx, *d.Target.Process, d.Scope)
	case response.ActionCollect:
		if d.Target.Process == nil {
			return exec.Handle{}, errors.New("response: collect decision with no process target")
		}
		return r.exec.Collect(ctx, *d.Target.Process)
	case response.ActionQuarantine:
		if d.Target.File == nil {
			return exec.Handle{}, errors.New("response: quarantine decision with no file target")
		}
		return r.exec.Quarantine(ctx, *d.Target.File)
	default:
		return exec.Handle{}, fmt.Errorf("response: unsupported action %q reached executor", d.Action)
	}
}

func (r *Responder) killSwitchPresent() bool {
	if r.policy.KillSwitchPath == "" {
		return false
	}
	_, err := os.Stat(r.policy.KillSwitchPath)
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

func targetPID(d response.Decision) int {
	if d.Target.Process != nil {
		return d.Target.Process.PID
	}
	return 0
}
