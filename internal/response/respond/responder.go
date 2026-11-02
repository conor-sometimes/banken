// Package respond wires banken's response layer into the alert dispatch point:
// it is the alert.Responder that, for every dispatched alert, runs the pure
// decision (internal/response.Decide) against a loaded policy, records the
// verdict to the ledger, and -- when the policy decided a real action -- writes
// a work order to the spool. It never acts: after the two-process split the
// only way an action reaches a primitive is a work order the privileged drain
// re-decides and executes in its own process (docs/design/response-architecture.md).
//
// This package deliberately does NOT import internal/response/exec. The daemon
// process holds no capability to kill, freeze, quarantine or neuter; its one
// lever on the drain is a JSON file the drain re-decides under the same rails.
// A compromised daemon can request only an action the policy already allows
// against a target the rails already allow, and that request is on the ledger.
//
// # SAFETY: nothing here is armed, and nothing here acts
//
// Decide returns a real (non-none) Action only when the policy mode is enforce,
// every safety rail passed, AND the responder was built armed (response.enforce
// on). In observe mode, or on a host that has not armed enforcement, Decide
// rails (observe-mode / not-armed) and no order is written. Even when an order
// IS written, nothing happens until the drain runs, and the drain is a dry-run
// unless its own executor was armed. The three gates (response.enable, policy
// mode:enforce, response.enforce) are all off by default.
package respond

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/response"
)

// Responder implements alert.Responder. One instance serves one banken process;
// the dispatcher serialises Respond, but the mutex guards the run-local budget
// and dedupe state regardless.
type Responder struct {
	mu       sync.Mutex
	policy   response.Policy
	self     response.SelfIdentity
	spool    *response.Spool
	ledger   *response.Ledger
	armed    bool // response.enforce: the Armed input to Decide
	version  string
	now      func() time.Time
	logf     func(string, ...any)
	seen     []response.Target
	runUsed  int
	hourUsed int
}

// New builds a responder over a loaded policy, a spool and a ledger. armed is
// the caller's response.enforce (Decide's Armed input): false means the host
// has not armed enforcement, so an enforce-mode decision rails as not-armed and
// no order is written. logf may be nil (a no-op is used).
func New(p response.Policy, self response.SelfIdentity, spool *response.Spool, led *response.Ledger, armed bool, version string, logf func(string, ...any)) *Responder {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Responder{
		policy:  p,
		self:    self,
		spool:   spool,
		ledger:  led,
		armed:   armed,
		version: version,
		now:     time.Now,
		logf:    logf,
	}
}

// Respond runs for every dispatched alert. It never returns an error that
// should suppress the alert: a bug here is recovered and logged, because a
// response layer that can "error out" is one an attacker can make skip. It
// returns an error only to report a recovered panic or a ledger/spool write
// failure to the dispatcher's error collection, which does not stop the sinks.
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
		Armed:      r.armed,
	}
	d := response.Decide(in)

	decID, lerr := r.ledger.RecordDecision(a, d, r.policy.Hash(), r.policy.Mode, in.KillSwitch, r.version)
	if lerr != nil {
		// A decision we could not record must not then be acted on: an action
		// without a record is worse than no action. Stop here (no order), report
		// the write. This is what guarantees a ledger failure writes NO order.
		r.logf("response: ledger write failed, no order written: %v", lerr)
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

	// Committed to requesting the action: count it toward the run-local budget
	// before the write so a burst cannot outrun the limit. The drain's own count
	// from the ledger is the one that binds; this run-local pair exists to avoid
	// writing duplicate orders within one scan (§2.4).
	r.runUsed++
	r.hourUsed++

	order := response.Order{
		Version:  response.OrderVersion,
		ID:       decID,
		Time:     r.now().UTC(),
		Alert:    a,
		Decision: d,
		Policy:   r.policy.Hash(),
		Banken:   r.version,
	}
	if werr := r.spool.Write(order); werr != nil {
		// The decision is on the ledger; the order could not be written. Surface
		// it (the dispatcher collects it; the sinks still fire). `respond explain`
		// will show this decision as "never requested".
		r.logf("response: spool write failed for decision %s, no order: %v", decID, werr)
		return werr
	}
	r.logf("response: %s %s pid %d -> order %s (drain will decide)", d.Action, d.Scope, targetPID(d), decID)
	return nil
}

func (r *Responder) killSwitchPresent() bool {
	if r.policy.KillSwitchPath == "" {
		return false
	}
	_, err := os.Stat(r.policy.KillSwitchPath)
	return err == nil
}

func targetPID(d response.Decision) int {
	if d.Target.Process != nil {
		return d.Target.Process.PID
	}
	return 0
}
