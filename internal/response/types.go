// Package response is banken's response-decision layer: it turns an alert
// plus an operator policy into a decided action (freeze, kill, quarantine,
// ...) without ever performing it. The decision is a pure function --
// Decide(Input) Decision -- with no clock, no filesystem, no /proc and no
// globals, so "would this alert kill a process?" is as testable as "does
// this event fire a rule?": same input, same output, forever, and no real
// process is ever touched.
//
// Nothing in this package acts. It decides, and (through Ledger) records.
// The execution of a decided action lives in internal/response/exec, which
// this package deliberately does not import: the dependency arrow points
// only the other way, so the decision layer cannot reach a destructive
// primitive even by accident. See docs/design/response-actions.md.
package response

import (
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
)

// Action is what a policy entry can ask for. The policy loader rejects any
// action string outside this set, and rejects the reserved ones
// (ActionIsolate) with a clear "not implemented" error rather than silently
// accepting them.
type Action string

const (
	ActionNone       Action = "none"
	ActionFreeze     Action = "freeze"     // reversible: cgroup v2 freezer / SIGSTOP fallback
	ActionKill       Action = "kill"       // destructive: pidfd_send_signal(SIGKILL) / cgroup.kill
	ActionQuarantine Action = "quarantine" // reversible: renameat2 into quarantine dir, or in-place neuter
	ActionCollect    Action = "collect"    // non-destructive: snapshot /proc + exe hash
	ActionIsolate    Action = "isolate"    // reserved (later phase): per-cgroup nft egress drop
)

// Rail names the safety rail that downgraded Intended to Action. Empty means
// no rail fired (an enforce-mode action that will actually happen once the
// executor is armed). Every rail is a string so it lands in the ledger and
// in a test's expectation verbatim.
type Rail string

const (
	RailNone            Rail = ""
	RailNoPolicyMatch   Rail = "no-policy-match"
	RailBelowMinLevel   Rail = "below-min-level"
	RailUntrustedSource Rail = "untrusted-source"
	RailUntargetable    Rail = "untargetable"
	RailDenylist        Rail = "denylist"
	RailDuplicate       Rail = "duplicate"
	RailRateLimit       Rail = "rate-limit"
	RailKillSwitch      Rail = "kill-switch"
	RailObserve         Rail = "observe-mode"
)

// Scope selects whether a process action targets just the process or the
// whole descendant tree. It is carried in the Decision and honoured by the
// executor; the decision layer only records it.
type Scope string

const (
	ScopeProcess Scope = "process"
	ScopeTree    Scope = "tree"
)

// ProcessRef is the identity the executor must re-verify before acting. The
// pid alone is never enough: by the time a response runs the pid may name a
// different process, so the executor pairs it with the start time (or, when
// the source carries none, the event time as an upper bound). See
// docs/design/response-actions.md section 5.1.
type ProcessRef struct {
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid,omitempty"`
	StartTime time.Time `json:"startTime,omitzero"` // zero = unknown (auditd/Laurel)
	Image     string    `json:"image"`
	User      string    `json:"user,omitempty"`
	EventTime time.Time `json:"eventTime,omitzero"` // upper bound on StartTime when unknown
}

// FileRef is a file target, as the event saw the path. The executor opens it
// O_NOFOLLOW and acts on the fd, never on a re-resolved path.
type FileRef struct {
	Path string `json:"path"`
}

// Target is what a decision acts on: exactly one of a process or a file,
// depending on the action.
type Target struct {
	Process *ProcessRef `json:"process,omitempty"`
	File    *FileRef    `json:"file,omitempty"`
}

// Budget is the rate-limit state the caller has already accumulated. It is an
// input, not hidden state, so Decide stays pure: the caller counts from the
// ledger and passes the totals in.
type Budget struct {
	RunUsed   int `json:"runUsed"`
	RunLimit  int `json:"runLimit"`
	HourUsed  int `json:"hourUsed"`
	HourLimit int `json:"hourLimit"`
}

// SelfIdentity is banken's own realpath, for the denylist (never act on the
// responder or scanner itself).
type SelfIdentity struct {
	Exe string `json:"exe"`
}

// Input is everything Decide looks at. Nothing else is read -- no clock, no
// filesystem -- which is what makes the decision reproducible from a fixture.
type Input struct {
	Alert      alert.Alert  `json:"alert"`
	Policy     Policy       `json:"-"`
	Self       SelfIdentity `json:"self"`
	KillSwitch bool         `json:"killSwitch"` // the caller stat'ed Policy.KillSwitchPath
	Budget     Budget       `json:"budget"`
	Seen       []Target     `json:"seen"` // targets already decided this run (dedupe)
}

// Decision is the whole verdict. Intended is what the policy asked for before
// any rail; Action is what will happen. In observe mode (and whenever a rail
// fires) they differ on purpose, and the ledger records both so an operator
// can see exactly what an enforce flip would have done.
type Decision struct {
	Intended Action `json:"intended"`
	Action   Action `json:"action"`
	Rail     Rail   `json:"rail,omitempty"`
	Reason   string `json:"reason"`
	Entry    string `json:"entry,omitempty"` // policy entry name that matched
	Target   Target `json:"target"`
	Scope    Scope  `json:"scope,omitempty"`
}
