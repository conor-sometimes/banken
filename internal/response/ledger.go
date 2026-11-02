package response

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
)

const ledgerDayLayout = "2006-01-02"

// Ledger is the append-only chain of custody for the decision layer: every
// Decide, observe mode included, is one JSON line in a per-day file so the
// scan and (later) the executor never interleave writes to one file. This
// is a recording component, not part of Decide -- Decide itself has no side
// effects; the caller records its verdict here.
//
// Retention is keep-forever: these lines are the undo handles and the
// evidence for "why did you touch my process".
type Ledger struct {
	mu  sync.Mutex
	dir string
	now func() time.Time
}

// NewLedger opens (creating if needed) the ledger directory.
func NewLedger(dir string) (*Ledger, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("response: create ledger dir: %w", err)
	}
	return &Ledger{dir: dir, now: time.Now}, nil
}

// decisionLine is one "decided" ledger record. It carries a compact summary
// of the alert (not the whole event) plus the full decision, the policy hash
// and the run context, so a line is self-contained.
type decisionLine struct {
	ID         string       `json:"id"`
	Time       time.Time    `json:"time"`
	Phase      string       `json:"phase"` // always "decided" for this layer
	Alert      alertSummary `json:"alert"`
	Decision   Decision     `json:"decision"`
	Policy     string       `json:"policy"` // policy hash
	Mode       Mode         `json:"mode"`
	KillSwitch bool         `json:"killSwitch"`
	Banken     string       `json:"banken,omitempty"` // binary version
}

type alertSummary struct {
	Rule    string    `json:"rule"`
	RuleID  string    `json:"ruleId,omitempty"`
	Level   string    `json:"level"`
	Source  string    `json:"source"`
	Time    time.Time `json:"time,omitzero"`
	Image   string    `json:"image,omitempty"`
	CmdLine string    `json:"commandLine,omitempty"`
	User    string    `json:"user,omitempty"`
	Tags    []string  `json:"tags,omitempty"`
}

// RecordDecision appends one "decided" line and returns its id. A write
// failure is returned, never fatal to the caller, but a caller that could
// not record a decision must not then act on it: an action without a record
// is worse than no action.
func (l *Ledger) RecordDecision(a alert.Alert, d Decision, policyHash string, mode Mode, killSwitch bool, version string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	id := newID(now)
	line := decisionLine{
		ID:    id,
		Time:  now.UTC(),
		Phase: "decided",
		Alert: alertSummary{
			Rule:    a.Rule,
			RuleID:  a.RuleID,
			Level:   a.Level,
			Source:  a.Source,
			Time:    a.Time,
			Image:   a.Event.Image,
			CmdLine: a.Event.CommandLine,
			User:    a.Event.User,
			Tags:    a.Tags,
		},
		Decision:   d,
		Policy:     policyHash,
		Mode:       mode,
		KillSwitch: killSwitch,
		Banken:     version,
	}
	buf, err := json.Marshal(line)
	if err != nil {
		return id, fmt.Errorf("response: marshal ledger line: %w", err)
	}

	day := now
	if !a.Time.IsZero() {
		day = a.Time
	}
	path := filepath.Join(l.dir, "decisions-"+day.UTC().Format(ledgerDayLayout)+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // operator-supplied ledger dir
	if err != nil {
		return id, fmt.Errorf("response: open ledger %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(buf, '\n')); err != nil {
		return id, fmt.Errorf("response: write ledger %s: %w", path, err)
	}
	return id, nil
}

// HandleInfo is the executor result the ledger records for an action, carried
// as plain fields so this package never imports internal/response/exec (the
// dependency arrow points only the other way). The drain (and the operator
// undo commands) translate the executor's own Handle into this before
// recording.
type HandleInfo struct {
	ID     string `json:"id,omitempty"`
	Kind   Action `json:"kind,omitempty"`
	PID    int    `json:"pid,omitempty"`
	Method string `json:"method,omitempty"`
	DryRun bool   `json:"dryRun"`
	Undo   string `json:"undo,omitempty"`
	Note   string `json:"note,omitempty"`
}

// LiveInfo is the live process identity the executor bound before acting
// (the exe it resolved, the start time it confirmed, the cgroup it saw). Like
// HandleInfo it is carried as plain fields so this package never imports the
// executor; the drain translates exec.Live into it. Empty for file actions and
// for phases that never reached the executor (expired, downgraded, malformed).
type LiveInfo struct {
	PID        int       `json:"pid"`
	StartTime  time.Time `json:"startTime,omitzero"`
	Exe        string    `json:"exe,omitempty"`
	CgroupPath string    `json:"cgroupPath,omitempty"`
	UID        int       `json:"uid"`
	Masquerade bool      `json:"masquerade,omitempty"`
}

// actionLine is one action record written to actions-<day>.jsonl by the drain
// (and later by thaw/restore). Phase is the drain vocabulary of §2.4/§2.6:
// executed, failed, expired, downgraded, already-applied, recovered, plus
// thawed and restored for the undo commands. It references the decision it
// enacts (DecisionID = the order id) and records whether real enforcement was
// armed, so a reader can always tell a real SIGKILL from a dry-run "would
// kill".
type actionLine struct {
	ID          string       `json:"id"`
	Time        time.Time    `json:"time"`
	Phase       string       `json:"phase"`
	Note        string       `json:"note,omitempty"` // a short reason within a phase, e.g. "malformed", "kill-switch"
	DecisionID  string       `json:"decisionId,omitempty"`
	Alert       alertSummary `json:"alert"`
	Action      Action       `json:"action"`              // what actually happened (the actor's verdict / the undo)
	Requested   Action       `json:"requested,omitempty"` // what the order asked for, when it differs (downgraded)
	Scope       Scope        `json:"scope,omitempty"`
	Target      Target       `json:"target"`
	Enforced    bool         `json:"enforced"` // executor armed (real) vs dry-run
	Handle      *HandleInfo  `json:"handle,omitempty"`
	Live        *LiveInfo    `json:"live,omitempty"`
	Error       string       `json:"error,omitempty"`
	Policy      string       `json:"policy"`                // the policy hash the ACTOR decided under
	OrderPolicy string       `json:"orderPolicy,omitempty"` // the policy hash carried in the order, when it differs
	Banken      string       `json:"banken,omitempty"`
}

// ActionRecord is everything an action ledger line carries. The drain and the
// operator undo commands (thaw/restore) fill it; the responder never does --
// after the two-process split the responder only records decisions (the
// decided line plus the order file IS the request, §2.3). A struct, not a long
// positional signature, because the drain fills a different subset per phase
// (a downgraded line has no handle; a malformed line has no verdict).
type ActionRecord struct {
	Alert       alert.Alert
	Phase       string
	Note        string
	DecisionID  string // the order id (= the decided line id)
	Action      Action
	Requested   Action
	Scope       Scope
	Target      Target
	Enforced    bool
	Handle      *HandleInfo
	Live        *LiveInfo
	Error       string
	Policy      string // the acting policy hash
	OrderPolicy string // the order's policy hash, when it differs from Policy
	Version     string
}

// RecordAction appends one action line to actions-<day>.jsonl. Like
// RecordDecision the write error is returned, never fatal to the caller.
func (l *Ledger) RecordAction(rec ActionRecord) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	id := newID(now)
	a := rec.Alert
	line := actionLine{
		ID:         id,
		Time:       now.UTC(),
		Phase:      rec.Phase,
		Note:       rec.Note,
		DecisionID: rec.DecisionID,
		Alert: alertSummary{
			Rule:    a.Rule,
			RuleID:  a.RuleID,
			Level:   a.Level,
			Source:  a.Source,
			Time:    a.Time,
			Image:   a.Event.Image,
			CmdLine: a.Event.CommandLine,
			User:    a.Event.User,
			Tags:    a.Tags,
		},
		Action:      rec.Action,
		Requested:   rec.Requested,
		Scope:       rec.Scope,
		Target:      rec.Target,
		Enforced:    rec.Enforced,
		Handle:      rec.Handle,
		Live:        rec.Live,
		Error:       rec.Error,
		Policy:      rec.Policy,
		OrderPolicy: rec.OrderPolicy,
		Banken:      rec.Version,
	}
	buf, err := json.Marshal(line)
	if err != nil {
		return id, fmt.Errorf("response: marshal action line: %w", err)
	}

	day := now
	if !a.Time.IsZero() {
		day = a.Time
	}
	path := filepath.Join(l.dir, "actions-"+day.UTC().Format(ledgerDayLayout)+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // operator-supplied ledger dir
	if err != nil {
		return id, fmt.Errorf("response: open action ledger %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(buf, '\n')); err != nil {
		return id, fmt.Errorf("response: write action ledger %s: %w", path, err)
	}
	return id, nil
}

// newID is a compact, time-ordered, unique id: 8 bytes of big-endian unix
// nanoseconds followed by 4 random bytes, hex-encoded. Lexical order matches
// time order, which is enough for the ledger (a full ULID would need a dep).
func newID(t time.Time) string {
	var b [12]byte
	binary.BigEndian.PutUint64(b[:8], uint64(t.UTC().UnixNano()))
	_, _ = rand.Read(b[8:])
	return hex.EncodeToString(b[:])
}
