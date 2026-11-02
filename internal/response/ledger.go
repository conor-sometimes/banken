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

// newID is a compact, time-ordered, unique id: 8 bytes of big-endian unix
// nanoseconds followed by 4 random bytes, hex-encoded. Lexical order matches
// time order, which is enough for the ledger (a full ULID would need a dep).
func newID(t time.Time) string {
	var b [12]byte
	binary.BigEndian.PutUint64(b[:8], uint64(t.UTC().UnixNano()))
	_, _ = rand.Read(b[8:])
	return hex.EncodeToString(b[:])
}
