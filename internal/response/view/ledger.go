package view

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/conor-sometimes/banken/internal/response"
)

// ledgerDayLayout is the date stamp in a per-day ledger filename, matching the
// response package's own writer (decisions-2006-01-02.jsonl).
const ledgerDayLayout = "2006-01-02"

// AlertSummary mirrors the compact alert the ledger records on each line (the
// response package writes it from an alert.Alert; the view only reads it). It
// is redeclared here, with the same json tags, so the view decodes a line
// without importing the writer's unexported type.
type AlertSummary struct {
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

// DecisionLine is one "decided" record from decisions-<day>.jsonl. The
// Decision field decodes into the exported response.Decision, so the chain
// reconstruction reads the intended action, the rail and the target straight
// from the record.
type DecisionLine struct {
	ID         string            `json:"id"`
	Time       time.Time         `json:"time"`
	Phase      string            `json:"phase"`
	Alert      AlertSummary      `json:"alert"`
	Decision   response.Decision `json:"decision"`
	Policy     string            `json:"policy"`
	Mode       response.Mode     `json:"mode"`
	KillSwitch bool              `json:"killSwitch"`
	Banken     string            `json:"banken,omitempty"`
}

// HandleInfo mirrors the executor result the ledger records for an action. The
// view never imports the executor, so it redeclares the plain-field shape the
// drain wrote.
type HandleInfo struct {
	ID     string          `json:"id,omitempty"`
	Kind   response.Action `json:"kind,omitempty"`
	PID    int             `json:"pid,omitempty"`
	Method string          `json:"method,omitempty"`
	DryRun bool            `json:"dryRun"`
	Undo   string          `json:"undo,omitempty"`
	Note   string          `json:"note,omitempty"`
}

// LiveInfo mirrors the live identity the drain recorded on an action line (the
// exe, start time and cgroup the executor bound before acting). It is what
// explain's "identity bound" line reads.
type LiveInfo struct {
	PID        int       `json:"pid"`
	StartTime  time.Time `json:"startTime,omitzero"`
	Exe        string    `json:"exe,omitempty"`
	CgroupPath string    `json:"cgroupPath,omitempty"`
	UID        int       `json:"uid"`
	Masquerade bool      `json:"masquerade,omitempty"`
}

// ActionLine is one record from actions-<day>.jsonl. Phase is the drain/undo
// vocabulary of §2.4/§2.6 (executed, failed, expired, downgraded,
// already-applied, recovered, thawed, restored). DecisionID ties it back to the
// decided line it enacts.
type ActionLine struct {
	ID          string          `json:"id"`
	Time        time.Time       `json:"time"`
	Phase       string          `json:"phase"`
	Note        string          `json:"note,omitempty"`
	DecisionID  string          `json:"decisionId,omitempty"`
	Alert       AlertSummary    `json:"alert"`
	Action      response.Action `json:"action"`
	Requested   response.Action `json:"requested,omitempty"`
	Scope       response.Scope  `json:"scope,omitempty"`
	Target      response.Target `json:"target"`
	Enforced    bool            `json:"enforced"`
	Handle      *HandleInfo     `json:"handle,omitempty"`
	Live        *LiveInfo       `json:"live,omitempty"`
	Error       string          `json:"error,omitempty"`
	Policy      string          `json:"policy"`
	OrderPolicy string          `json:"orderPolicy,omitempty"`
	Banken      string          `json:"banken,omitempty"`
}

// ledgerFilesInRange returns the per-day ledger files of the given prefix
// ("actions-" or "decisions-") whose day stamp falls within [since, until],
// newest day first. A file whose name does not parse as a day is skipped, not
// an error: an operator may keep other files in the ledger dir. An unreadable
// ledger dir yields no files (list over an empty/fresh host is not an error).
func (r *Reader) ledgerFilesInRange(prefix string, since, until time.Time) []string {
	if r.ledgerDir == "" {
		return nil
	}
	ents, err := fs.ReadDir(r.root, r.ledgerDir)
	if err != nil {
		return nil
	}
	sinceDay := since.UTC().Truncate(24 * time.Hour)
	untilDay := until.UTC().Truncate(24 * time.Hour)
	var files []string
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		stamp := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".jsonl")
		day, derr := time.Parse(ledgerDayLayout, stamp)
		if derr != nil {
			continue
		}
		if day.Before(sinceDay) || day.After(untilDay) {
			continue
		}
		files = append(files, name)
	}
	// Newest day first so a reader that stops early sees recent records first.
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	return files
}

// readActions reads every action line whose time is within [since, until],
// across the day files the range covers. Lines are returned oldest first (by
// their recorded time, then by id) so list and explain print in the order
// things happened. A malformed line is skipped, never fatal: one corrupt line
// must not blind the operator to the rest of the ledger.
func (r *Reader) readActions(since, until time.Time) ([]ActionLine, error) {
	files := r.ledgerFilesInRange("actions-", since, until)
	var out []ActionLine
	for _, name := range files {
		lines, err := readJSONL[ActionLine](r.root, path.Join(r.ledgerDir, name))
		if err != nil {
			return nil, err
		}
		for _, ln := range lines {
			if ln.Time.Before(since) || ln.Time.After(until) {
				continue
			}
			out = append(out, ln)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Time.Equal(out[j].Time) {
			return out[i].ID < out[j].ID
		}
		return out[i].Time.Before(out[j].Time)
	})
	return out, nil
}

// findDecision returns the decided line whose id is addressed by query (exact
// or a >= minIDPrefix prefix), searching the decisions ledger within the range.
// Found reports whether exactly such a line exists.
func (r *Reader) findDecision(query string, since, until time.Time) (DecisionLine, bool, error) {
	files := r.ledgerFilesInRange("decisions-", since, until)
	for _, name := range files {
		lines, err := readJSONL[DecisionLine](r.root, path.Join(r.ledgerDir, name))
		if err != nil {
			return DecisionLine{}, false, err
		}
		for _, ln := range lines {
			if idMatches(ln.ID, query) {
				return ln, true, nil
			}
		}
	}
	return DecisionLine{}, false, nil
}

// readJSONL decodes a newline-delimited JSON file into a slice of T. A missing
// file is empty, not an error. A line that fails to decode is skipped.
func readJSONL[T any](root fs.FS, name string) ([]T, error) {
	f, err := root.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("view: open ledger %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var v T
		if err := json.Unmarshal(line, &v); err != nil {
			continue
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("view: read ledger %s: %w", name, err)
	}
	return out, nil
}
