package view

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/conor-sometimes/banken/internal/response"
)

// ListOptions bounds and filters a list. The zero value lists the default 24h
// window of every kind and state.
type ListOptions struct {
	Since time.Duration   // window back from Now; 0 means DefaultListWindow
	Kind  response.Action // "" = every kind
	State string          // "" = every state; else a leading-word bucket (held|frozen|thawed|restored|lost)
	Now   time.Time       // the upper bound; zero means time.Now (set by a test for determinism)
}

// DefaultListWindow is the default -since: a day of actions, enough to cover a
// handful of scan intervals and an operator's shift.
const DefaultListWindow = 24 * time.Hour

// Row is one handle in the list: the action that created it, the store entry
// (nil for a kill/collect handle that keeps no reversible store), the live
// facts, and the computed §3.1 state.
type Row struct {
	ID     string
	Kind   response.Action
	State  State
	Live   LiveFacts
	Entry  *Entry
	Action ActionLine
}

// List reads the action ledger within the window and returns one row per
// materialised handle (an executed or already-applied line that produced a
// handle id), joined to its store entry and classified by ComputeState. Rows
// are ordered by the time the action landed. A dry-run handle (no store entry)
// is reported with state "dry-run"; a kill/collect handle is classified from
// the ledger alone, since neither keeps a reversible store.
func (r *Reader) List(prober Prober, opts ListOptions) ([]Row, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	window := opts.Since
	if window <= 0 {
		window = DefaultListWindow
	}
	since := now.Add(-window)

	actions, err := r.readActions(since, now)
	if err != nil {
		return nil, err
	}

	// One row per handle id, first materialising line wins for the metadata;
	// the store (read now) carries the current state, so a later thaw/restore
	// shows without a second ledger line being needed here.
	seen := make(map[string]bool)
	var rows []Row
	for _, a := range actions {
		if a.Handle == nil || a.Handle.ID == "" {
			continue
		}
		if a.Phase != "executed" && a.Phase != "already-applied" {
			continue
		}
		if seen[a.Handle.ID] {
			continue
		}
		seen[a.Handle.ID] = true

		kind := a.Handle.Kind
		if kind == "" {
			kind = a.Action
		}
		row := Row{ID: a.Handle.ID, Kind: kind, Action: a}

		entry, eerr := r.readEntry(kind, a.Handle.ID)
		switch {
		case eerr == nil:
			row.Entry = &entry
			row.Live = prober.Probe(entry)
			row.State = ComputeState(entry, row.Live)
		case a.Handle.DryRun:
			row.State = State("dry-run")
		case kind == response.ActionKill:
			row.State = State("killed (" + methodOr(a.Handle.Method, "signal") + ")")
		case kind == response.ActionCollect:
			row.State = State("collected")
		default:
			row.State = State("lost (no store)")
		}

		if opts.Kind != "" && kind != opts.Kind {
			continue
		}
		if opts.State != "" && stateKind(row.State) != opts.State {
			continue
		}
		rows = append(rows, row)
	}

	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].Action.Time.Before(rows[j].Action.Time)
	})
	return rows, nil
}

// methodOr returns method, or fallback when method is empty.
func methodOr(method, fallback string) string {
	if method == "" {
		return fallback
	}
	return method
}

// RenderList writes the human table of §3.1. Columns are tab-aligned so the
// output is stable for a golden test and readable in a terminal. An empty list
// prints a single "no actions" line, never a bare header.
func RenderList(w io.Writer, rows []Row) {
	if len(rows) == 0 {
		fprintln(w, "no actions in the window")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fprintln(tw, "ID\tKIND\tSTATE\tTARGET\tUSER\tRULE\tWHEN")
	for _, row := range rows {
		fprintf(
			tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			shortID(row.ID),
			row.Kind,
			row.State,
			targetString(row),
			dash(row.Action.Alert.User),
			dash(row.Action.Alert.Rule),
			stamp(row.Action.Time),
		)
	}
	_ = tw.Flush()
}

// jsonRow is the -json shape of §3.1: id, kind, state, the live facts, the
// store manifest verbatim (nil for a kill/collect handle) and the action line.
// Manifest is json.RawMessage so `-json` round-trips the manifest byte for
// byte -- no field the view did not model is dropped.
type jsonRow struct {
	ID       string          `json:"id"`
	Kind     response.Action `json:"kind"`
	State    State           `json:"state"`
	Live     *LiveFacts      `json:"live,omitempty"`
	Manifest json.RawMessage `json:"manifest,omitempty"`
	Action   ActionLine      `json:"action"`
}

// RenderListJSON writes one JSON object per row, so a script reads the list
// line by line. The manifest is emitted verbatim.
func RenderListJSON(w io.Writer, rows []Row) error {
	enc := json.NewEncoder(w)
	for _, row := range rows {
		jr := jsonRow{ID: row.ID, Kind: row.Kind, State: row.State, Action: row.Action}
		if row.Entry != nil {
			jr.Manifest = row.Entry.Raw
			live := row.Live
			jr.Live = &live
		}
		if err := enc.Encode(jr); err != nil {
			return err
		}
	}
	return nil
}

// targetString renders the TARGET column: a process as "pid N exe", a file as
// "path size method". It reads the action line's target, falling back to the
// store manifest for fields the compact ledger line does not carry.
func targetString(row Row) string {
	a := row.Action
	if a.Target.Process != nil {
		exe := a.Target.Process.Image
		if exe == "" && row.Entry != nil && row.Entry.Freeze != nil {
			exe = row.Entry.Freeze.Target.Exe
		}
		return fmt.Sprintf("pid %d %s", a.Target.Process.PID, dash(exe))
	}
	if a.Target.File != nil {
		s := a.Target.File.Path
		if row.Entry != nil && row.Entry.Quar != nil {
			s = fmt.Sprintf("%s %s %s", row.Entry.Quar.OrigPath, humanBytes(row.Entry.Quar.Stat.Size), row.Entry.Quar.Method)
		}
		return s
	}
	if a.Handle != nil && a.Handle.PID != 0 {
		return fmt.Sprintf("pid %d", a.Handle.PID)
	}
	return "-"
}

// shortID is the 8-hex prefix shown in the ID column; the full id is in -json.
func shortID(id string) string {
	if len(id) <= minIDPrefix {
		return id
	}
	return id[:minIDPrefix]
}

// dash renders an empty string as "-" so a column never collapses.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// humanBytes renders a byte size as a compact KiB/MiB figure for the target
// column, matching the "48 KiB" of the §3.1 example.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.0f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
