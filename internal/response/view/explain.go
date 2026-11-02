package view

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/conor-sometimes/banken/internal/response"
)

// ActionView is one action line in a chain, with the store state it reached.
// Entry is nil for an action that keeps no store (kill, collect) or never
// reached one (expired, downgraded, malformed).
type ActionView struct {
	Line      ActionLine
	Entry     *Entry
	Live      LiveFacts
	State     State
	StorePath string
}

// Explanation is the reconstructed §3.2 chain for one id: the decided line, the
// action lines that enacted it (in order), and -- when the decision asked for
// an action that never produced one -- whether an order is still waiting in the
// spool. It is a pure data structure; RenderExplain formats it with no further
// I/O, so a golden test asserts the exact text.
type Explanation struct {
	Decision     DecisionLine
	Actions      []ActionView
	SpoolPending bool
	SpoolAge     time.Duration
	Now          time.Time
}

// ExplainOptions bounds the ledger search. Since defaults to a week (an action
// explained days later is still in range); Now is the clock, set by a test.
type ExplainOptions struct {
	Since time.Duration
	Now   time.Time
}

// DefaultExplainWindow is how far back explain searches the ledger for the id.
const DefaultExplainWindow = 7 * 24 * time.Hour

// Explain reconstructs the chain for a decision id or a handle id. It resolves
// a handle id to its decision via the action line that carries the handle, then
// gathers every action line for that decision. found is false when no decision,
// no handle and no spool order matches the id (the caller exits 1). ok reports
// an unambiguous resolve; an id prefix that matches more than one decision is
// an error naming the ambiguity.
func (r *Reader) Explain(prober Prober, query string, opts ExplainOptions) (*Explanation, error) {
	if len(query) < minIDPrefix {
		return nil, fmt.Errorf("id %q is too short: give at least %d hex characters", query, minIDPrefix)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	window := opts.Since
	if window <= 0 {
		window = DefaultExplainWindow
	}
	since := now.Add(-window)

	actions, err := r.readActions(since, now)
	if err != nil {
		return nil, err
	}

	// Resolve the decision id: either the query is a decision id, or it is a
	// handle id whose action line names the decision it enacts.
	decisionID := ""
	dec, found, err := r.findDecision(query, since, now)
	if err != nil {
		return nil, err
	}
	if found {
		decisionID = dec.ID
	} else {
		for _, a := range actions {
			if a.Handle != nil && idMatches(a.Handle.ID, query) {
				decisionID = a.DecisionID
				break
			}
		}
		if decisionID != "" {
			dec, found, err = r.findDecision(decisionID, since, now)
			if err != nil {
				return nil, err
			}
		}
	}
	if decisionID == "" {
		return nil, fmt.Errorf("no decision or handle matches id %q within %s", query, window)
	}

	exp := &Explanation{Decision: dec, Now: now}

	for _, a := range actions {
		if a.DecisionID != decisionID {
			continue
		}
		av := ActionView{Line: a}
		if a.Handle != nil && a.Handle.ID != "" && !a.Handle.DryRun {
			kind := a.Handle.Kind
			if kind == "" {
				kind = a.Action
			}
			if entry, eerr := r.readEntry(kind, a.Handle.ID); eerr == nil {
				av.Entry = &entry
				av.Live = prober.Probe(entry)
				av.State = ComputeState(entry, av.Live)
				av.StorePath = r.storeDisplayPath(kind, a.Handle.ID)
			}
		}
		exp.Actions = append(exp.Actions, av)
	}

	// A decided action with no action line: either it is still waiting in the
	// spool, or the daemon crashed between the decision and the order.
	if len(exp.Actions) == 0 && dec.Decision.Action != response.ActionNone {
		if order, ok := r.readSpoolOrder(decisionID); ok {
			exp.SpoolPending = true
			if !order.Time.IsZero() {
				exp.SpoolAge = now.Sub(order.Time)
			}
		}
	}

	return exp, nil
}

// storeDisplayPath is the human store path for an entry (leading slash restored
// from the root-relative dir), as shown on explain's "store" line.
func (r *Reader) storeDisplayPath(kind response.Action, id string) string {
	dir := r.storeDirFor(kind)
	if dir == "" {
		return ""
	}
	return "/" + path.Join(dir, id)
}

// spoolOrder is the sliver of a work order explain reads: just the time, to age
// the "requested, not yet drained" line. The full order shape lives in the
// response package; the view only needs the timestamp.
type spoolOrder struct {
	Time time.Time `json:"time"`
}

// readSpoolOrder reads the work order whose filename stem is the decision id.
// ok is false when the spool is unset or holds no such order.
func (r *Reader) readSpoolOrder(decisionID string) (spoolOrder, bool) {
	if r.spoolDir == "" {
		return spoolOrder{}, false
	}
	b, err := fs.ReadFile(r.root, path.Join(r.spoolDir, decisionID+".json"))
	if err != nil {
		return spoolOrder{}, false
	}
	var o spoolOrder
	if err := json.Unmarshal(b, &o); err != nil {
		return spoolOrder{}, true // present but unparseable: pending, age unknown
	}
	return o, true
}

// RenderExplain writes the §3.2 chain. It is pure over the Explanation.
func RenderExplain(w io.Writer, exp *Explanation) {
	d := exp.Decision
	dec := d.Decision
	fmt.Fprintf(w, "decision %s   %s   policy %s   mode %s   armed %s\n",
		d.ID, stamp(d.Time), dash(d.Policy), dash(string(d.Mode)), armedWord(d))

	al := d.Alert
	fmt.Fprintf(w, "  alert    %s (%s, %s) at %s  %s\n",
		dash(al.Rule), dash(al.Level), dash(al.Source), stamp(al.Time), targetIdentity(dec.Target, al))
	if al.Image != "" || al.CmdLine != "" || len(al.Tags) > 0 {
		fmt.Fprintf(w, "           image %s   cmd %q   tags %s\n", dash(al.Image), al.CmdLine, dash(strings.Join(al.Tags, ",")))
	}
	fmt.Fprintf(w, "  entry    %s -> intended %s%s\n", dash(dec.Entry), dec.Intended, scopeSuffix(dec.Scope))
	fmt.Fprintf(w, "  rails    %s   masquerade: %s\n", railWord(dec.Rail, dec.Reason), yesNo(dec.Masquerade))
	fmt.Fprintf(w, "  verdict  %s\n", verdictLine(dec))

	if len(exp.Actions) == 0 {
		if exp.SpoolPending {
			if exp.SpoolAge > 0 {
				fmt.Fprintf(w, "action   requested, not yet drained (order in spool for %s)\n", exp.SpoolAge.Round(time.Second))
			} else {
				fmt.Fprintln(w, "action   requested, not yet drained (order in spool)")
			}
			return
		}
		if dec.Action != response.ActionNone {
			fmt.Fprintln(w, "action   never requested (no order found; the daemon may have crashed between the decision and the order)")
		} else {
			fmt.Fprintln(w, "action   none (the policy mapped this alert to no action)")
		}
		return
	}

	for _, av := range exp.Actions {
		renderAction(w, exp.Decision, av)
	}
}

// renderAction writes one action block of the chain.
func renderAction(w io.Writer, d DecisionLine, av ActionView) {
	a := av.Line
	fmt.Fprintf(w, "action   %s   %s by banken-respond   %s   policy %s %s\n",
		shortID(a.ID), dash(a.Phase), stamp(a.Time), dash(a.Policy), policyAgreement(d.Policy, a.Policy))

	switch a.Phase {
	case "downgraded":
		fmt.Fprintf(w, "  helper re-decided: %s (DOWNGRADED from requested %s)\n", a.Action, dashAction(a.Requested))
		if a.Note != "" {
			fmt.Fprintf(w, "  reason: %s\n", a.Note)
		}
		return
	case "failed", "expired", "malformed":
		fmt.Fprintf(w, "  outcome: %s %s\n", a.Phase, a.Note)
		if a.Error != "" {
			fmt.Fprintf(w, "  error: %s\n", a.Error)
		}
		return
	}

	// executed / already-applied / recovered / thawed / restored: the agreeing
	// act, the bound identity, the handle and the live state.
	if a.Requested != "" && a.Requested != a.Action {
		fmt.Fprintf(w, "  helper re-decided: %s (downgraded from %s)\n", a.Action, a.Requested)
	} else {
		fmt.Fprintf(w, "  helper re-decided: %s (agrees)\n", a.Action)
	}
	if a.Live != nil {
		fmt.Fprintf(w, "  identity bound: exe %s  start %s  uid %d  cgroup %s\n",
			dash(a.Live.Exe), stamp(a.Live.StartTime), a.Live.UID, dash(a.Live.CgroupPath))
	}
	if a.Handle != nil {
		fmt.Fprintf(w, "  method %s   handle %s%s%s\n",
			dash(a.Handle.Method), shortID(a.Handle.ID), pidsSuffix(av), storeSuffix(av.StorePath))
	}
	if av.State != "" {
		fmt.Fprintf(w, "  state now: %s\n", av.State)
	}
}

// jsonExplainAction is one action in the -json chain: the ledger line, the
// store manifest verbatim, the live facts and the computed state.
type jsonExplainAction struct {
	Action   ActionLine      `json:"action"`
	Manifest json.RawMessage `json:"manifest,omitempty"`
	Live     *LiveFacts      `json:"live,omitempty"`
	State    State           `json:"state,omitempty"`
}

// jsonExplain is the -json shape of explain: the decided line and the chain of
// actions, each with its manifest round-tripped verbatim. SpoolPending is set
// when the decision's action never produced a line but an order waits.
type jsonExplain struct {
	Decision     DecisionLine        `json:"decision"`
	Actions      []jsonExplainAction `json:"actions"`
	SpoolPending bool                `json:"spoolPending,omitempty"`
}

// RenderExplainJSON writes the chain as a single JSON object (the `show` of
// §5's Q11). The manifests round-trip verbatim.
func RenderExplainJSON(w io.Writer, exp *Explanation) error {
	out := jsonExplain{Decision: exp.Decision, SpoolPending: exp.SpoolPending}
	for _, av := range exp.Actions {
		ja := jsonExplainAction{Action: av.Line, State: av.State}
		if av.Entry != nil {
			ja.Manifest = av.Entry.Raw
			live := av.Live
			ja.Live = &live
		}
		out.Actions = append(out.Actions, ja)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func armedWord(d DecisionLine) string {
	if d.Decision.Rail == response.RailNotArmed {
		return "no"
	}
	if d.Mode == response.ModeEnforce {
		return "yes"
	}
	return "-"
}

func railWord(rail response.Rail, reason string) string {
	if rail == response.RailNone {
		return "none fired"
	}
	if reason != "" {
		return fmt.Sprintf("%s (%s)", rail, reason)
	}
	return string(rail)
}

func verdictLine(d response.Decision) string {
	if d.Target.File != nil {
		return fmt.Sprintf("%s %s", d.Action, d.Target.File.Path)
	}
	if d.Target.Process != nil {
		return fmt.Sprintf("%s %s of pid %d", d.Action, scopeWord(d.Scope), d.Target.Process.PID)
	}
	return string(d.Action)
}

func targetIdentity(t response.Target, al AlertSummary) string {
	if t.Process != nil {
		return fmt.Sprintf("pid %d ppid %d user %s", t.Process.PID, t.Process.PPID, dash(al.User))
	}
	if t.File != nil {
		return "file " + t.File.Path
	}
	return "user " + dash(al.User)
}

func scopeSuffix(s response.Scope) string {
	if s == "" {
		return ""
	}
	return " (" + string(s) + ")"
}

func scopeWord(s response.Scope) string {
	if s == "" {
		return "process"
	}
	return string(s)
}

func pidsSuffix(av ActionView) string {
	if av.Entry != nil && av.Entry.Freeze != nil && len(av.Entry.Freeze.PIDs) > 0 {
		return fmt.Sprintf("   pids %v", av.Entry.Freeze.PIDs)
	}
	return ""
}

func storeSuffix(storePath string) string {
	if storePath == "" {
		return ""
	}
	return "   store " + storePath
}

func policyAgreement(decisionPolicy, actionPolicy string) string {
	if decisionPolicy == actionPolicy {
		return "(same)"
	}
	return "(differs from decision " + dash(decisionPolicy) + ")"
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func dashAction(a response.Action) string {
	if a == "" {
		return "-"
	}
	return string(a)
}
