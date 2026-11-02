// Package engine wires the pieces together: it takes parsed events,
// matches them against the Sigma rules and IOC set, turns every hit into
// an alert, and sends each alert through the one dispatcher. It holds no
// I/O of its own beyond reading an io.Reader through a parser, so it is
// trivially testable with in-memory inputs.
package engine

import (
	"fmt"
	"io"
	"sync/atomic"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/ioc"
	"github.com/conor-sometimes/banken/internal/parser"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// Engine matches events and dispatches alerts.
//
// The rule set (the compiled Sigma matcher and the IOC set) lives behind two
// atomic.Pointers so it can be replaced on a running daemon without a lock on
// the hot path: SetRules publishes a freshly built set with a single atomic
// store, and every match loads the current pointers per call. An event that is
// mid-match when a swap happens finishes against whichever set it loaded; the
// next event sees the new one. This is the one safe publication point for a
// live rule reload (see docs/design/rule-refresh.md section 6).
type Engine struct {
	matcher atomic.Pointer[sigma.Matcher]
	iocs    atomic.Pointer[ioc.Set]
	disp    *alert.Dispatcher
}

// New builds an engine. iocs and disp may be nil (no IOC matching / no
// dispatch), which keeps the matcher usable in tests that only inspect the
// returned alerts. The rules are compiled into a prefiltered matcher so the
// per-event cost does not grow with the rule count.
func New(rules []*sigma.Rule, iocs *ioc.Set, disp *alert.Dispatcher) *Engine {
	e := &Engine{disp: disp}
	e.matcher.Store(sigma.NewMatcher(rules))
	if iocs != nil {
		e.iocs.Store(iocs)
	}
	return e
}

// SetRules atomically replaces the engine's live rule set with one compiled
// from rules and iocs, with no restart and no lock on the match path. The new
// matcher is built here (off the hot path -- the old set keeps serving every
// in-flight and newly arriving event throughout the build) and published with
// a single atomic store, so a match never sees a half-built set. iocs may be
// nil to clear IOC matching. The caller is responsible for the validate step
// (a candidate with zero rules must be refused before calling this, so the
// daemon can never go ruleless); SetRules is the swap, not the gate.
func (e *Engine) SetRules(rules []*sigma.Rule, iocs *ioc.Set) {
	e.matcher.Store(sigma.NewMatcher(rules))
	e.iocs.Store(iocs) // nil clears the IOC set
}

// Match returns every alert an event produces (Sigma rules first, in rule
// order, then IOC hits), without dispatching. Deterministic for a given
// event and rule set.
func (e *Engine) Match(ev event.Event) []alert.Alert {
	var alerts []alert.Alert
	for _, r := range e.matcher.Load().Match(ev) {
		alerts = append(alerts, alert.Alert{
			Time:     ev.Time,
			Kind:     alert.KindSigma,
			Rule:     r.Name,
			RuleID:   r.ID,
			Title:    r.Title,
			Desc:     r.Description,
			Level:    defaultLevel(r.Level),
			Observed: r.Observe,
			Source:   ev.Source,
			Tags:     r.Tags,
			Message:  fmt.Sprintf("rule %q matched", r.Name),
			Event:    ev,
		})
	}
	if iocs := e.iocs.Load(); iocs != nil {
		for _, m := range iocs.Match(ev) {
			alerts = append(alerts, alert.Alert{
				Time:    ev.Time,
				Kind:    alert.KindIOC,
				Rule:    m.Indicator.Source,
				Title:   "IOC match: " + m.Indicator.Value,
				Level:   "high",
				Source:  ev.Source,
				IOC:     m.Indicator.Value,
				Field:   m.Field,
				Message: fmt.Sprintf("indicator %q found in %s", m.Indicator.Value, m.Field),
				Event:   ev,
			})
		}
	}
	return alerts
}

// Result summarises one Process call.
type Result struct {
	Events int
	Alerts int
	Errors []error
	// ParseErr is non-nil when the source could not be fully parsed (an I/O
	// error or a recovered parser panic). The caller uses it to decide
	// whether to advance the cursor: advancing past bytes that did not parse
	// cleanly would skip events on the next run. It is a dedicated field
	// precisely so that decision is made on a real signal, not by matching
	// the text of an error. It is also included in Errors for logging.
	ParseErr error
}

// Process parses r with p, matches every event, and dispatches every
// alert. A parser I/O error is returned in Result.Errors but processing of
// whatever events were parsed still happens. If the engine has no
// dispatcher, alerts are counted but not delivered.
//
// Both the parse and each event's match run under a panic guard: a bug (or
// a crafted input designed to trip one) takes out at most that one source
// or that one event, never the whole scan. Blinding the detector by feeding
// it one pathological record is precisely the attack this prevents, so a
// recovered panic is surfaced as an error, not swallowed.
func (e *Engine) Process(p parser.Parser, r io.Reader) Result {
	var res Result
	events, err := e.safeParse(p, r)
	if err != nil {
		res.ParseErr = fmt.Errorf("parse %s: %w", p.Name(), err)
		res.Errors = append(res.Errors, res.ParseErr)
	}
	res.Events = len(events)
	for _, ev := range events {
		alerts, perr := e.safeMatch(ev)
		if perr != nil {
			res.Errors = append(res.Errors, perr)
			continue
		}
		for _, a := range alerts {
			res.Alerts++
			if e.disp != nil {
				res.Errors = append(res.Errors, e.disp.Dispatch(a)...)
			}
		}
	}
	return res
}

// ProcessEvent matches a single event and dispatches its alerts immediately: the streaming
// counterpart to Process. Where Process reads a source to EOF and matches a batch (the timer
// model), ProcessEvent runs per event as events arrive on a live sensor stream, so end-to-end
// latency is capture + match rather than bounded by a scan interval. It runs under the same
// per-event panic guard as Process, so one pathological event degrades to a returned error, never
// a crash of the stream. It returns the number of alerts fired and any errors (a recovered match
// panic, or sink errors).
func (e *Engine) ProcessEvent(ev event.Event) (alerts int, errs []error) {
	as, perr := e.safeMatch(ev)
	if perr != nil {
		return 0, []error{perr}
	}
	for _, a := range as {
		alerts++
		if e.disp != nil {
			errs = append(errs, e.disp.Dispatch(a)...)
		}
	}
	return alerts, errs
}

// safeParse runs the parser under a recover so a parser bug on one source
// cannot abort the whole run.
func (e *Engine) safeParse(p parser.Parser, r io.Reader) (events []event.Event, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			events = nil
			err = fmt.Errorf("parser %s panicked (recovered): %v", p.Name(), rec)
		}
	}()
	return p.Parse(r)
}

// safeMatch runs the matcher under a recover so one event can never crash
// the scan.
func (e *Engine) safeMatch(ev event.Event) (alerts []alert.Alert, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			alerts = nil
			err = fmt.Errorf("match panicked (recovered) on event from %s: %v", ev.Source, rec)
		}
	}()
	return e.Match(ev), nil
}

// defaultLevel supplies a level for a rule that declared none.
func defaultLevel(level string) string {
	if level == "" {
		return "medium"
	}
	return level
}
