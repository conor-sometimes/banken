// Package engine wires the pieces together: it takes parsed events,
// matches them against the Sigma rules and IOC set, turns every hit into
// an alert, and sends each alert through the one dispatcher. It holds no
// I/O of its own beyond reading an io.Reader through a parser, so it is
// trivially testable with in-memory inputs.
package engine

import (
	"fmt"
	"io"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/ioc"
	"github.com/conor-sometimes/banken/internal/parser"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// Engine matches events and dispatches alerts.
type Engine struct {
	matcher *sigma.Matcher
	iocs    *ioc.Set
	disp    *alert.Dispatcher
	now     func() time.Time
}

// New builds an engine. iocs and disp may be nil (no IOC matching / no
// dispatch), which keeps the matcher usable in tests that only inspect the
// returned alerts. The rules are compiled into a prefiltered matcher so the
// per-event cost does not grow with the rule count.
func New(rules []*sigma.Rule, iocs *ioc.Set, disp *alert.Dispatcher) *Engine {
	return &Engine{matcher: sigma.NewMatcher(rules), iocs: iocs, disp: disp, now: time.Now}
}

// Match returns every alert an event produces (Sigma rules first, in rule
// order, then IOC hits), without dispatching. Deterministic for a given
// event and rule set.
func (e *Engine) Match(ev event.Event) []alert.Alert {
	var alerts []alert.Alert
	for _, r := range e.matcher.Match(ev) {
		alerts = append(alerts, alert.Alert{
			Time:    ev.Time,
			Kind:    alert.KindSigma,
			Rule:    r.Name,
			RuleID:  r.ID,
			Title:   r.Title,
			Level:   defaultLevel(r.Level),
			Source:  ev.Source,
			Message: fmt.Sprintf("rule %q matched", r.Name),
			Event:   ev,
		})
	}
	if e.iocs != nil {
		for _, m := range e.iocs.Match(ev) {
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
		res.Errors = append(res.Errors, fmt.Errorf("parse %s: %w", p.Name(), err))
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
