// Package alert turns a rule hit into an alert and fans it out to the
// configured sinks (journal, jsonl, webhook) through one dispatch point.
// That single point is deliberate: a response action -- kill the process,
// revoke a key, isolate the host -- slots in at Dispatch without touching
// any sink, so banken can grow from alert-only to EDR response without a
// redesign.
package alert

import (
	"time"

	"github.com/conor-sometimes/banken/internal/event"
)

// Kind distinguishes what produced an alert.
const (
	KindSigma = "sigma"
	KindIOC   = "ioc"
)

// Alert is one detection, carrying enough of the rule and the triggering
// event to be actionable and to be the JSON a webhook receives.
type Alert struct {
	Time    time.Time   `json:"time"`
	Kind    string      `json:"kind"`             // KindSigma or KindIOC
	Rule    string      `json:"rule"`             // rule name / indicator feed
	RuleID  string      `json:"ruleId,omitempty"` // Sigma rule id, if any
	Title   string      `json:"title"`
	Level   string      `json:"level"` // critical|high|medium|low
	Source  string      `json:"source"`
	IOC     string      `json:"ioc,omitempty"` // the matched indicator, for KindIOC
	Field   string      `json:"field,omitempty"`
	Message string      `json:"message"`
	Event   event.Event `json:"event"`
}

// Sink is one alert destination.
type Sink interface {
	// Name identifies the sink in logs and errors.
	Name() string
	// Emit delivers one alert. It returns an error if delivery failed;
	// the dispatcher keeps going to the other sinks regardless.
	Emit(a Alert) error
	// Close flushes and releases the sink (e.g. the journal summary line,
	// an open jsonl file). Safe to call once.
	Close() error
}

// Responder is the hook a future response action implements: it is called
// with every dispatched alert before the sinks, and may act on it. Nil by
// default (alert-only). This is the "single dispatch point" the README
// promises response actions will slot into.
type Responder interface {
	Respond(a Alert) error
}

// Dispatcher fans an alert out to every sink. Construct with NewDispatcher.
type Dispatcher struct {
	sinks     []Sink
	responder Responder
}

// NewDispatcher builds a dispatcher over the given sinks.
func NewDispatcher(sinks ...Sink) *Dispatcher {
	return &Dispatcher{sinks: sinks}
}

// SetResponder installs the response hook (nil disables it).
func (d *Dispatcher) SetResponder(r Responder) { d.responder = r }

// Dispatch is the one place every matched alert flows through. It runs the
// responder (if any), then every sink, collecting -- never short-circuiting
// on -- their errors, so one failing sink never suppresses the others.
func (d *Dispatcher) Dispatch(a Alert) []error {
	var errs []error
	if d.responder != nil {
		if err := d.responder.Respond(a); err != nil {
			errs = append(errs, err)
		}
	}
	for _, s := range d.sinks {
		if err := s.Emit(a); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// Close closes every sink, collecting errors.
func (d *Dispatcher) Close() []error {
	var errs []error
	for _, s := range d.sinks {
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
