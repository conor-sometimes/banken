// Package alert turns a rule hit into an alert and fans it out to the
// configured sinks (journal, jsonl, webhook, OTLP) through one dispatch point.
// That single point is deliberate: a response action -- kill the process,
// revoke a key, isolate the host -- slots in at Dispatch without touching
// any sink, so banken can grow from alert-only to EDR response without a
// redesign.
//
// Dispatch must stay fast: it runs on the detection path (the stream follower
// per event, the periodic scanner per batch) and holds one lock across all
// sinks. So a sink's Emit must not block on anything slow. The local sinks
// (journal, jsonl) are quick file writes. The network sinks (webhook, OTLP)
// would otherwise block on a 15s HTTP timeout, so they send asynchronously:
// Emit queues the alert to a bounded buffer drained by one background goroutine
// and returns at once (see async.go). A hung endpoint therefore never stalls
// detection output -- it fills the queue and then drops, and because an EDR must
// never lose an alert silently, each drop is counted, returned from Emit as an
// error, and summarised by the sink's Close. Per-sink delivery stays FIFO; there
// is no cross-sink ordering guarantee.
package alert

import (
	"sync"
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
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`             // KindSigma or KindIOC
	Rule   string    `json:"rule"`             // rule name / indicator feed
	RuleID string    `json:"ruleId,omitempty"` // Sigma rule id, if any
	Title  string    `json:"title"`
	Desc   string    `json:"desc,omitempty"` // the rule's description, for OCSF finding_info.desc and the analyst's first read
	Level  string    `json:"level"`          // critical|high|medium|low
	// Observed marks an observe-mode hit: an optional rule the operator put in
	// observeRules (not optionalRules). It is recorded like any alert (jsonl,
	// run summary) but the paging sinks (journal, webhook) skip it, so a host
	// can measure a rule's noise before letting it page.
	Observed bool        `json:"observed,omitempty"`
	Source   string      `json:"source"`
	Tags     []string    `json:"tags,omitempty"` // the rule's ATT&CK tags (attack.tNNNN...), for OCSF + response selectors
	IOC      string      `json:"ioc,omitempty"`  // the matched indicator, for KindIOC
	Field    string      `json:"field,omitempty"`
	Message  string      `json:"message"`
	Event    event.Event `json:"event"`
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
	// mu serializes Dispatch and Close: banken's unified daemon dispatches from more than one
	// goroutine at once (a continuous stream follower and the periodic scanner share one
	// dispatcher), and a sink -- a day-file, a webhook -- is not required to be concurrency-safe.
	// It is held only for the quick fan-out (file writes, queueing the network sinks); no sink
	// blocks on the network under it, so it is never the latency bottleneck it once was.
	mu        sync.Mutex
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
	d.mu.Lock()
	defer d.mu.Unlock()
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
	d.mu.Lock()
	defer d.mu.Unlock()
	var errs []error
	for _, s := range d.sinks {
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
