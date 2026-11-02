package alert

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// A network sink (webhook, OTLP) sends over HTTP with a 15s request timeout. If
// that send ran inline in Dispatch, a slow or hung endpoint would hold up the
// detection path: in the continuous daemon the stream follower could not
// dispatch its next alert, and the shared Dispatcher lock would stall the
// periodic scanner too, so a dead webhook silently throttles detection output.
// asyncSender moves the send off that path: Emit hands the alert to a bounded
// in-memory queue drained by one background goroutine, so Emit returns at memory
// speed and the HTTP latency never reaches a detection goroutine.
//
// An EDR must never drop an alert silently, so a full queue is explicit, not
// quiet: the alert is dropped, a counter is incremented, and the drop is
// returned from enqueue as an error (the caller logs it) and summarised again by
// close. Delivery failures from the background send (a non-2xx, a refused
// connection) are counted the same way and surfaced by close, since the sending
// goroutine has no caller to return them to.
//
// One goroutine drains the queue in order, so per-sink delivery stays FIFO:
// alerts reach the endpoint in the order they were dispatched, just not
// synchronously. (There was never a cross-sink ordering guarantee.)
type asyncSender struct {
	name    string
	deliver func(Alert) error
	queue   chan Alert
	stop    chan struct{} // closed by close once the flush budget is spent

	dropped atomic.Uint64
	failed  atomic.Uint64

	wg   sync.WaitGroup
	once sync.Once
}

// asyncQueueDepth bounds how many alerts a network sink may hold waiting to be
// sent. An alert is a few KB of JSON, so 1024 is a few MB ceiling: deep enough
// to ride out a brief sink stall (a slow endpoint, a reconnect) without dropping
// a normal burst, shallow enough that a genuinely hung endpoint fills it and
// starts dropping -- visibly, with a count -- in seconds rather than ballooning
// memory or delivering pages that are minutes stale.
const asyncQueueDepth = 1024

// asyncFlushTimeout bounds how long close spends draining still-queued alerts to
// a possibly-slow endpoint before it gives up and drops the rest (counted). It
// keeps a clean shutdown from hanging on a dead webhook. One send already in
// flight when the budget expires still finishes under its own request timeout,
// so worst-case shutdown is this budget plus one request timeout.
const asyncFlushTimeout = 5 * time.Second

// newAsyncSender starts the background sender. deliver is the synchronous send
// (the HTTP POST); it is called from exactly one goroutine, so it need not be
// concurrency-safe.
func newAsyncSender(name string, depth int, deliver func(Alert) error) *asyncSender {
	s := &asyncSender{
		name:    name,
		deliver: deliver,
		queue:   make(chan Alert, depth),
		stop:    make(chan struct{}),
	}
	s.wg.Add(1)
	go s.run()
	return s
}

func (s *asyncSender) run() {
	defer s.wg.Done()
	stopped := false
	for a := range s.queue {
		if !stopped {
			select {
			case <-s.stop:
				stopped = true
			default:
			}
		}
		if stopped {
			// Flush budget spent: treat the endpoint as hung and drain the rest
			// without sending, so close returns promptly instead of waiting on a
			// dead endpoint for every queued alert.
			s.dropped.Add(1)
			continue
		}
		if err := s.deliver(a); err != nil {
			s.failed.Add(1)
		}
	}
}

// enqueue hands one alert to the background sender without ever blocking. A full
// queue means the endpoint is not keeping up; the alert is dropped, counted, and
// the drop is returned as an error so a caller that logs dispatch errors reports
// it in real time -- the loss is never silent.
func (s *asyncSender) enqueue(a Alert) error {
	select {
	case s.queue <- a:
		return nil
	default:
		n := s.dropped.Add(1)
		return fmt.Errorf("%s: send queue full (%d deep), alert dropped -- endpoint slow or unreachable; %d dropped this run", s.name, cap(s.queue), n)
	}
}

// close flushes the queue for up to asyncFlushTimeout, stops the background
// sender, and returns a summary error if any alert was dropped or failed to send
// over the run (so even a daemon that only ever reports at shutdown sees the
// count). It is safe to call once, per the Sink contract.
func (s *asyncSender) close() error {
	s.once.Do(func() {
		timer := time.AfterFunc(asyncFlushTimeout, func() { close(s.stop) })
		close(s.queue)
		s.wg.Wait()
		timer.Stop() // if it already fired, Stop is a harmless no-op
	})
	d, f := s.dropped.Load(), s.failed.Load()
	if d == 0 && f == 0 {
		return nil
	}
	return fmt.Errorf("%s: %d alert(s) dropped (queue full) and %d delivery failure(s) over the run", s.name, d, f)
}
