package alert

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestSlowSinkDoesNotBlockDispatch is the regression test for ROUGHEDGE M9: a
// hung HTTP sink must not put its latency on the detection path. A webhook
// pointed at a receiver that never responds is dispatched alongside a fast
// (local) sink; dispatch must return at memory speed and the fast sink must see
// every alert, instead of each Dispatch blocking on the webhook's request
// timeout as it did when the POST ran inline under the Dispatcher lock.
func TestSlowSinkDoesNotBlockDispatch(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // hang until the test frees us
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer unblock() // free the handler so srv.Close() can return

	slow, err := NewWebhookSink(WebhookConfig{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	fast := &recordingSink{name: "fast"}
	d := NewDispatcher(fast, slow)

	const n = 5
	start := time.Now()
	for range n {
		d.Dispatch(sampleAlert("high"))
	}
	elapsed := time.Since(start)

	// Inline (the bug) each Dispatch would block on the webhook's 15s request
	// timeout; async delivery makes this microseconds. 2s cleanly separates them.
	if elapsed > 2*time.Second {
		t.Fatalf("dispatching %d alerts took %v while the webhook receiver was hung; "+
			"a slow HTTP sink is still on the detection path", n, elapsed)
	}
	if len(fast.got) != n {
		t.Fatalf("fast sink received %d/%d alerts; the hung sink delayed dispatch to the others", len(fast.got), n)
	}

	unblock() // let the background sender drain so Close returns promptly
	if err := slow.Close(); err != nil {
		// A clean release means everything flushed; log rather than fail, since
		// the property under test is non-blocking dispatch, proven above.
		t.Logf("webhook close summary: %v", err)
	}
}

// TestAsyncSenderDropsWhenFullWithoutBlocking proves the bounded queue: when the
// endpoint is stuck and the queue is full, enqueue drops the alert and returns
// at once with an error -- a visible, counted loss, never a block and never
// silent.
func TestAsyncSenderDropsWhenFullWithoutBlocking(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	deliver := func(Alert) error {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release // block the sender on whatever it dequeues first
		return nil
	}
	s := newAsyncSender("test", 1, deliver) // depth 1: easy to fill

	// a1 is dequeued and the sender blocks in deliver; the one-slot buffer empties.
	if err := s.enqueue(sampleAlert("high")); err != nil {
		t.Fatalf("enqueue a1: %v", err)
	}
	<-started // the sender is now parked inside deliver

	// a2 fills the single buffer slot.
	if err := s.enqueue(sampleAlert("high")); err != nil {
		t.Fatalf("enqueue a2 should fit the buffer: %v", err)
	}

	// a3 has nowhere to go: it must drop immediately, without blocking.
	start := time.Now()
	if err := s.enqueue(sampleAlert("high")); err == nil {
		t.Fatal("enqueue into a full queue must return a drop error")
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("enqueue blocked %v on a full queue; it must drop and return at once", d)
	}
	if got := s.dropped.Load(); got != 1 {
		t.Fatalf("dropped counter = %d, want 1", got)
	}

	close(release) // let the sender finish so close returns
	if err := s.close(); err == nil {
		t.Error("close must report the drop in its run summary")
	}
}

// TestAsyncSenderFlushesInOrderOnClose proves Close is not lossy on a healthy
// endpoint: everything queued is delivered, in dispatch (FIFO) order.
func TestAsyncSenderFlushesInOrderOnClose(t *testing.T) {
	var mu sync.Mutex
	var order []string
	deliver := func(a Alert) error {
		mu.Lock()
		order = append(order, a.Rule)
		mu.Unlock()
		return nil
	}
	s := newAsyncSender("test", 8, deliver)

	want := []string{"r0", "r1", "r2", "r3"}
	for _, r := range want {
		a := sampleAlert("high")
		a.Rule = r
		if err := s.enqueue(a); err != nil {
			t.Fatalf("enqueue %s: %v", r, err)
		}
	}
	if err := s.close(); err != nil {
		t.Fatalf("close reported loss on a healthy sender: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(order) != len(want) {
		t.Fatalf("delivered %v, want all of %v flushed", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("delivery order = %v, want FIFO %v", order, want)
		}
	}
}
