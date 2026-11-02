package engine

import (
	"context"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/parser"
)

// StreamErrorKind classifies which stage of the follow loop produced an error, so the caller can
// log it structurally -- by kind, never by matching the error's text. The follow loop reports
// each of the four errors it would otherwise swallow (an unreadable sink, a failing parser, a
// dispatch sink, a cursor save) through its onError hook tagged with the matching kind.
type StreamErrorKind int

const (
	// StreamErrOpen: cursor.OpenAt failed. The sink is unreadable or not present yet, so the
	// loop saw nothing this drain; without surfacing it a mis-pathed or unreadable sink leaves
	// banken "following" forever and blind.
	StreamErrOpen StreamErrorKind = iota
	// StreamErrParse: the parser failed or panicked. The cursor is deliberately held (not
	// advanced) so the bytes are re-read, which means a sustained parser fault would otherwise
	// stall the stream silently.
	StreamErrParse
	// StreamErrSink: a dispatch sink returned an error (a webhook down, a file sink failing).
	// In scan mode scanSources logs these; in stream mode they were dropped.
	StreamErrSink
	// StreamErrSave: persisting the cursor failed. The offset advanced in memory but did not
	// reach disk, so a restart would re-read from the last saved point.
	StreamErrSave
)

// String names the kind for a log line (used by the daemon's recovery message).
func (k StreamErrorKind) String() string {
	switch k {
	case StreamErrOpen:
		return "open"
	case StreamErrParse:
		return "parse"
	case StreamErrSink:
		return "sink"
	case StreamErrSave:
		return "save"
	default:
		return "unknown"
	}
}

// edgeGate reports a recurring condition through onError only on its edges: once when the
// condition starts failing and once when it clears, never once per tick. The follow loop
// re-drains on a 1s safety tick (and on every inotify change), so an unreadable sink, a cursor
// stuck on an unparseable record, or an unwritable state file re-fails on every drain and would
// otherwise log every second. The gate switches on a boolean (is the condition failing?), never
// on the error's identity or text, so classification stays structural. err == nil is the recovery
// edge, reported so the caller can log that the fault cleared.
type edgeGate struct{ failing bool }

func (g *edgeGate) report(err error, kind StreamErrorKind, onError func(StreamErrorKind, error)) {
	switch {
	case err != nil && !g.failing:
		g.failing = true
		if onError != nil {
			onError(kind, err)
		}
	case err == nil && g.failing:
		g.failing = false
		if onError != nil {
			onError(kind, nil) // recovery edge
		}
	}
}

// StreamFollow consumes one source as a continuous push stream instead of on a scan interval: it
// processes whatever is already there, then blocks until the file grows and processes each new
// complete line as it arrives, dispatching alerts immediately. End-to-end detection latency is then
// capture + match, not bounded by any timer -- the point of a live sensor (mimi) feeding banken: two
// independently-timed stages would compound latency ("miss the bus").
//
// It reuses the one-shot path's guarantees rather than reinventing them: the cursor advances only to
// the last complete line (a partial trailing write is never split, and a restart resumes from the
// cursor without loss), rotation is handled on reopen, and each event matches under ProcessEvent's
// per-event panic guard so one pathological line degrades to a skipped event, never a dead stream.
//
// For every event that carried a capture time (the sensor stamps each one), onLatency -- when
// non-nil -- is called with the capture-to-match latency and the number of alerts it fired, so the
// caller can log or aggregate a real end-to-end number rather than assert "should be fast".
//
// onError -- when non-nil -- surfaces each error the drain would otherwise swallow, tagged with a
// StreamErrorKind so the caller logs it the same way scanSources logs the one-shot path's errors.
// Open, parse and save errors recur on every 1s drain while their condition holds, so they are
// reported on the failing edge and again on the recovery edge (not once per tick); sink errors fire
// only when a new matching event is dispatched (the cursor has advanced), so they are bounded by
// event volume exactly as in scan mode and are reported each occurrence. It returns when ctx is
// cancelled.
func (e *Engine) StreamFollow(ctx context.Context, p parser.Parser, path, statePath string,
	onLatency func(ev event.Event, latency time.Duration, alerts int),
	onError func(kind StreamErrorKind, err error),
) error {
	cursor, _ := LoadCursor(statePath)

	var openG, parseG, saveG edgeGate
	drain := func() {
		ch, err := cursor.OpenAt(path)
		openG.report(err, StreamErrOpen, onError)
		if err != nil {
			return // not present yet, or a transient open error; a later change re-drains
		}
		events, perr := e.safeParse(p, ch)
		parseG.report(perr, StreamErrParse, onError)
		for _, ev := range events {
			alerts, errs := e.ProcessEvent(ev)
			for _, se := range errs {
				if onError != nil {
					onError(StreamErrSink, se)
				}
			}
			if onLatency != nil && !ev.Time.IsZero() {
				onLatency(ev, time.Since(ev.Time), alerts)
			}
		}
		// Advance past complete lines only when the parse did not error, exactly as the one-shot
		// path does, so a partial trailing write or an I/O error is re-read, not skipped.
		if perr == nil {
			cursor.Offsets[path] = ch.NextOffset()
			if ino := ch.Ino(); ino != 0 {
				cursor.Inodes[path] = ino
			}
			saveG.report(cursor.Save(statePath), StreamErrSave, onError)
		}
		_ = ch.Close()
	}

	// Arm the watcher before the backlog drain, so a write that lands during the drain queues a
	// change the loop then picks up (inotify queues events; nothing between drain and wait is lost).
	w, err := newWatcher(path)
	if err != nil {
		return err
	}
	defer w.close()

	// Run the watcher in the background and signal a (coalescing) channel on each change, so the loop
	// can also wake on a slow safety-net tick. inotify stays the low-latency path.
	changed := make(chan struct{}, 1)
	go func() {
		for {
			if err := w.wait(ctx); err != nil {
				return // ctx cancelled, or the fd was closed on return
			}
			select {
			case changed <- struct{}{}:
			default:
			}
		}
	}()

	// A slow tick re-drains even when the inotify watch has gone stale: the sink can be armed before
	// it exists and created later (the sensor was still starting, or crash-looping and never wrote
	// it), or its directory inode can be replaced out from under the watch (the sensor's DynamicUser
	// LogsDirectory recreated across a restart). drain() re-resolves the path every time, so a 1s
	// floor guarantees banken picks the stream up within a second of it appearing or moving, without
	// coupling banken's lifecycle to the sensor's. The normal path stays inotify-fast.
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	drain()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
			drain()
		case <-tick.C:
			drain()
		}
	}
}
