package engine

import (
	"context"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/parser"
)

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
// caller can log or aggregate a real end-to-end number rather than assert "should be fast". It
// returns when ctx is cancelled.
func (e *Engine) StreamFollow(ctx context.Context, p parser.Parser, path, statePath string,
	onLatency func(ev event.Event, latency time.Duration, alerts int)) error {
	cursor, _ := LoadCursor(statePath)

	drain := func() {
		ch, err := cursor.OpenAt(path)
		if err != nil {
			return // not present yet, or a transient open error; a later change re-drains
		}
		events, perr := e.safeParse(p, ch)
		for _, ev := range events {
			alerts, _ := e.ProcessEvent(ev)
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
			_ = cursor.Save(statePath)
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

	drain()
	for {
		if err := w.wait(ctx); err != nil {
			return err
		}
		drain()
	}
}
