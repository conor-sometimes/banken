package alert

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

// syslog severity levels (RFC 5424), the ones banken uses.
const (
	sevCrit    = 2
	sevErr     = 3
	sevWarning = 4
	sevNotice  = 5
)

// facilityDaemon is the syslog facility banken logs under.
const facilityDaemon = 3

// JournalSink writes high/critical alerts to the system journal as
// syslog-priority-prefixed lines, and on Close writes the one-line login
// summary an admin sees ("banken: N alerts since ..."). Lower-severity
// alerts are not journalled (they still reach jsonl/webhook) to keep the
// journal to what warrants a human's attention.
//
// The sink writes to any io.Writer: main points it at a *syslog.Writer (or
// stderr under systemd, which journals it); tests point it at a buffer.
type JournalSink struct {
	mu      sync.Mutex
	w       io.Writer
	count   int
	byLevel map[string]int
}

// NewJournalSink writes priority-tagged lines to w.
func NewJournalSink(w io.Writer) *JournalSink {
	return &JournalSink{w: w, byLevel: map[string]int{}}
}

// Name implements Sink.
func (*JournalSink) Name() string { return "journal" }

// Emit implements Sink: critical and high go to the journal; the sink
// counts every level for the Close summary.
func (j *JournalSink) Emit(a Alert) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.count++
	j.byLevel[strings.ToLower(a.Level)]++

	sev, journalled := severityFor(a.Level)
	if !journalled {
		return nil
	}
	pri := facilityDaemon*8 + sev
	line := fmt.Sprintf("<%d>banken[%s]: %s %s (%s) image=%q cmd=%q user=%q\n",
		pri, a.Level, a.Rule, a.Title, a.Source, a.Event.Image, a.Event.CommandLine, a.Event.User)
	_, err := io.WriteString(j.w, line)
	return err
}

// Close writes the one-line login summary and is otherwise a no-op.
func (j *JournalSink) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.count == 0 {
		return nil
	}
	pri := facilityDaemon*8 + sevNotice
	line := fmt.Sprintf("<%d>banken: %d alert(s) this run (%s)\n", pri, j.count, summaryBreakdown(j.byLevel))
	_, err := io.WriteString(j.w, line)
	return err
}

// severityFor maps a rule level to a syslog severity and whether it is
// journalled at all (only critical/high are).
func severityFor(level string) (sev int, journalled bool) {
	switch strings.ToLower(level) {
	case "critical":
		return sevCrit, true
	case "high":
		return sevErr, true
	case "medium":
		return sevWarning, false
	default:
		return sevNotice, false
	}
}

func summaryBreakdown(byLevel map[string]int) string {
	var parts []string
	for _, lvl := range []string{"critical", "high", "medium", "low"} {
		if n := byLevel[lvl]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", lvl, n))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}
