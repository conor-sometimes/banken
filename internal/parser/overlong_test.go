package parser

import (
	"strings"
	"testing"
)

// TestOverLongLineSkippedNotFailed is the A1 regression: one pathological
// over-long line must be skipped, never crash, fail the batch, or lose the
// surrounding events. Before the fix a 4 MiB-capped bufio.Scanner returned
// ErrTooLong and Parse discarded the whole batch - blinding the source.
func TestOverLongLineSkippedNotFailed(t *testing.T) {
	good1 := `{"ID":"1.000:1","SYSCALL":{"exe":"/usr/bin/cat"},"EXECVE":{"argc":"2","ARGV":["cat","/etc/shadow"]}}`
	good2 := `{"ID":"1.000:2","SYSCALL":{"exe":"/bin/bash"},"EXECVE":{"argc":"1","ARGV":["bash"]}}`
	huge := `{"junk":"` + strings.Repeat("A", 5*1024*1024) + `"}` // 5 MiB, well over maxLineBytes
	log := good1 + "\n" + huge + "\n" + good2 + "\n"

	events, err := Laurel{}.Parse(strings.NewReader(log))
	if err != nil {
		t.Fatalf("Parse returned an error on an over-long line (A1 regression): %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 - the over-long line skipped, both good events kept", len(events))
	}
	if events[0].Image != "/usr/bin/cat" || events[1].Image != "/bin/bash" {
		t.Errorf("surrounding events corrupted: %q, %q", events[0].Image, events[1].Image)
	}
}

// TestAuditdOverLongLineSkipped is the same guarantee for the raw auditd
// parser (a multi-MB hex argv must not take the batch down).
func TestAuditdOverLongLineSkipped(t *testing.T) {
	good := "type=SYSCALL msg=audit(1.0:1): exe=\"/bin/sh\"\n" +
		"type=EXECVE msg=audit(1.0:1): argc=1 a0=\"sh\"\n"
	huge := "type=EXECVE msg=audit(1.0:2): argc=1 a0=" + strings.Repeat("41", 3*1024*1024) + "\n"
	good2 := "type=SYSCALL msg=audit(1.0:3): exe=\"/usr/bin/cat\"\n"

	events, err := Auditd{}.Parse(strings.NewReader(good + huge + good2))
	if err != nil {
		t.Fatalf("Parse returned an error on an over-long line (A1 regression): %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("got %d events, want >=2 - the over-long record skipped, the good ones kept", len(events))
	}
}

// TestNoFinalNewlineStillParsed guards the scanLines edge where the last line
// has no trailing newline - it must still be emitted.
func TestNoFinalNewlineStillParsed(t *testing.T) {
	log := `{"ID":"1.000:1","SYSCALL":{"exe":"/usr/bin/id"}}` // no trailing \n
	events, err := Laurel{}.Parse(strings.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Image != "/usr/bin/id" {
		t.Fatalf("final unterminated line lost: %+v", events)
	}
}
