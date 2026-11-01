package parser

import (
	"strings"
	"testing"
)

// A parser callback that panics on one crafted line must not take out the whole source. scanLines
// recovers per line, drops the poisoned one, and keeps emitting the rest, so Parse returns the good
// events with no error and the cursor advances past the bad bytes (instead of re-reading them until
// the file rotates). This is the "one bad line never blinds a source" contract at the line level.
func TestScanLinesRecoversPanickingEmit(t *testing.T) {
	var got []string
	err := scanLines(strings.NewReader("a\nBOOM\nc\n"), func(line []byte) {
		if string(line) == "BOOM" {
			panic("crafted line that trips a parser bug")
		}
		got = append(got, string(line))
	})
	if err != nil {
		t.Fatalf("scanLines returned error: %v", err)
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("got %v, want [a c] (the panicking line skipped, the rest emitted)", got)
	}
}
