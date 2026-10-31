// Package parser turns a raw log source into the common event.Event
// stream the rules match against. There is one parser per source, all
// behind the Parser interface, so adding a log type is adding a parser
// and nothing else changes.
//
// The cardinal rule, enforced by a Fuzz* target per parser: a parser
// never panics and never mis-normalises on malformed, truncated or
// adversarial input. A log is untrusted bytes; a parser that crashes on a
// bad line hands an attacker a way to switch the detection off by writing
// one. So every parser here skips what it cannot understand and keeps
// going, and only ever returns an error for a condition that makes the
// whole stream unreadable (an I/O failure), never for bad content.
package parser

import (
	"io"

	"github.com/conor-sometimes/banken/internal/event"
)

// Parser reads a single log source and normalises it to events.
type Parser interface {
	// Name is the source tag the parser stamps onto every event it
	// produces ("laurel", "auditd", ...).
	Name() string

	// Parse reads r to completion and returns the events it found, in the
	// order they appeared. It returns a non-nil error only for an I/O
	// failure reading r; malformed content is skipped, never surfaced as
	// an error, so a caller always gets every event that was parseable
	// even when some of the input was garbage.
	Parse(r io.Reader) ([]event.Event, error)
}

// Registry maps a source name to the parser that handles it.
func Registry() map[string]Parser {
	return map[string]Parser{
		laurelName:   Laurel{},
		auditdName:   Auditd{},
		journaldName: Journald{},
		syslogName:   Syslog{},
	}
}

// decodeHexField decodes an auditd/audit-style hex-encoded field value
// back to its literal string. auditd encodes a field as an even-length
// run of hex digits (no quotes) when its value contains a space, quote or
// other non-printable byte; a NUL separates argv elements inside a hex
// PROCTITLE. A value that is not valid even-length hex is returned
// unchanged, so this is always safe to try on a field that might be
// encoded. It never panics.
func decodeHexField(s string) string {
	if s == "" || len(s)%2 != 0 {
		return s
	}
	buf := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, ok1 := hexVal(s[i])
		lo, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			return s // not pure hex -- it was a literal all along
		}
		buf = append(buf, hi<<4|lo)
	}
	// NUL bytes separate argv words in a hex proctitle; render as spaces,
	// matching how the EXECVE argv join reads.
	for i, b := range buf {
		if b == 0 {
			buf[i] = ' '
		}
	}
	return string(buf)
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
