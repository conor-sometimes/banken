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
	"bufio"
	"errors"
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

// maxLineBytes caps one log line. A real auditd record or Laurel event is a
// few KB; 1 MiB is far above any legitimate line, so a longer one is junk (or
// an attempt to choke the parser) and is skipped -- never buffered unboundedly
// and never turned into an error that would fail the batch.
const maxLineBytes = 1 << 20

// scanLines calls emit once per newline-delimited line of r, with the
// trailing CR/LF stripped and empty lines dropped. It is the heart of the
// parser contract: it NEVER fails on content -- a line longer than
// maxLineBytes is skipped (drained to the next newline), not buffered and not
// surfaced as an error -- and returns a non-nil error ONLY for a genuine read
// failure of r. A final line with no trailing newline is still emitted.
//
// The []byte handed to emit is valid only for that call; a parser must read it
// (parse/copy), never retain it, because the backing array is reused.
func scanLines(r io.Reader, emit func([]byte)) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var line []byte
	skip := false // the current line already blew the cap: drain and drop it
	for {
		chunk, err := br.ReadSlice('\n')
		switch {
		case err == nil, errors.Is(err, io.EOF):
			if !skip && len(line)+len(chunk) <= maxLineBytes {
				line = append(line, chunk...)
				if t := trimLineEnd(line); len(t) > 0 {
					safeEmit(emit, t)
				}
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			line, skip = line[:0], false
		case errors.Is(err, bufio.ErrBufferFull): // line spans the buffer; keep reading it
			if skip || len(line)+len(chunk) > maxLineBytes {
				line, skip = line[:0], true
			} else {
				line = append(line, chunk...)
			}
		default:
			return err // a real I/O error -- the stream is unreadable
		}
	}
}

// safeEmit runs emit under a recover, so a parser callback that panics on one crafted line drops
// only that line and scanLines keeps going -- rather than the panic unwinding through Parse to the
// engine's per-source recover, which would discard every event of the source AND leave the cursor
// stuck on the poisoned bytes, re-reading them until the file rotates (blinding that source for
// hours). A panicking line is treated like any other line the parser cannot understand: skipped.
// The engine's per-source recover stays as a backstop for a panic outside emit.
func safeEmit(emit func([]byte), line []byte) {
	defer func() { _ = recover() }()
	emit(line)
}

func trimLineEnd(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// Registry maps a source name to the parser that handles it.
func Registry() map[string]Parser {
	return map[string]Parser{
		laurelName:   Laurel{},
		auditdName:   Auditd{},
		journaldName: Journald{},
		syslogName:   Syslog{},
		genericName:  Generic{},
		mimiName:     Mimi{},
		sysmonName:   Sysmon{},
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
