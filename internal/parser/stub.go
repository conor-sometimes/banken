package parser

import (
	"io"

	"github.com/conor-sometimes/banken/internal/event"
)

const (
	journaldName = "journald"
	syslogName   = "syslog"
)

// Journald is a placeholder parser for systemd-journal export output,
// behind the same interface as the real parsers so wiring it up later is a
// matter of filling Parse in -- nothing else in banken changes. It reads
// its input to completion (so a caller's cursor still advances past the
// bytes) and returns no events.
//
// TODO(banken): implement the journald export-format parser
// (_COMM / _EXE / _CMDLINE / _UID fields, one entry per double-newline).
type Journald struct{}

// Name implements Parser.
func (Journald) Name() string { return journaldName }

// Parse implements Parser. Stub: drains r, emits nothing.
func (Journald) Parse(r io.Reader) ([]event.Event, error) {
	_, err := io.Copy(io.Discard, r)
	return nil, err
}

// Syslog is a placeholder parser for RFC 3164/5424 syslog/auth.log lines,
// behind the same interface as the real parsers.
//
// TODO(banken): implement the syslog/auth.log parser (sshd accepted/failed
// logins, sudo sessions -> the login summary and privilege-escalation
// rules).
type Syslog struct{}

// Name implements Parser.
func (Syslog) Name() string { return syslogName }

// Parse implements Parser. Stub: drains r, emits nothing.
func (Syslog) Parse(r io.Reader) ([]event.Event, error) {
	_, err := io.Copy(io.Discard, r)
	return nil, err
}
