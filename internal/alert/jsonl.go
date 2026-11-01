package alert

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// jsonlFilePattern matches the per-day alert files so retention pruning
// never touches an unrelated file in the directory.
var jsonlFilePattern = regexp.MustCompile(`^alerts-(\d{4}-\d{2}-\d{2})\.jsonl$`)

const dayLayout = "2006-01-02"

// JSONLSink appends each alert as one JSON line to a per-day file
// (alerts-YYYY-MM-DD.jsonl) in a directory, and prunes files older than
// RetentionDays so retention is a plain file delete -- no rotation daemon,
// no index. A RetentionDays of 0 disables pruning (keep forever).
type JSONLSink struct {
	mu            sync.Mutex
	dir           string
	retentionDays int
	fileMode      os.FileMode      // per-day file mode (default 0600)
	enc           Encoder          // how each alert is rendered (nil = EncodeAlert)
	now           func() time.Time // injectable clock for tests
}

// NewJSONLSink creates the directory if needed and prunes stale files. It
// writes banken's native JSON; NewJSONLSinkEncoded chooses another encoding
// (e.g. OCSF) over the same per-day files and retention.
func NewJSONLSink(dir string, retentionDays int) (*JSONLSink, error) {
	return NewJSONLSinkEncoded(dir, retentionDays, EncodeAlert)
}

// NewJSONLSinkEncoded is NewJSONLSink with an explicit encoder, so the same
// file rotation and retention serve either the native shape or OCSF. A nil
// encoder falls back to EncodeAlert. Files are owner-only (0600).
func NewJSONLSinkEncoded(dir string, retentionDays int, enc Encoder) (*JSONLSink, error) {
	return NewJSONLSinkEncodedMode(dir, retentionDays, enc, 0o600)
}

// NewJSONLSinkEncodedMode is NewJSONLSinkEncoded with an explicit per-day file
// mode. The default (0600, via the other constructors) keeps the log
// owner-only; 0640 lets a log-reader group read it when the directory is
// setgid-owned by that group, so new files inherit it -- banken runs with
// CAP_DAC_READ_SEARCH only (no CAP_CHOWN), so it never chowns, and the
// directory's group ownership is arranged by the deployment (the NixOS
// module), not here. A zero fileMode falls back to 0600.
func NewJSONLSinkEncodedMode(dir string, retentionDays int, enc Encoder, fileMode os.FileMode) (*JSONLSink, error) {
	// When the files are group-readable, create the directory setgid so files
	// created in it inherit its group (the reader group the module set), since
	// banken cannot chown them itself. Harmless if banken is not the one that
	// creates the dir (the module's tmpfiles rule usually is).
	dirMode := os.FileMode(0o750)
	if fileMode&0o040 != 0 {
		dirMode |= os.ModeSetgid
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("jsonl: create dir: %w", err)
	}
	if enc == nil {
		enc = EncodeAlert
	}
	if fileMode == 0 {
		fileMode = 0o600
	}
	s := &JSONLSink{dir: dir, retentionDays: retentionDays, fileMode: fileMode, enc: enc, now: time.Now}
	s.prune(s.now())
	return s, nil
}

// Name implements Sink.
func (*JSONLSink) Name() string { return "jsonl" }

// Emit appends the alert to the file for its day (falling back to today if
// the event carried no timestamp).
func (s *JSONLSink) Emit(a Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	day := a.Time
	if day.IsZero() {
		day = s.now()
	}
	path := filepath.Join(s.dir, "alerts-"+day.UTC().Format(dayLayout)+".jsonl")

	enc := s.enc
	if enc == nil {
		enc = EncodeAlert
	}
	line, err := enc(a)
	if err != nil {
		return fmt.Errorf("jsonl: marshal: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, s.fileMode)
	if err != nil {
		return fmt.Errorf("jsonl: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("jsonl: write %s: %w", path, err)
	}
	return nil
}

// Close implements Sink (nothing buffered; files are closed per-write).
func (*JSONLSink) Close() error { return nil }

// prune deletes alert files whose day is older than retentionDays before
// now. retentionDays <= 0 keeps everything.
func (s *JSONLSink) prune(now time.Time) {
	if s.retentionDays <= 0 {
		return
	}
	cutoff := now.UTC().AddDate(0, 0, -s.retentionDays)
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		m := jsonlFilePattern.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		day, err := time.Parse(dayLayout, m[1])
		if err != nil {
			continue
		}
		if day.Before(cutoff) {
			_ = os.Remove(filepath.Join(s.dir, e.Name()))
		}
	}
}
