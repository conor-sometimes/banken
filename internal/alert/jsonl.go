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
// encoder falls back to EncodeAlert.
func NewJSONLSinkEncoded(dir string, retentionDays int, enc Encoder) (*JSONLSink, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("jsonl: create dir: %w", err)
	}
	if enc == nil {
		enc = EncodeAlert
	}
	s := &JSONLSink{dir: dir, retentionDays: retentionDays, enc: enc, now: time.Now}
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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
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
