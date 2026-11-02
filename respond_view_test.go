package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

// TestRespondExplainUnknownIDExits1 locks the exit-code contract of §3: an
// explain for an id that matches no decision, handle or spool order is a
// failure (exit 1, reason on stderr), not a silent empty success. The CLI runs
// against the real state dir (os.DirFS("/")); on a Mac that dir is absent, so a
// bogus id resolves to nothing and must exit 1.
func TestRespondExplainUnknownIDExits1(t *testing.T) {
	old := defaultConfigPath
	defaultConfigPath = filepath.Join(t.TempDir(), "absent.yml")
	t.Cleanup(func() { defaultConfigPath = old })

	var out, errb bytes.Buffer
	err := runRespondExplain([]string{"ffffffffffffffffffffffff"}, &out, &errb)
	var ee exitError
	if !errors.As(err, &ee) {
		t.Fatalf("explain unknown id: want an exitError, got %v", err)
	}
	if ee.code != 1 {
		t.Errorf("explain unknown id: exit code = %d, want 1", ee.code)
	}
}

// TestRespondExplainMissingIDIsUsage locks that a missing id argument is a
// usage error (exit 2), distinct from a lookup failure (exit 1).
func TestRespondExplainMissingIDIsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	err := runRespondExplain(nil, &out, &errb)
	var ee exitError
	if !errors.As(err, &ee) {
		t.Fatalf("explain with no id: want an exitError, got %v", err)
	}
	if ee.code != 2 {
		t.Errorf("explain with no id: exit code = %d, want 2", ee.code)
	}
}
