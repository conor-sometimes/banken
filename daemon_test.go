package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/config"
	"github.com/conor-sometimes/banken/internal/engine"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// daemonSink counts dispatched alerts, safe to read while the daemon's goroutines write.
type daemonSink struct {
	mu   sync.Mutex
	seen int
}

func (s *daemonSink) Name() string           { return "daemon" }
func (s *daemonSink) Emit(alert.Alert) error { s.mu.Lock(); s.seen++; s.mu.Unlock(); return nil }
func (s *daemonSink) Close() error           { return nil }
func (s *daemonSink) count() int             { s.mu.Lock(); defer s.mu.Unlock(); return s.seen }

// TestRunDaemonFollowsStreamAndScansPeriodic proves the unified daemon: a mimi stream source is
// followed continuously while a non-stream source (generic) is scanned on the interval, both in one
// process sharing one dispatcher, and ctx cancellation shuts it down cleanly. The same act (a
// cat /etc/shadow exec) arrives on each source and each fires the one loaded rule, so two alerts is
// one-from-the-stream and one-from-the-scan.
func TestRunDaemonFollowsStreamAndScansPeriodic(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "smoke.yml"), []byte(smokeRule), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, problems := sigma.LoadTree(rulesDir) // just this rule, not the embedded baseline
	if len(problems) != 0 {
		t.Fatalf("rule problems: %v", problems)
	}
	if len(rules) != 1 {
		t.Fatalf("loaded %d rules, want 1", len(rules))
	}

	sink := &daemonSink{}
	eng := engine.New(rules, nil, alert.NewDispatcher(sink))

	mimiPath := filepath.Join(dir, "mimi.jsonl")
	genPath := filepath.Join(dir, "generic.jsonl")
	for _, p := range []string{mimiPath, genPath} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := config.Config{
		Sources: []config.Source{
			{Type: "mimi", Path: mimiPath},
			{Type: "generic", Path: genPath},
		},
		StatePath: filepath.Join(dir, "cursor.json"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, eng, cfg, 40*time.Millisecond, nil, io.Discard) }()

	// Stream (mimi, followed continuously): a cat /etc/shadow exec.
	appendLine(t, mimiPath, `{"schema":"mimi/2","time":"`+time.Now().UTC().Format(time.RFC3339Nano)+
		`","process":{"pid":7,"name":"cat","cmd_line":"cat /etc/shadow",`+
		`"file":{"path":"/usr/bin/cat"},"user":{"uid":"0"}},"ancestry":[{"pid":7,"name":"cat"}]}`)
	// Periodic (generic, scanned on the interval): the same act.
	appendLine(t, genPath, `{"image":"/usr/bin/cat","commandLine":"cat /etc/shadow"}`)

	deadline := time.Now().Add(3 * time.Second)
	for sink.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runDaemon returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runDaemon did not shut down within 2s of cancel")
	}

	if n := sink.count(); n != 2 {
		t.Fatalf("got %d alerts, want 2 (one from the followed mimi stream, one from the scanned generic source)", n)
	}
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Error(err)
	}
	_ = f.Close()
}
