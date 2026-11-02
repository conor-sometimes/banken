package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/config"
	"github.com/conor-sometimes/banken/internal/engine"
	"github.com/conor-sometimes/banken/internal/event"
)

// A rule that matches a made-up token no baseline rule reacts to, so a test can
// prove the rule went live by watching an event start to match after a refresh.
const reloadProbeRule = `title: reload probe
id: reload-probe
level: low
detection:
  sel:
    CommandLine|contains: BANKENPROBEONE
  condition: sel
`

// A second distinct probe, for proving two good rules co-load.
const reloadProbeRule2 = `title: reload probe two
id: reload-probe-2
level: low
detection:
  sel:
    CommandLine|contains: BANKENPROBETWO
  condition: sel
`

// A rule file that cannot compile (a detection block with no condition), so a
// refresh must report it and skip it without disturbing the good rules.
const badRule = `title: broken
detection:
  sel:
    CommandLine|contains: whatever
`

func probeEvent() event.Event {
	return event.Event{Image: "/bin/echo", CommandLine: "/bin/echo BANKENPROBEONE"}
}

func putRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestReloadRulesSwapsInRefreshDirRule proves requirement (1): a rule dropped
// into a refreshDir becomes live after a refresh, swapped into the running
// engine with no restart. Before the refresh the probe event matches nothing;
// after it, the probe rule fires.
func TestReloadRulesSwapsInRefreshDirRule(t *testing.T) {
	refreshDir := t.TempDir()
	cfg := config.Config{RefreshDirs: []string{refreshDir}}

	cs, err := buildCandidate(cfg)
	if err != nil {
		t.Fatalf("buildCandidate: %v", err)
	}
	eng := engine.New(cs.rules, cs.iocs, nil)

	if n := len(eng.Match(probeEvent())); n != 0 {
		t.Fatalf("probe already matches %d rule(s) before the rule exists; pick a more unique token", n)
	}

	putRule(t, refreshDir, "probe.yml", reloadProbeRule)
	reloadRules(eng, cfg, io.Discard)

	hits := eng.Match(probeEvent())
	if len(hits) != 1 {
		t.Fatalf("after refresh, probe event matched %d rule(s), want 1 (the rule did not swap in)", len(hits))
	}
	if hits[0].Rule != "probe" {
		t.Fatalf("matched rule %q, want %q", hits[0].Rule, "probe")
	}
}

// TestReloadRulesKeepsGoodSetOnBadRule proves requirement (2): a bad rule file
// in the dir is reported and skipped, and the previously-good rule set is
// retained (the good probe rule keeps firing; a second good rule added in the
// same refresh also loads). The build never crashes on the bad file.
func TestReloadRulesKeepsGoodSetOnBadRule(t *testing.T) {
	refreshDir := t.TempDir()
	cfg := config.Config{RefreshDirs: []string{refreshDir}}

	cs, err := buildCandidate(cfg)
	if err != nil {
		t.Fatalf("buildCandidate: %v", err)
	}
	eng := engine.New(cs.rules, cs.iocs, nil)

	// First refresh: one good rule. It goes live.
	putRule(t, refreshDir, "probe.yml", reloadProbeRule)
	reloadRules(eng, cfg, io.Discard)
	if n := len(eng.Match(probeEvent())); n != 1 {
		t.Fatalf("good rule not live after first refresh (got %d)", n)
	}

	// Second refresh: a bad file lands alongside the good ones, plus a second
	// good rule. The bad file must be reported and skipped; the good set must
	// survive intact.
	putRule(t, refreshDir, "broken.yml", badRule)
	putRule(t, refreshDir, "probe2.yml", reloadProbeRule2)
	var log bytes.Buffer
	reloadRules(eng, cfg, &log)

	if !strings.Contains(log.String(), "broken.yml") {
		t.Fatalf("bad rule file was not reported; log:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "swapped") {
		t.Fatalf("expected a successful swap despite the bad file; log:\n%s", log.String())
	}
	// Previously-good rule retained.
	if n := len(eng.Match(probeEvent())); n != 1 {
		t.Fatalf("previously-good rule was dropped by a refresh that hit a bad file (got %d)", n)
	}
	// The other good rule from the same refresh also loaded (bad one skipped, good ones kept).
	ev2 := event.Event{Image: "/bin/echo", CommandLine: "/bin/echo BANKENPROBETWO"}
	if n := len(eng.Match(ev2)); n != 1 {
		t.Fatalf("second good rule did not load past the bad file (got %d)", n)
	}
}

// TestRunDaemonReloadsOnSignalAndStaysUp proves the daemon's reload wiring
// end to end: a running daemon, with a periodic source and a refreshDir,
// receives a reload on its signal channel (the exact channel watch() feeds real
// SIGHUP into), rebuilds its rule set, and a rule added to the refreshDir then
// fires on a subsequently scanned event. The daemon never returns early or
// crashes across the reload (it stays up and shuts down cleanly only on
// cancel), which is the never-crash invariant.
func TestRunDaemonReloadsOnSignalAndStaysUp(t *testing.T) {
	dir := t.TempDir()
	refreshDir := filepath.Join(dir, "refresh")
	if err := os.MkdirAll(refreshDir, 0o755); err != nil {
		t.Fatal(err)
	}
	genPath := filepath.Join(dir, "generic.jsonl")
	if err := os.WriteFile(genPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{
		RefreshDirs: []string{refreshDir},
		Sources:     []config.Source{{Type: "generic", Path: genPath}},
		StatePath:   filepath.Join(dir, "cursor.json"),
	}

	// The engine starts with the baseline only (refreshDir empty), so the probe
	// event matches nothing yet.
	cs, err := buildCandidate(cfg)
	if err != nil {
		t.Fatalf("buildCandidate: %v", err)
	}
	sink := &daemonSink{}
	eng := engine.New(cs.rules, cs.iocs, alert.NewDispatcher(sink))

	reload := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, eng, cfg, 20*time.Millisecond, reload, io.Discard) }()

	// Add the rule to the refreshDir, then trigger a reload the way watch() does.
	putRule(t, refreshDir, "probe.yml", reloadProbeRule)
	reload <- syscall.SIGHUP

	// Give the reload time to be handled (several scan ticks), THEN write the
	// event line, so it is only ever scanned under the new rule set.
	time.Sleep(200 * time.Millisecond)
	appendLine(t, genPath, `{"image":"/bin/echo","commandLine":"/bin/echo BANKENPROBEONE"}`)

	deadline := time.Now().Add(3 * time.Second)
	for sink.count() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// The daemon must still be running (not returned) right up to cancel.
	select {
	case err := <-done:
		t.Fatalf("daemon returned early (%v) instead of staying up across the reload", err)
	default:
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

	if n := sink.count(); n < 1 {
		t.Fatalf("reloaded rule never fired on a scanned event (got %d alerts); the SIGHUP refresh did not take effect", n)
	}
}

// TestCheckDirPreflightExitCodes proves requirement (3): `banken check <dir>`
// exits zero on a clean rules tree and non-zero on one with a bad rule.
func TestCheckDirPreflightExitCodes(t *testing.T) {
	// Clean tree: one good rule, exit 0 (nil error).
	clean := t.TempDir()
	putRule(t, clean, "probe.yml", reloadProbeRule)
	var out, errOut bytes.Buffer
	if err := runCheck([]string{clean}, &out, &errOut); err != nil {
		t.Fatalf("clean dir: runCheck returned %v (want nil / exit 0)\nstdout: %s\nstderr: %s", err, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "1 rule(s) compiled, 0 errors") {
		t.Fatalf("clean dir: unexpected summary: %s", out.String())
	}

	// Dirty tree: a bad rule, non-zero exit (exitError code 2).
	dirty := t.TempDir()
	putRule(t, dirty, "probe.yml", reloadProbeRule)
	putRule(t, dirty, "broken.yml", badRule)
	out.Reset()
	errOut.Reset()
	err := runCheck([]string{dirty}, &out, &errOut)
	if err == nil {
		t.Fatalf("dirty dir: runCheck returned nil, want a non-zero exit error")
	}
	var ee exitError
	if !errors.As(err, &ee) {
		t.Fatalf("dirty dir: error %T is not an exitError", err)
	}
	if ee.code == 0 {
		t.Fatalf("dirty dir: exit code is 0, want non-zero")
	}
	if !strings.Contains(errOut.String(), "broken.yml") {
		t.Fatalf("dirty dir: bad rule file not named in the error output: %s", errOut.String())
	}

	// Empty tree: no rules is also a non-zero exit (nothing to load).
	empty := t.TempDir()
	out.Reset()
	errOut.Reset()
	if err := runCheck([]string{empty}, &out, &errOut); err == nil {
		t.Fatalf("empty dir: runCheck returned nil, want a non-zero exit error")
	}
}
