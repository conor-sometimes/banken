package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/conor-sometimes/banken/internal/config"
)

// writeConfigFor writes a minimal config file whose statePath lives in dir, and
// returns its path. The daemon's pidfile and refresh status file both derive
// from that statePath's directory, so a subcommand pointed at this config finds
// them with no other flags.
func writeConfigFor(t *testing.T, dir string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "banken.yml")
	body := "statePath: " + filepath.Join(dir, "cursor.json") + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// TestReloadSendsSIGHUPToPidfileDaemon proves `banken reload` resolves the
// daemon from its pidfile and sends it SIGHUP (the refresh trigger), using an
// injected sender so no real signal is delivered.
func TestReloadSendsSIGHUPToPidfileDaemon(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeConfigFor(t, dir)

	// A daemon wrote its pid here (we use a made-up pid; the sender is injected).
	pidPath := filepath.Join(dir, "banken.pid")
	const wantPid = 4242
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(wantPid)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var gotPid int
	var gotSig syscall.Signal
	calls := 0
	kill := func(pid int, sig syscall.Signal) error {
		calls++
		gotPid, gotSig = pid, sig
		return nil
	}

	var out, errOut bytes.Buffer
	if err := reloadWith([]string{"-config", cfgPath}, &out, &errOut, kill); err != nil {
		t.Fatalf("reloadWith: %v\nstderr: %s", err, errOut.String())
	}
	if calls != 1 {
		t.Fatalf("expected exactly one signal, got %d", calls)
	}
	if gotPid != wantPid {
		t.Fatalf("signalled pid %d, want %d", gotPid, wantPid)
	}
	if gotSig != syscall.SIGHUP {
		t.Fatalf("sent signal %v, want SIGHUP", gotSig)
	}
}

// TestReloadErrorsWithNoPidfile proves `banken reload` fails clearly (and sends
// nothing) when no daemon pidfile exists, rather than signalling a stray pid.
func TestReloadErrorsWithNoPidfile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeConfigFor(t, dir) // no pidfile written

	calls := 0
	kill := func(int, syscall.Signal) error { calls++; return nil }

	var out, errOut bytes.Buffer
	err := reloadWith([]string{"-config", cfgPath}, &out, &errOut, kill)
	if err == nil {
		t.Fatal("reloadWith returned nil with no pidfile, want an error")
	}
	if calls != 0 {
		t.Fatalf("a signal was sent (%d) despite there being no pidfile", calls)
	}
}

// TestPidFileRoundTrip proves writePidFile records this process's pid where
// pidFilePath expects it, and removePidFile clears it.
func TestPidFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{StatePath: filepath.Join(dir, "cursor.json")}

	if err := writePidFile(cfg); err != nil {
		t.Fatalf("writePidFile: %v", err)
	}
	pid, err := readPidFile(pidFilePath(cfg))
	if err != nil {
		t.Fatalf("readPidFile: %v", err)
	}
	if pid != os.Getpid() {
		t.Fatalf("pidfile has %d, want this process %d", pid, os.Getpid())
	}
	removePidFile(cfg)
	if _, err := os.Stat(pidFilePath(cfg)); !os.IsNotExist(err) {
		t.Fatalf("pidfile still present after removePidFile (stat err: %v)", err)
	}
}
