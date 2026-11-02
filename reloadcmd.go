package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/conor-sometimes/banken/internal/config"
)

// pidFilePath is where the long-running daemon records its pid so `banken
// reload` can find it with no systemd and no flags: banken.pid in the state
// directory (beside the cursor). It returns "" when no state path is set, which
// disables the pidfile (an ad-hoc foreground run that an operator signals by
// hand). Keeping the binary self-contained -- a pidfile rather than a shell-out
// to systemctl -- is what lets `banken reload` work the same on a non-systemd
// host (docs/design/rule-refresh.md section 5).
func pidFilePath(cfg config.Config) string {
	if cfg.StatePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(cfg.StatePath), "banken.pid")
}

// writePidFile records the current pid at pidFilePath(cfg). A failure is
// returned, not fatal to the caller: the daemon runs fine without it, only
// `banken reload`'s pid discovery is lost (the operator can still SIGHUP by
// hand or via systemctl reload). A no-op when no pidfile path is configured.
func writePidFile(cfg config.Config) error {
	path := pidFilePath(cfg)
	if path == "" {
		return nil
	}
	// 0600: the pidfile lives in the 0700 state directory (root-only), so the
	// mode is moot in practice, and 0600 keeps the static-analysis gate happy.
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
}

// removePidFile removes the pidfile on daemon shutdown so a stale pid never
// outlives the process. Best-effort: a missing file is fine.
func removePidFile(cfg config.Config) {
	if path := pidFilePath(cfg); path != "" {
		_ = os.Remove(path)
	}
}

// runReload is the `banken reload` subcommand: it finds the running daemon via
// its pidfile and sends it SIGHUP, so an operator (or the fleet puller) triggers
// a live rule refresh without knowing the pid and without a restart. The
// mechanism is exactly the signal systemctl reload sends; this is the
// no-systemd / scriptable path to the same thing.
func runReload(args []string, stdout, stderr io.Writer) error {
	return reloadWith(args, stdout, stderr, syscall.Kill)
}

// reloadWith is runReload with an injectable signal sender, so a test can prove
// the right pid is signalled without delivering a real SIGHUP.
func reloadWith(args []string, stdout, stderr io.Writer, kill func(pid int, sig syscall.Signal) error) error {
	fs := flag.NewFlagSet("banken reload", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to the YAML config (to locate the daemon pidfile; default "+defaultConfigPath+" if it exists)")
	fs.Usage = func() {
		logln(stderr, "usage: banken reload [-config path]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := configForCmd(configPath)
	if err != nil {
		return err
	}
	path := pidFilePath(cfg)
	if path == "" {
		return errors.New("no state path configured, so the daemon pidfile cannot be located (set statePath, or send SIGHUP yourself)")
	}
	pid, err := readPidFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no running banken daemon found (no pidfile at %s); reload is for the --watch/--follow daemon, a one-shot timer run reloads on its next scan", path)
		}
		return err
	}
	if err := kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("sending SIGHUP to banken daemon (pid %d): %w", pid, err)
	}
	logf(stdout, "banken: sent SIGHUP to the daemon (pid %d); it will rebuild its rule set\n", pid)
	return nil
}

// readPidFile reads and parses the pid from a pidfile.
func readPidFile(path string) (int, error) {
	data, err := os.ReadFile(path) //nolint:gosec // state-dir pidfile, same trust as the config
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("pidfile %s does not contain a pid: %w", path, err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("pidfile %s has a non-positive pid %d", path, pid)
	}
	return pid, nil
}

// configForCmd loads the config a non-scan subcommand (reload, status) needs to
// locate the daemon's state directory: the named -config, else the default path
// if it exists, else the built-in defaults. It applies no flag overrides -- it
// only needs the paths.
func configForCmd(configPath string) (config.Config, error) {
	path := configPath
	if path == "" {
		if _, err := os.Stat(defaultConfigPath); err == nil {
			path = defaultConfigPath
		}
	}
	if path == "" {
		return config.Default(), nil
	}
	return config.Load(path)
}
