package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/conor-sometimes/banken/internal/config"
)

// Refresh outcomes recorded in the status file. startup is the set the process
// loaded at launch; swapped is a refresh that installed a new set; kept-old is a
// refresh that was refused (empty, over-cap, or a build error) and left the
// previously-good set running.
const (
	refreshStartup = "startup"
	refreshSwapped = "swapped"
	refreshKeptOld = "kept-old"
)

// RefreshStatus is the record written atomically on every refresh and at
// startup, and read by `banken status`. It answers "did the new rule actually
// go live on this host?" without guessing: the outcome, the counts, the
// per-file errors, and the baseline overrides (docs/design/rule-refresh.md
// section 9). JSON so a fleet tool can scrape it; the field names are stable.
type RefreshStatus struct {
	Time        time.Time          `json:"time"`
	Outcome     string             `json:"outcome"`          // startup | swapped | kept-old
	Reason      string             `json:"reason,omitempty"` // why a refresh was kept-old
	RulesLoaded int                `json:"rulesLoaded"`
	RulesFailed int                `json:"rulesFailed"`
	Failed      []RefreshFileError `json:"failed,omitempty"`
	IOCCount    int                `json:"iocCount"`
	Dirs        []string           `json:"dirs,omitempty"`
	Overrides   []RefreshOverride  `json:"baselineOverrides,omitempty"`
}

// RefreshFileError is one rule file that failed to compile on the recorded
// refresh (the rule is absent; the good rules loaded).
type RefreshFileError struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// RefreshOverride is one on-disk rule shadowing a baseline rule, carried into
// the status file so a shadowing push is visible to a fleet operator, not only
// in the journal. Blocked marks one protectBaseline refused.
type RefreshOverride struct {
	Name           string `json:"name"`
	WinnerPath     string `json:"winnerPath"`
	OverriddenPath string `json:"overriddenPath"`
	Blocked        bool   `json:"blocked,omitempty"`
}

// refreshStatusPath is where the status file lives: the configured StatusPath,
// else refresh-status.json beside the cursor in the state directory. It returns
// "" when neither is set (an ad-hoc run with no state dir, e.g. a bare `banken
// check`), which tells recordRefresh to skip writing rather than litter the cwd.
func refreshStatusPath(cfg config.Config) string {
	if cfg.Refresh.StatusPath != "" {
		return cfg.Refresh.StatusPath
	}
	if cfg.StatePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(cfg.StatePath), "refresh-status.json")
}

// recordRefresh builds a RefreshStatus from a candidate set and writes it
// atomically. It never fails a refresh: a write error is logged and swallowed
// (the status file is observability, not the detection path). It is a no-op
// when no status path can be resolved.
func recordRefresh(cfg config.Config, outcome, reason string, cs candidateSet, stderr io.Writer) {
	path := refreshStatusPath(cfg)
	if path == "" {
		return
	}
	st := RefreshStatus{
		Time:        time.Now().UTC(),
		Outcome:     outcome,
		Reason:      reason,
		RulesLoaded: len(cs.rules),
		RulesFailed: len(cs.problems),
		Dirs:        ruleDirs(cfg),
	}
	if cs.iocs != nil {
		st.IOCCount = cs.iocs.Len()
	}
	for _, p := range cs.problems {
		st.Failed = append(st.Failed, RefreshFileError{Path: p.Path, Error: p.Error()})
	}
	for _, ov := range cs.overrides {
		st.Overrides = append(st.Overrides, RefreshOverride{
			Name:           ov.name,
			WinnerPath:     ov.winnerPath,
			OverriddenPath: ov.overriddenPath,
			Blocked:        ov.blocked,
		})
	}
	if err := writeRefreshStatus(path, st); err != nil {
		logAt(stderr, levelWarning, "banken: could not write refresh status to %s: %v", path, err)
	}
}

// writeRefreshStatus marshals the status and writes it atomically (temp file in
// the same dir, then rename), so a reader never sees a half-written file and a
// crash mid-write cannot corrupt the previous status.
func writeRefreshStatus(path string, st RefreshStatus) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".refresh-status-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // harmless no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// readRefreshStatus reads and parses the status file.
func readRefreshStatus(path string) (RefreshStatus, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator/state-dir path, same trust as the config
	if err != nil {
		return RefreshStatus{}, err
	}
	var st RefreshStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return RefreshStatus{}, fmt.Errorf("refresh status %s: %w", path, err)
	}
	return st, nil
}

// runStatus is the `banken status` subcommand: it reads the refresh status file
// and prints a human summary, so an operator can confirm which rule set is live
// on this host and whether the last refresh took. It reads the same config the
// daemon does (for the state dir) so it finds the file with no flags on a normal
// install.
func runStatus(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("banken status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to the YAML config (to locate the state dir; default "+defaultConfigPath+" if it exists)")
	fs.Usage = func() {
		logln(stderr, "usage: banken status [-config path]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := configForCmd(configPath)
	if err != nil {
		return err
	}
	path := refreshStatusPath(cfg)
	if path == "" {
		return errors.New("no state path configured, so there is no refresh status file to read (set statePath or refresh.statusPath)")
	}
	st, err := readRefreshStatus(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logf(stdout, "no refresh has been recorded yet (no status file at %s)\n", path)
			return nil
		}
		return err
	}
	printRefreshStatus(stdout, st)
	return nil
}

// printRefreshStatus writes the human summary of a status record.
func printRefreshStatus(stdout io.Writer, st RefreshStatus) {
	logf(stdout, "last refresh: %s  outcome: %s  loaded: %d  failed: %d  indicators: %d\n",
		st.Time.Format(time.RFC3339), st.Outcome, st.RulesLoaded, st.RulesFailed, st.IOCCount)
	if st.Reason != "" {
		logf(stdout, "  reason: %s\n", st.Reason)
	}
	if len(st.Dirs) > 0 {
		logf(stdout, "  dirs: %v\n", st.Dirs)
	}
	for _, f := range st.Failed {
		logf(stdout, "  failed rule: %s: %s\n", f.Path, f.Error)
	}
	for _, ov := range st.Overrides {
		if ov.Blocked {
			logf(stdout, "  baseline override BLOCKED: %s (%s would shadow %s)\n", ov.Name, ov.WinnerPath, ov.OverriddenPath)
			continue
		}
		logf(stdout, "  baseline override: %s (%s shadows %s)\n", ov.Name, ov.WinnerPath, ov.OverriddenPath)
	}
}
