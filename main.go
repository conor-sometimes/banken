// Command banken is a small host-wide EDR: on each run it reads the host
// logs since a saved cursor, matches them against the Sigma rule tree and
// IOC lists, and alerts. It is one-shot by design -- a systemd timer owns
// the schedule -- with an optional --watch self-timing loop for a host
// without a timer. See README.md for the full picture.
//
// TODO(banken): the Nix module (module.nix), package and VM test
// (tests/vm.nix) are intentionally not in this repo yet -- owned by the
// head session.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/config"
	"github.com/conor-sometimes/banken/internal/engine"
	"github.com/conor-sometimes/banken/internal/ioc"
	"github.com/conor-sometimes/banken/internal/parser"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// version is stamped in at build time (see justfile `build`).
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		logln(os.Stderr, "banken:", err)
		os.Exit(1)
	}
}

type flags struct {
	configPath string
	rules      string
	statePath  string
	watch      bool
	interval   time.Duration
	journal    bool
	jsonlDir   string
	retention  int
	webhookURL string
	style      string
	showVer    bool
}

// logf / logln write progress to a Writer, discarding the write error
// deliberately (a failed write to stderr is not worth failing a scan over,
// and swallowing it in one place keeps every call site clean).
func logf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
func logln(w io.Writer, a ...any)               { _, _ = fmt.Fprintln(w, a...) }

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("banken", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f flags
	fs.StringVar(&f.configPath, "config", "", "path to a YAML config file (flags override its values)")
	fs.StringVar(&f.rules, "rules", "", "comma-separated rule tree dirs (overrides config)")
	fs.StringVar(&f.statePath, "state", "", "path to the cursor/state file (overrides config)")
	fs.BoolVar(&f.watch, "watch", false, "run continuously on --interval instead of one-shot")
	fs.DurationVar(&f.interval, "interval", 2*time.Minute, "scan interval in --watch mode")
	fs.BoolVar(&f.journal, "journal", false, "enable the journal sink (to stderr)")
	fs.StringVar(&f.jsonlDir, "jsonl-dir", "", "enable the jsonl sink, writing per-day files here")
	fs.IntVar(&f.retention, "jsonl-retention", 30, "days of jsonl alert files to keep (0 = forever)")
	fs.StringVar(&f.webhookURL, "webhook-url-file", "", "enable the webhook sink, URL read from this file")
	fs.StringVar(&f.style, "webhook-style", "generic", "webhook body style: generic|slack|discord|ntfy")
	fs.BoolVar(&f.showVer, "version", false, "print version and exit")

	// Allow repeated -source type:path to add inputs on the command line.
	var sources multiFlag
	fs.Var(&sources, "source", "add an input as type:path (e.g. laurel:/var/log/laurel/audit.log); repeatable")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if f.showVer {
		logln(stdout, "banken", version)
		return nil
	}

	cfg, err := buildConfig(f, sources)
	if err != nil {
		return err
	}

	rules, problems := sigma.LoadTree(cfg.Rules...)
	for _, p := range problems {
		// A malformed rule is surfaced, loudly, never silently dropped.
		logln(stderr, "banken: rule error:", p.Error())
	}
	if len(rules) == 0 {
		return fmt.Errorf("no rules loaded from %s", strings.Join(cfg.Rules, ", "))
	}
	iocSet, err := ioc.LoadTree(cfg.Rules...)
	if err != nil {
		return fmt.Errorf("loading IOCs: %w", err)
	}

	sinks, err := buildSinks(cfg, stderr)
	if err != nil {
		return err
	}
	disp := alert.NewDispatcher(sinks...)
	defer func() {
		for _, e := range disp.Close() {
			logln(stderr, "banken: sink close:", e)
		}
	}()

	eng := engine.New(rules, iocSet, disp)

	logf(stderr, "banken %s: %d rules, %d indicators, %d source(s)\n",
		version, len(rules), iocSet.Len(), len(cfg.Sources))

	if f.watch {
		return watch(eng, cfg, f.interval, stderr)
	}
	return scanOnce(eng, cfg, stderr)
}

// scanOnce reads every source from its cursor, processes it, and advances
// the cursor only for sources that read without an I/O error.
func scanOnce(eng *engine.Engine, cfg config.Config, stderr io.Writer) error {
	cursor, corrupted := engine.LoadCursor(cfg.StatePath)
	if corrupted {
		logf(stderr, "banken: cursor at %s was unreadable, starting fresh (re-reading sources this pass)\n", cfg.StatePath)
	}
	reg := parser.Registry()
	totalAlerts := 0

	for _, src := range cfg.Sources {
		p, ok := reg[src.Type]
		if !ok {
			logf(stderr, "banken: unknown source type %q (%s), skipping\n", src.Type, src.Path)
			continue
		}
		file, newOffset, err := cursor.OpenAt(src.Path)
		if err != nil {
			logf(stderr, "banken: open %s: %v\n", src.Path, err)
			continue
		}
		res := eng.Process(p, file)
		_ = file.Close()
		for _, e := range res.Errors {
			logln(stderr, "banken:", e)
		}
		totalAlerts += res.Alerts
		// Advance the cursor only if the read itself did not fail; bad
		// content (skipped by the parser) still counts as consumed.
		if !hasIOError(res.Errors) {
			cursor.Offsets[src.Path] = newOffset
		}
		logf(stderr, "banken: %s %s: %d events, %d alerts\n", src.Type, src.Path, res.Events, res.Alerts)
	}

	if err := cursor.Save(cfg.StatePath); err != nil {
		return err
	}
	logf(stderr, "banken: done, %d alert(s)\n", totalAlerts)
	return nil
}

// watch runs scanOnce on a fixed interval. A self-timing fallback for a
// host without a systemd timer; the timer path (scanOnce) is the norm.
func watch(eng *engine.Engine, cfg config.Config, interval time.Duration, stderr io.Writer) error {
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	if err := scanOnce(eng, cfg, stderr); err != nil {
		logln(stderr, "banken: scan:", err)
	}
	for range ticker.C {
		if err := scanOnce(eng, cfg, stderr); err != nil {
			logln(stderr, "banken: scan:", err)
		}
	}
	return nil
}

func hasIOError(errs []error) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), "parse ") {
			return true
		}
	}
	return false
}

// buildConfig loads the config file (if any) and applies flag overrides.
func buildConfig(f flags, sources multiFlag) (config.Config, error) {
	cfg := config.Default()
	if f.configPath != "" {
		loaded, err := config.Load(f.configPath)
		if err != nil {
			return config.Config{}, err
		}
		cfg = loaded
	}
	if f.rules != "" {
		cfg.Rules = splitComma(f.rules)
	}
	if f.statePath != "" {
		cfg.StatePath = f.statePath
	}
	if f.journal {
		cfg.Alerts.Journal.Enable = true
	}
	if f.jsonlDir != "" {
		cfg.Alerts.JSONL.Enable = true
		cfg.Alerts.JSONL.Dir = f.jsonlDir
		cfg.Alerts.JSONL.RetentionDays = f.retention
	}
	if f.webhookURL != "" {
		cfg.Alerts.Webhook.Enable = true
		cfg.Alerts.Webhook.URLFile = f.webhookURL
		cfg.Alerts.Webhook.Style = f.style
	}
	for _, s := range sources {
		typ, path, ok := strings.Cut(s, ":")
		if !ok {
			return config.Config{}, fmt.Errorf("bad -source %q, want type:path", s)
		}
		cfg.Sources = append(cfg.Sources, config.Source{Type: typ, Path: path})
	}
	return cfg, nil
}

// buildSinks constructs the enabled sinks.
func buildSinks(cfg config.Config, stderr io.Writer) ([]alert.Sink, error) {
	var sinks []alert.Sink
	if cfg.Alerts.Journal.Enable {
		sinks = append(sinks, alert.NewJournalSink(stderr))
	}
	if cfg.Alerts.JSONL.Enable {
		js, err := alert.NewJSONLSink(cfg.Alerts.JSONL.Dir, cfg.Alerts.JSONL.RetentionDays)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, js)
	}
	if cfg.Alerts.Webhook.Enable {
		ws, err := alert.NewWebhookSink(alert.WebhookConfig{
			URLFile: cfg.Alerts.Webhook.URLFile,
			Style:   cfg.Alerts.Webhook.WebhookStyle(),
		})
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, ws)
	}
	return sinks, nil
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
