// Command banken is a small host-wide EDR: on each run it reads the host
// logs since a saved cursor, matches them against the Sigma rule tree and
// IOC lists, and alerts. It is one-shot by design -- a systemd timer owns
// the schedule -- with an optional --watch self-timing loop for a host
// without a timer. See README.md for the full picture; the NixOS module is
// module.nix, the package package.nix, and their end-to-end test tests/vm.nix.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
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

// defaultConfigPath is read when -config is not given and the file exists:
// the zero-fiddle install is a unit with no flags, and an operator who wants
// settings puts them here. A missing default is the built-in defaults; a
// missing file named with -config is an error. A var so tests can point it
// at a temp dir.
var defaultConfigPath = "/etc/banken/banken.yml"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		logAt(os.Stderr, levelErr, "banken: %v", err)
		os.Exit(1)
	}
}

type flags struct {
	configPath  string
	rules       string
	optional    string
	observe     string
	statePath   string
	watch       bool
	interval    time.Duration
	journal     bool
	jsonlDir    string
	jsonlFormat string
	retention   int
	webhookURL  string
	style       string
	showVer     bool
}

// logf / logln write progress to a Writer, discarding the write error
// deliberately (a failed write to stderr is not worth failing a scan over,
// and swallowing it in one place keeps every call site clean).
func logf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
func logln(w io.Writer, a ...any)               { _, _ = fmt.Fprintln(w, a...) }

// banken's own messages carry a log level (sd-daemon(3)). Under systemd,
// which sets JOURNAL_STREAM when a service's stderr goes to the journal, the
// level prefixes the line ("<3>") and the journal files it at that priority,
// so `journalctl -u banken -p warning` shows banken's problems and only them.
// In a terminal the prefix would be noise, so it is left off.
const (
	levelErr     = 3
	levelWarning = 4
	levelInfo    = 6
)

var underJournald = os.Getenv("JOURNAL_STREAM") != ""

// logAt writes one message line at a level (see above).
func logAt(w io.Writer, level int, format string, a ...any) {
	if underJournald {
		format = "<" + strconv.Itoa(level) + ">" + format
	}
	_, _ = fmt.Fprintf(w, format+"\n", a...)
}

func run(args []string, stdout, stderr io.Writer) error {
	// Subcommands. The default (no subcommand) is the one-shot scan.
	if len(args) > 0 && args[0] == "check" {
		return runCheck(args[1:], stdout, stderr)
	}

	fs := flag.NewFlagSet("banken", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f flags
	fs.StringVar(&f.configPath, "config", "", "path to a YAML config file, flags override its values (default "+defaultConfigPath+" if it exists)")
	fs.StringVar(&f.rules, "rules", "", "comma-separated rule tree dirs (overrides config)")
	fs.StringVar(&f.optional, "optional", "", "comma-separated optional rule names to activate, or * for all (overrides config)")
	fs.StringVar(&f.observe, "observe", "", "comma-separated optional rule names to run in observe mode (recorded, never paged), or * for all (overrides config)")
	fs.StringVar(&f.statePath, "state", "", "path to the cursor/state file (overrides config)")
	fs.BoolVar(&f.watch, "watch", false, "run continuously on --interval instead of one-shot")
	fs.DurationVar(&f.interval, "interval", 2*time.Minute, "scan interval in --watch mode")
	fs.BoolVar(&f.journal, "journal", false, "enable the journal sink (to stderr)")
	fs.StringVar(&f.jsonlDir, "jsonl-dir", "", "enable the jsonl sink, writing per-day files here")
	fs.StringVar(&f.jsonlFormat, "jsonl-format", "", "jsonl encoding: banken (native) | ocsf (OCSF Detection Finding); default banken")
	fs.IntVar(&f.retention, "jsonl-retention", 30, "days of jsonl alert files to keep (0 = forever)")
	fs.StringVar(&f.webhookURL, "webhook-url-file", "", "enable the webhook sink, URL read from this file")
	fs.StringVar(&f.style, "webhook-style", "generic", "webhook body style: generic|slack|discord|ntfy|ocsf")
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

	// Zero-fiddle: with nothing configured, find the host's audit log so a
	// bare `banken` still does something useful.
	if len(cfg.Sources) == 0 {
		cfg.Sources = config.AutoDetectSources(nil)
		if len(cfg.Sources) == 0 {
			logAt(stderr, levelWarning, "banken: no log source configured or auto-detected; "+
				"pass -source type:path or set sources in the config (will retry next run)")
		} else {
			logAt(stderr, levelInfo, "banken: auto-detected source: %s %s", cfg.Sources[0].Type, cfg.Sources[0].Path)
		}
	}

	// A rule that switches syscall auditing off leaves banken running cleanly
	// and seeing nothing: say so, loudly, every run.
	for _, b := range auditBlindspots() {
		logAt(stderr, levelWarning, "banken: audit rule %s turns syscall auditing off, so banken sees no "+
			"process events; remove it and run augenrules --load (docs/deployment.md, Log source)", b)
	}

	rules, problems := loadRules(cfg.Rules)
	for _, p := range problems {
		// A malformed rule is surfaced, loudly, never silently dropped.
		logAt(stderr, levelErr, "banken: rule error: %s", p.Error())
	}
	if len(rules) == 0 {
		// The embedded baseline should always load, so this means the binary
		// itself is broken, not a misconfiguration.
		return errors.New("no rules loaded (embedded baseline missing?)")
	}

	// Hold back optional (opt-in) rules the operator did not activate, and mark
	// observe-mode rules. A named rule that matches no optional rule is warned
	// about -- a typo'd enable is a detection that silently is not running.
	rules, sel := selectActive(rules, optionalSet(cfg.OptionalRules), optionalSet(cfg.ObserveRules))
	for _, name := range sel.unknown {
		logAt(stderr, levelWarning, "banken: %q is named in optionalRules/observeRules but is not an optional rule; it will not run (check the spelling)", name)
	}

	iocSet, err := loadIOCs(cfg.Rules)
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
			logAt(stderr, levelErr, "banken: sink close: %v", e)
		}
	}()

	eng := engine.New(rules, iocSet, disp)

	if sel.observing > 0 {
		logAt(stderr, levelInfo, "banken: %d optional rule(s) in observe mode (recorded, not paged)", sel.observing)
	}
	if sel.heldBack > 0 {
		logAt(stderr, levelInfo, "banken: %d optional rule(s) held back (activate with optionalRules/-optional, or watch with observeRules/-observe)", sel.heldBack)
	}
	logAt(stderr, levelInfo, "banken %s: %d rules, %d indicators, %d source(s)",
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
		logAt(stderr, levelWarning, "banken: cursor at %s was unreadable, starting fresh (re-reading sources this pass)", cfg.StatePath)
	}
	reg := parser.Registry()
	totalAlerts := 0

	for _, src := range cfg.Sources {
		p, ok := reg[src.Type]
		if !ok {
			logAt(stderr, levelWarning, "banken: unknown source type %q (%s), skipping", src.Type, src.Path)
			continue
		}
		ch, err := cursor.OpenAt(src.Path)
		if err != nil {
			logAt(stderr, levelErr, "banken: open %s: %v", src.Path, err)
			continue
		}
		res := eng.Process(p, ch)
		_ = ch.Close()
		for _, e := range res.Errors {
			logAt(stderr, levelErr, "banken: %v", e)
		}
		totalAlerts += res.Alerts
		// Advance the cursor only if the source parsed cleanly; a parse/read
		// failure leaves the offset so the next run re-reads those bytes.
		// NextOffset is the end of the last complete line, so bad content a
		// parser merely skipped still counts as consumed, but a partial
		// trailing line does not.
		if res.ParseErr == nil {
			cursor.Offsets[src.Path] = ch.NextOffset()
			if ino := ch.Ino(); ino != 0 {
				cursor.Inodes[src.Path] = ino // for rotation detection next run
			}
		}
		logAt(stderr, levelInfo, "banken: %s %s: %d events, %d alerts", src.Type, src.Path, res.Events, res.Alerts)
	}

	if err := cursor.Save(cfg.StatePath); err != nil {
		return err
	}
	logAt(stderr, levelInfo, "banken: done, %d alert(s)", totalAlerts)
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
		logAt(stderr, levelErr, "banken: scan: %v", err)
	}
	for range ticker.C {
		if err := scanOnce(eng, cfg, stderr); err != nil {
			logAt(stderr, levelErr, "banken: scan: %v", err)
		}
	}
	return nil
}

// loadRules loads the embedded baseline rule tree and then any on-disk rule
// dirs that exist, with on-disk rules overriding the baseline on a name
// clash. A missing on-disk dir is not an error -- the embedded baseline means
// detection works with nothing on disk (the zero-fiddle goal).
func loadRules(dirs []string) ([]*sigma.Rule, []sigma.RuleError) {
	base, problems := sigma.LoadFS(embeddedRules, "rules")
	byName := make(map[string]*sigma.Rule, len(base))
	for _, r := range base {
		byName[r.Name] = r
	}
	disk, dprobs := sigma.LoadTree(existingDirs(dirs)...)
	problems = append(problems, dprobs...)
	for _, r := range disk {
		byName[r.Name] = r // on-disk wins
	}
	out := make([]*sigma.Rule, 0, len(byName))
	for _, r := range byName {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, problems
}

// optionalSet turns the configured optionalRules list into a lookup. "*"
// activates every optional rule; otherwise each entry names one rule.
func optionalSet(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			m[n] = true
		}
	}
	return m
}

// selection is the outcome of selectActive beyond the active rule set.
type selection struct {
	heldBack  int      // optional rules neither enabled nor observed
	observing int      // optional rules running in observe mode
	unknown   []string // enable/observe names matching no optional rule (likely typos)
}

// selectActive decides which rules run and in what mode. A non-optional rule is
// always active. An optional rule is active if it is enabled (optionalRules) or
// observed (observeRules), where "*" selects all; enabled wins over observed,
// and an observed rule is marked Observe so its alerts are recorded but never
// paged. Every other optional rule is held back. Names in either set that match
// no optional rule are returned as unknown (a likely typo worth a warning). The
// input is assumed sorted by Name and the output preserves that order.
func selectActive(rules []*sigma.Rule, enabled, observed map[string]bool) (active []*sigma.Rule, sel selection) {
	enableAll, observeAll := enabled["*"], observed["*"]
	optionalNames := make(map[string]bool)
	active = make([]*sigma.Rule, 0, len(rules))
	for _, r := range rules {
		if !r.Optional {
			r.Observe = false
			active = append(active, r)
			continue
		}
		optionalNames[r.Name] = true
		switch {
		case enableAll || enabled[r.Name]: // explicit enable wins over observe
			r.Observe = false
			active = append(active, r)
		case observeAll || observed[r.Name]:
			r.Observe = true
			active = append(active, r)
			sel.observing++
		default:
			sel.heldBack++
		}
	}
	// A name in either set that is not an optional rule's name does nothing.
	seen := map[string]bool{}
	for _, set := range []map[string]bool{enabled, observed} {
		for name := range set {
			if name != "*" && !optionalNames[name] && !seen[name] {
				seen[name] = true
				sel.unknown = append(sel.unknown, name)
			}
		}
	}
	sort.Strings(sel.unknown)
	return active, sel
}

// loadIOCs loads the on-disk IOC feeds (if any) and the embedded baseline
// into one set. Duplicate values are harmless -- Match dedups by value+field.
func loadIOCs(dirs []string) (*ioc.Set, error) {
	set, err := ioc.LoadTree(existingDirs(dirs)...)
	if err != nil {
		return nil, err
	}
	if err := set.ReadFS(embeddedRules, "rules"); err != nil {
		return nil, err
	}
	return set, nil
}

// existingDirs keeps only the paths that exist and are directories, so a
// default rules dir that was never created is quietly skipped rather than
// reported as a rule error on every run.
func existingDirs(dirs []string) []string {
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			out = append(out, d)
		}
	}
	return out
}

// buildConfig loads the config file (if any) and applies flag overrides.
func buildConfig(f flags, sources multiFlag) (config.Config, error) {
	cfg := config.Default()
	path := f.configPath
	if path == "" {
		if _, err := os.Stat(defaultConfigPath); err == nil {
			path = defaultConfigPath
		}
	}
	if path != "" {
		loaded, err := config.Load(path)
		if err != nil {
			return config.Config{}, err
		}
		cfg = loaded
	}
	if f.rules != "" {
		cfg.Rules = splitComma(f.rules)
	}
	if f.optional != "" {
		cfg.OptionalRules = splitComma(f.optional)
	}
	if f.observe != "" {
		cfg.ObserveRules = splitComma(f.observe)
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
	if f.jsonlFormat != "" {
		cfg.Alerts.JSONL.Format = f.jsonlFormat
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

// buildSinks constructs the enabled sinks. OCSF options (product version,
// hostname) are gathered once and shared by any sink configured for OCSF.
func buildSinks(cfg config.Config, stderr io.Writer) ([]alert.Sink, error) {
	ocsfOpts := alert.OCSFOptions{
		ProductVersion: version,
		Hostname:       ocsfHostname(stderr),
		Now:            time.Now,
	}

	var sinks []alert.Sink
	if cfg.Alerts.Journal.Enable {
		sinks = append(sinks, alert.NewJournalSink(stderr, underJournald))
	}
	if cfg.Alerts.JSONL.Enable {
		enc, err := jsonlEncoder(cfg.Alerts.JSONL.Format, ocsfOpts)
		if err != nil {
			return nil, err
		}
		fileMode := os.FileMode(0o600)
		if cfg.Alerts.JSONL.GroupReadable {
			fileMode = 0o640
		}
		js, err := alert.NewJSONLSinkEncodedMode(cfg.Alerts.JSONL.Dir, cfg.Alerts.JSONL.RetentionDays, enc, fileMode)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, js)
	}
	if cfg.Alerts.Webhook.Enable {
		ws, err := alert.NewWebhookSink(alert.WebhookConfig{
			URLFile: cfg.Alerts.Webhook.URLFile,
			Style:   cfg.Alerts.Webhook.WebhookStyle(),
			OCSF:    ocsfOpts,
		})
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, ws)
	}
	return sinks, nil
}

// jsonlEncoder picks the jsonl encoder from the configured format. An unknown
// value is an error naming it -- never a silent fallback to the native shape,
// because an operator who asked for ocsf and got banken JSON would only find
// out from their SIEM.
func jsonlEncoder(format string, o alert.OCSFOptions) (alert.Encoder, error) {
	switch format {
	case "", "banken":
		return alert.EncodeAlert, nil
	case "ocsf":
		return alert.EncodeOCSF(o), nil
	default:
		return nil, fmt.Errorf("unknown jsonl format %q (want banken or ocsf)", format)
	}
}

// ocsfHostname is the host identity stamped into OCSF findings' device
// object. A failure or empty result omits the device object (its constraint
// needs an identifier); the sink still works, so this never fails a run.
func ocsfHostname(stderr io.Writer) string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		logAt(stderr, levelWarning, "banken: os.Hostname() unavailable; OCSF findings will omit device.hostname")
		return ""
	}
	return h
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
