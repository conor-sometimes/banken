package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/conor-sometimes/banken/internal/config"
	"github.com/conor-sometimes/banken/internal/response"
	"github.com/conor-sometimes/banken/internal/response/drain"
	"github.com/conor-sometimes/banken/internal/response/exec"
	"github.com/conor-sometimes/banken/internal/response/view"
)

// runRespond dispatches `banken respond <sub>`: the privileged half of the
// two-process response split and the operator CLI. list and explain are the
// read-only operator surface; thaw and restore are the privileged in-process
// undo. A compromised daemon cannot run any of these -- they live in a separate
// unit (the helper) or a root operator shell.
func runRespond(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		respondUsage(stderr)
		return exitError{code: 2, err: errors.New("banken respond: a subcommand is required")}
	}
	switch args[0] {
	case "drain":
		return runRespondDrain(args[1:], stdout, stderr)
	case "list":
		return runRespondList(args[1:], stdout, stderr)
	case "explain":
		return runRespondExplain(args[1:], stdout, stderr)
	case "thaw":
		return runRespondThaw(args[1:], stdout, stderr)
	case "restore":
		return runRespondRestore(args[1:], stdout, stderr)
	default:
		respondUsage(stderr)
		return exitError{code: 2, err: fmt.Errorf("banken respond: unknown subcommand %q", args[0])}
	}
}

func respondUsage(stderr io.Writer) {
	logln(stderr, "usage: banken respond <subcommand> [-config path]")
	logln(stderr, "  list     [-since 24h] [-kind freeze|kill|quarantine|collect] [-state held|frozen|thawed|restored|lost] [-json]")
	logln(stderr, "  explain  <decision-id | handle-id> [-verify] [-json]")
	logln(stderr, "  thaw     <handle-id>              reverse a freeze (root shell)")
	logln(stderr, "  restore  <handle-id> [-to PATH]   reverse a quarantine (root shell)")
	logln(stderr, "  drain    (the privileged helper unit; not for operators)")
}

// runRespondDrain is the `banken respond drain` subcommand: the privileged unit
// that reads work orders from the spool, re-decides each from the policy on
// disk, and acts via the executor only when its own verdict matches. It is the
// trust boundary of the split (§2.4). It loads the same config and policy the
// daemon does, builds the executor the daemon no longer holds, and hands
// everything to the drain package, which is unit-testable with a fake executor.
func runRespondDrain(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("banken respond drain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to the YAML config (to locate the state dir, policy and stores; default "+defaultConfigPath+" if it exists)")
	fs.Usage = func() {
		logln(stderr, "usage: banken respond drain [-config path]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := configForCmd(configPath)
	if err != nil {
		return err
	}
	if !cfg.Response.Enable {
		return errors.New("banken respond drain: response is not enabled in the config (response.enable is off)")
	}

	policy, err := loadResponsePolicy(cfg.Response)
	if err != nil {
		return err
	}

	ledger, err := response.NewLedger(responseLedgerDir(cfg))
	if err != nil {
		return err
	}

	spoolDir, spoolTmpDir := spoolPaths(cfg)
	spool, err := response.NewSpool(spoolDir, spoolTmpDir)
	if err != nil {
		return fmt.Errorf("banken respond drain: spool: %w", err)
	}

	// The executor lives ONLY here, in the helper process: the daemon dropped it
	// at the split. Armed is cfg.Response.Enforce -- the Armed input to the
	// drain's re-decision and the executor's second belt. Off => a dry-run that
	// prints what it would do, which is how the drain's own unit tests run.
	ex, err := exec.New(exec.Config{
		Enforce:              cfg.Response.Enforce,
		AllowRoot:            policy.AllowRoot,
		CgroupRoot:           cfg.Response.CgroupRoot,
		QuarantineDir:        cfg.Response.QuarantineDir,
		QuarantineAllowPaths: policy.Quarantine.AllowPaths,
		MaxFileBytes:         policy.Quarantine.MaxFileBytes,
		Logf: func(format string, a ...any) {
			logAt(stderr, levelWarning, format, a...)
		},
	})
	if err != nil {
		return fmt.Errorf("banken respond drain: executor: %w", err)
	}

	maxAge, err := spoolMaxAge(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	logAt(stderr, levelInfo, "banken respond drain: policy %s, mode=%s, armed=%v, spool %s, maxAge %s",
		policy.Hash(), policy.Mode, cfg.Response.Enforce, spoolDir, maxAge)

	return drain.Run(ctx, drain.Options{
		Spool:                spool,
		Policy:               policy,
		Executor:             ex,
		Ledger:               ledger,
		Self:                 response.SelfIdentity{Exe: selfExe()},
		Armed:                cfg.Response.Enforce,
		MaxAge:               maxAge,
		QuarantineAllowPaths: cfg.Response.QuarantineAllowPaths,
		Version:              version,
		Logf: func(format string, a ...any) {
			logAt(stderr, levelInfo, format, a...)
		},
	})
}

// spoolMaxAge parses response.spool.maxAge, applying the default when unset. An
// unparseable value is an error naming it, never a silent fallback -- an
// operator who set "10min" and got the default would not know their orders
// expire on a different schedule than they asked for.
func spoolMaxAge(cfg config.Config) (time.Duration, error) {
	s := cfg.Response.Spool.MaxAge
	if s == "" {
		return config.DefaultSpoolMaxAge, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("banken respond drain: invalid response.spool.maxAge %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("banken respond drain: response.spool.maxAge %q must be positive", s)
	}
	return d, nil
}

// ---- the read-only operator CLI: list and explain (§3.1, §3.2) -------------
//
// list and explain READ the ledger and the stores and touch nothing: no act,
// no signal, no privileged helper. They run as any user with read access to
// the state dir (a root shell, or CAP_DAC_READ_SEARCH). The one exception is
// explain -verify, which re-identifies the live process (pidfd + /proc) and so
// needs CAP_SYS_PTRACE for another uid's process -- a root shell. Everything
// else is pure file reading, so both work on a Mac over a fixture tree.

// newViewReader builds the view.Reader over the real root (os.DirFS("/")): the
// ledger, the three stores and the spool are all absolute host paths, read
// root-relative. The store dirs are resolved exactly as the executor resolves
// them (QuarantineDir from the config or the executor default; freeze and
// evidence at their fixed defaults), so list/explain read the same directories
// the drain wrote.
func newViewReader(cfg config.Config) *view.Reader {
	quarantineDir := cfg.Response.QuarantineDir
	if quarantineDir == "" {
		quarantineDir = "/var/lib/banken/quarantine"
	}
	spoolDir, _ := spoolPaths(cfg)
	return view.NewReader(
		os.DirFS("/"),
		responseLedgerDir(cfg),
		"/var/lib/banken/freeze",
		quarantineDir,
		"/var/lib/banken/evidence",
		spoolDir,
	)
}

// newViewProber builds the live-system prober for list/explain on a host (a
// no-op observer off Linux). It re-hashes a stored file under the same
// MaxFileBytes cap the policy set, so list never stalls on a huge artifact.
func newViewProber(cfg config.Config) view.Prober {
	quarantineDir := cfg.Response.QuarantineDir
	if quarantineDir == "" {
		quarantineDir = "/var/lib/banken/quarantine"
	}
	var maxBytes int64
	if policy, err := loadResponsePolicy(cfg.Response); err == nil {
		maxBytes = policy.Quarantine.MaxFileBytes
	}
	return view.NewSysProber(quarantineDir, maxBytes)
}

func runRespondList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("banken respond list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath string
		since      time.Duration
		kind       string
		state      string
		asJSON     bool
	)
	fs.StringVar(&configPath, "config", "", "path to the YAML config (to locate the state dir and stores)")
	fs.DurationVar(&since, "since", view.DefaultListWindow, "how far back to read the action ledger")
	fs.StringVar(&kind, "kind", "", "filter by action kind: freeze|kill|quarantine|collect")
	fs.StringVar(&state, "state", "", "filter by state bucket: held|frozen|thawed|restored|lost")
	fs.BoolVar(&asJSON, "json", false, "emit one JSON object per handle (manifest verbatim)")
	fs.Usage = func() {
		logln(stderr, "usage: banken respond list [-since 24h] [-kind ...] [-state ...] [-json] [-config path]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return exitError{code: 2, err: fmt.Errorf("banken respond list: unexpected argument %q", fs.Arg(0))}
	}

	cfg, err := configForCmd(configPath)
	if err != nil {
		return err
	}
	reader := newViewReader(cfg)
	rows, err := reader.List(newViewProber(cfg), view.ListOptions{
		Since: since,
		Kind:  response.Action(kind),
		State: state,
	})
	if err != nil {
		return exitError{code: 1, err: fmt.Errorf("banken respond list: %w", err)}
	}
	if asJSON {
		if err := view.RenderListJSON(stdout, rows); err != nil {
			return exitError{code: 1, err: fmt.Errorf("banken respond list: %w", err)}
		}
		return nil
	}
	view.RenderList(stdout, rows)
	return nil
}

func runRespondExplain(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("banken respond explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath string
		verify     bool
		asJSON     bool
	)
	fs.StringVar(&configPath, "config", "", "path to the YAML config (to locate the state dir and stores)")
	fs.BoolVar(&verify, "verify", false, "re-identify the live process now (needs CAP_SYS_PTRACE: a root shell)")
	fs.BoolVar(&asJSON, "json", false, "emit the chain as a single JSON object")
	fs.Usage = func() {
		logln(stderr, "usage: banken respond explain <decision-id | handle-id> [-verify] [-json] [-config path]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return exitError{code: 2, err: errors.New("banken respond explain: exactly one id argument is required")}
	}
	id := fs.Arg(0)

	cfg, err := configForCmd(configPath)
	if err != nil {
		return err
	}
	reader := newViewReader(cfg)
	exp, err := reader.Explain(newViewProber(cfg), id, view.ExplainOptions{})
	if err != nil {
		return exitError{code: 1, err: fmt.Errorf("banken respond explain: %w", err)}
	}

	if asJSON {
		if err := view.RenderExplainJSON(stdout, exp); err != nil {
			return exitError{code: 1, err: fmt.Errorf("banken respond explain: %w", err)}
		}
		return nil
	}
	view.RenderExplain(stdout, exp)
	if verify {
		explainVerify(stdout, stderr, cfg, exp)
	}
	return nil
}

// explainVerify runs the executor's read-only Verify on the decision's process
// target and prints the live identity (or the reason it is gone). It reuses the
// EXISTING exec.Executor.Verify -- a pidfd + /proc re-identify that is always
// real and read-only, so a dry-run executor is fine; no mutating method is
// touched and no new executor seam is added. A file-target decision has no
// process to verify, which is said plainly rather than silently skipped.
func explainVerify(stdout, stderr io.Writer, cfg config.Config, exp *view.Explanation) {
	proc := exp.Decision.Decision.Target.Process
	if proc == nil {
		logln(stdout, "verify now: not a process target (nothing to verify)")
		return
	}
	ex, err := exec.New(exec.Config{Enforce: false})
	if err != nil {
		logln(stderr, "verify now: executor unavailable: "+err.Error())
		return
	}
	live, verr := ex.Verify(context.Background(), *proc)
	if verr != nil {
		logln(stdout, "verify now: "+verr.Error())
		return
	}
	_, _ = fmt.Fprintf(stdout, "verify now: pid %d exe %s start %s uid %d\n",
		live.PID, orDash(live.Exe), orZeroTime(live.StartTime), live.UID)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func orZeroTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

// ---- the privileged undo CLI: thaw and restore (§3.3, §3.4) ----------------
//
// thaw and restore run the undo IN-PROCESS under the operator's root shell:
// sudo is the privilege boundary, not the spool/helper (the doc default, §3).
// They read the store entry, reverse the act through the SAME exec package the
// drain uses, and write a thawed/restored ledger line carrying the operator
// uid. Both are idempotent via the item 4/5 tombstones: a second run is a clean
// no-op and the store entry is KEPT (never deleted -- that was the Q3 bug), so
// list keeps showing what was done to whom.

func runRespondThaw(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("banken respond thaw", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to the YAML config (to locate the state dir, policy and stores)")
	fs.Usage = func() {
		logln(stderr, "usage: banken respond thaw <handle-id> [-config path]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return exitError{code: 2, err: errors.New("banken respond thaw: exactly one handle id is required")}
	}
	id := fs.Arg(0)

	cfg, err := configForCmd(configPath)
	if err != nil {
		return err
	}
	entry, err := newViewReader(cfg).FindEntry(response.ActionFreeze, id)
	if err != nil {
		return exitError{code: 1, err: fmt.Errorf("banken respond thaw: %w", err)}
	}

	ledger, err := response.NewLedger(responseLedgerDir(cfg))
	if err != nil {
		return err
	}
	uid := operatorUID()
	decisionID := ""
	if entry.Freeze != nil {
		decisionID = entry.Freeze.Order
	}
	target := freezeTargetRef(entry)

	// Already thawed: a clean no-op with a ledger note (§3.3 step 1).
	if entry.Thawed {
		logln(stdout, fmt.Sprintf("already thawed at %s", orZeroTime(entry.ThawedAt)))
		recordUndo(ledger, cfg, "thawed", response.ActionFreeze, decisionID, target, uid, "already")
		return nil
	}

	ex, err := undoExecutor(cfg, stderr)
	if err != nil {
		return exitError{code: 1, err: fmt.Errorf("banken respond thaw: %w", err)}
	}
	h := exec.Handle{ID: entry.ID, Undo: entry.ID, Kind: response.ActionFreeze}
	if err := ex.Thaw(context.Background(), h); err != nil {
		return exitError{code: 1, err: fmt.Errorf("banken respond thaw %s: %w", entry.ID, err)}
	}
	logln(stdout, fmt.Sprintf("thawed %s", entry.ID))
	recordUndo(ledger, cfg, "thawed", response.ActionFreeze, decisionID, target, uid, "")
	return nil
}

func runRespondRestore(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("banken respond restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath string
		to         string
	)
	fs.StringVar(&configPath, "config", "", "path to the YAML config (to locate the state dir, policy and stores)")
	fs.StringVar(&to, "to", "", "restore to this absolute path instead of the original (bounded by the policy's quarantine allowPaths; does not bypass it)")
	fs.Usage = func() {
		logln(stderr, "usage: banken respond restore <handle-id> [-to PATH] [-config path]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return exitError{code: 2, err: errors.New("banken respond restore: exactly one handle id is required")}
	}
	id := fs.Arg(0)

	cfg, err := configForCmd(configPath)
	if err != nil {
		return err
	}
	entry, err := newViewReader(cfg).FindEntry(response.ActionQuarantine, id)
	if err != nil {
		return exitError{code: 1, err: fmt.Errorf("banken respond restore: %w", err)}
	}

	ledger, err := response.NewLedger(responseLedgerDir(cfg))
	if err != nil {
		return err
	}
	uid := operatorUID()
	decisionID := ""
	origPath := ""
	if entry.Quar != nil {
		decisionID = entry.Quar.Order
		origPath = entry.Quar.OrigPath
	}
	target := quarTargetRef(entry)

	// Already restored: a clean no-op with a ledger note (§3.4 step 1).
	if entry.Restored {
		dest := entry.RestoreDest
		if dest == "" {
			dest = origPath
		}
		logln(stdout, fmt.Sprintf("already restored at %s to %s", orZeroTime(entry.RestoredAt), dest))
		recordUndo(ledger, cfg, "restored", response.ActionQuarantine, decisionID, target, uid, "already")
		return nil
	}

	ex, err := undoExecutor(cfg, stderr)
	if err != nil {
		return exitError{code: 1, err: fmt.Errorf("banken respond restore: %w", err)}
	}
	h := exec.Handle{ID: entry.ID, Undo: entry.ID, Kind: response.ActionQuarantine}
	if err := ex.Restore(context.Background(), h, to); err != nil {
		return exitError{code: 1, err: fmt.Errorf("banken respond restore %s: %w", entry.ID, err)}
	}
	dest := origPath
	if to != "" {
		dest = to
	}
	logln(stdout, fmt.Sprintf("restored %s to %s", entry.ID, dest))
	recordUndo(ledger, cfg, "restored", response.ActionQuarantine, decisionID, target, uid, "")
	return nil
}

// undoExecutor builds the executor for an in-process thaw/restore. Thaw and
// Restore work from the store and reverse the act regardless of
// response.enforce (an undo is the safe direction, §3); the store dirs are
// resolved exactly as the drain and the view resolve them so all three agree.
func undoExecutor(cfg config.Config, stderr io.Writer) (exec.Executor, error) {
	policy, err := loadResponsePolicy(cfg.Response)
	if err != nil {
		return nil, err
	}
	return exec.New(exec.Config{
		Enforce:              cfg.Response.Enforce,
		AllowRoot:            policy.AllowRoot,
		CgroupRoot:           cfg.Response.CgroupRoot,
		QuarantineDir:        cfg.Response.QuarantineDir,
		QuarantineAllowPaths: policy.Quarantine.AllowPaths,
		MaxFileBytes:         policy.Quarantine.MaxFileBytes,
		Logf: func(format string, a ...any) {
			logAt(stderr, levelWarning, format, a...)
		},
	})
}

// recordUndo appends a thawed/restored ledger line for an operator undo. The
// line references the decision id the manifest carried and the operator uid, so
// the audit trail shows who reversed what; it is a record, not the state
// list/explain read (those compute state from the store tombstone). A ledger
// write error is logged by the ledger, never fatal to an undo that already
// landed.
func recordUndo(ledger *response.Ledger, cfg config.Config, phase string, action response.Action, decisionID string, target response.Target, uid int, note string) {
	n := fmt.Sprintf("operator uid %d", uid)
	if note != "" {
		n = note + "; " + n
	}
	_, _ = ledger.RecordAction(response.ActionRecord{
		Phase:      phase,
		Note:       n,
		DecisionID: decisionID,
		Action:     action,
		Target:     target,
		Enforced:   cfg.Response.Enforce,
		Version:    version,
	})
}

// freezeTargetRef / quarTargetRef render a store entry's target for the undo
// ledger line, so a reader sees which pid or file was reversed.
func freezeTargetRef(e view.Entry) response.Target {
	if e.Freeze == nil {
		return response.Target{}
	}
	return response.Target{Process: &response.ProcessRef{PID: e.Freeze.Target.PID, Image: e.Freeze.Target.Exe}}
}

func quarTargetRef(e view.Entry) response.Target {
	if e.Quar == nil {
		return response.Target{}
	}
	return response.Target{File: &response.FileRef{Path: e.Quar.OrigPath}}
}

// operatorUID is the uid credited in a thawed/restored ledger line: the user
// behind sudo if known, else the real uid. It mirrors the executor tombstone's
// convention so the ledger line and the tombstone agree on who acted.
func operatorUID() int {
	if s := os.Getenv("SUDO_UID"); s != "" {
		if u, err := strconv.Atoi(s); err == nil {
			return u
		}
	}
	return os.Getuid()
}
