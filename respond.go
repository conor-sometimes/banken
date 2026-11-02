package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/signal"
	"syscall"
	"time"

	"github.com/conor-sometimes/banken/internal/config"
	"github.com/conor-sometimes/banken/internal/response"
	"github.com/conor-sometimes/banken/internal/response/drain"
	"github.com/conor-sometimes/banken/internal/response/exec"
)

// runRespond dispatches `banken respond <sub>`: the privileged half of the
// two-process response split and the operator CLI. Only drain is implemented in
// this build; list/explain/thaw/restore land with the later build items (the
// read-only and undo commands). A compromised daemon cannot run any of these --
// they live in a separate unit (the helper) or a root operator shell.
func runRespond(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		respondUsage(stderr)
		return exitError{code: 2, err: errors.New("banken respond: a subcommand is required")}
	}
	switch args[0] {
	case "drain":
		return runRespondDrain(args[1:], stdout, stderr)
	case "list", "explain", "thaw", "restore":
		return fmt.Errorf("banken respond %s: not implemented in this build (the operator CLI lands with a later build item)", args[0])
	default:
		respondUsage(stderr)
		return exitError{code: 2, err: fmt.Errorf("banken respond: unknown subcommand %q", args[0])}
	}
}

func respondUsage(stderr io.Writer) {
	logln(stderr, "usage: banken respond drain [-config path]")
	logln(stderr, "       (list | explain | thaw | restore: a later build item)")
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
