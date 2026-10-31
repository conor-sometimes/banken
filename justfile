# banken -- task runner.
#
# `just` (or `just all`) runs the full battery: gofumpt check, vet,
# staticcheck, golangci-lint, errcheck, gosec, govulncheck, `test`, and
# coverage. Individual pieces are their own recipes below.
#
# `test` is the one command: every package, race detector on, plus every
# `Fuzz*` target's own short randomized search (not just its seed corpus,
# which plain `go test` already replays) and a deeper rapid property sweep.
# The parsers eat untrusted log bytes, so the fuzzing is not optional here:
# a parser that panics on a bad line is a hole in the detection.
#
# Tools: `brew install just gofumpt staticcheck errcheck gosec govulncheck
# golangci-lint` (or `go install` the same), plus
# `go install gotest.tools/gotestsum@v1.13.0`.
#
# Performance recipes (bench*) additionally need benchstat
# (`go install golang.org/x/perf/cmd/benchstat@latest`); bench-e2e also needs
# hyperfine (`brew install hyperfine`).

alias all := default

default: fmt vet lint golangci errcheck gosec vulncheck test cover

# Reports files that aren't gofumpt'd without rewriting them. git ls-files,
# not a `.` walk: gofmt/gofumpt aren't module-boundary-aware, so a nested
# go.mod (e.g. a leftover agent worktree) would otherwise be walked into.
fmt:
	#!/bin/sh
	set -eu
	unformatted="$(gofumpt -l -- $(git ls-files '*.go'))"
	if [ -n "$unformatted" ]; then
		echo "not gofumpt'd:" >&2
		echo "$unformatted" >&2
		echo "run: just fmt-write" >&2
		exit 1
	fi

fmt-write:
	gofumpt -w -- $(git ls-files '*.go')

vet:
	go vet ./...

# staticcheck: the standard linter beyond vet.
lint:
	staticcheck ./...

# A curated set beyond staticcheck/vet/errcheck/unused (which run
# standalone) -- see .golangci.yml. tagliatelle is configured for banken's
# camelCase JSON tag convention.
golangci:
	golangci-lint run ./...

errcheck:
	errcheck ./...

# Security static analysis. Run standalone, NOT via golangci-lint, which
# silently caps a repo-wide gosec scan (confirmed in the sibling pth repo).
#
# -exclude=G304 (file inclusion via variable) is repo-wide: banken's whole
# job is reading paths the operator names -- the rules dir, the config, the
# cursor/state file, the webhook urlFile, the log inputs themselves -- never
# a value crossing a trust boundary the way G304 is meant to catch. The
# untrusted bytes are the *contents* of those files, which the parsers
# handle (and the Fuzz* targets prove) without trusting them.
#
# -exclude=G122 (symlink TOCTOU in a WalkDir callback): the rules tree and
# ioc/ dir are operator-owned config directories banken opens files from
# while walking them; there is no untrusted writer racing a symlink into
# that tree. Same trust-boundary reasoning as G304.
gosec:
	gosec -exclude=G304,G122 ./...

vulncheck:
	govulncheck ./...

# The one test command: every package, race on, no caching, with the fuzz
# smoke and rapid deep sweep run first.
test: fuzz property-deep
	gotestsum --format pkgname -- ./... -race -count=1

cover:
	go test ./... -cover -count=1

# Mutation testing on the detection core (periodic, NOT part of `just default`
# -- it reruns the suite once per mutant). It mutates the code and fails if too
# few mutants are killed, which proves the tests actually catch regressions
# rather than merely running green. A handful of surviving mutants are
# equivalent (a sort over equal keys, an early-return optimization) and do not
# change behaviour, so the efficacy threshold sits below 100 deliberately.
# Needs gremlins: go install github.com/go-gremlins/gremlins/cmd/gremlins@v0.5.0
mutation:
	gremlins unleash --timeout-coefficient 8 --threshold-efficacy 90 --threshold-mcover 75 ./internal/sigma

# --- performance: tracked, not vibed ---
#
# bench runs the in-process Go benchmarks (matcher, parsers) with the race
# detector OFF and allocs reported. -count makes benchstat's statistics
# meaningful. Results land in bench/new.txt.
bench count="10":
	mkdir -p bench
	go test ./... -run '^$' -bench . -benchmem -count={{count}} | tee bench/new.txt

# bench-baseline records the current numbers as the committed reference
# `bench-compare` diffs against. It is machine-specific (the goos/goarch/cpu
# header says which), so compare on the same machine; CI treats a cross-runner
# delta as indicative only and the trend dashboard is the real cross-run gate.
# Run it deliberately, when a change is meant to move performance, and commit
# bench/baseline.txt with that change.
bench-baseline count="10":
	mkdir -p bench
	go test ./... -run '^$' -bench . -benchmem -count={{count}} | tee bench/baseline.txt

# bench-compare shows the delta from the committed baseline to a fresh run.
# benchstat prints the percentage change and whether it is statistically
# significant, so a regression is a number, not a hunch.
bench-compare: (bench "10")
	benchstat bench/baseline.txt bench/new.txt

# bench-e2e measures a full binary scan over a large synthetic log with
# hyperfine: build -> generate ~200k events -> time `banken` end to end (fresh
# cursor each run so every run does the full scan). This catches regressions
# the micro-benchmarks miss -- startup, rule loading, file I/O.
bench-e2e n="200000":
	#!/usr/bin/env bash
	set -euo pipefail
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	go build -o "$tmp/banken" .
	go run ./tools/genlog -n {{n}} > "$tmp/audit.jsonl"
	printf 'rules: [./rules]\nstatePath: %s/state.json\nsources:\n  - type: laurel\n    path: %s/audit.jsonl\n' "$tmp" "$tmp" > "$tmp/banken.yml"
	hyperfine --warmup 1 --prepare "rm -f $tmp/state.json" \
		--export-json "$tmp/e2e.json" \
		"$tmp/banken -config $tmp/banken.yml"
	echo "log: {{n}} events -> $(wc -c < "$tmp/audit.jsonl") bytes"

# Short fuzz run against every Fuzz* target in every package, discovered via
# `go test -list` (not hardcoded, so a new target is picked up
# automatically). {{fuzztime}} per target (default 5s).
fuzz fuzztime="5s":
	#!/bin/sh
	set -eu
	for pkg in $(go list ./...); do
		names="$(go test "$pkg" -list '^Fuzz' 2>/dev/null | grep '^Fuzz' || true)"
		for name in $names; do
			echo "--- fuzzing $name in $pkg ({{fuzztime}}) ---"
			go test "$pkg" -run '^$' -fuzz "^${name}\$" -fuzztime {{fuzztime}}
		done
	done

# Deeper sweep of the rapid property tests than their plain `go test`
# default (100 cases each). `just property-deep` for 10,000 per property.
# Scoped to the package that imports rapid -- -rapid.checks is only a
# registered flag there, so `go test ./...` would reject it elsewhere.
property-deep checks="10000":
	go test ./internal/parser/ -run '^TestProperty' -count=1 -rapid.checks={{checks}}

# Build the binary to output/banken, stamping in the version.
build:
	mkdir -p output
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" -trimpath -o output/banken .

# install-hooks points git at the repo's tracked hooks (core.hooksPath), so a
# fresh clone enforces the commit-msg policy (no AI attribution) with no
# dependence on any global git config. Run once after cloning.
install-hooks:
	git config core.hooksPath .githooks
	@echo "core.hooksPath -> .githooks"
