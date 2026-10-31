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
