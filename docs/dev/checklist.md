# Per-commit checklist

What to run before a change lands, tiered by cost. Running the full distro matrix or the
stress/profiling suite on every commit is impractical (tens of minutes of KVM each). So the fast
gate runs on every commit, and the heavy work runs per-PR or nightly.

This file is the SPEC. The goal is that each item is AUTOMATED - a `just` target, a CI job, or the
pre-commit hook - not a thing a human remembers. Where an item is not wired yet it is marked TODO
with its Taskwarrior anchor. Wiring it is the work; this doc is the contract.

## Golden rule

Run the WHOLE `just default`, never a subset like `go test ./internal/...`. The CI breakage on
2026-11-02 (staticcheck plus govulncheck red tree-wide) slipped through for exactly this reason.
Every local and worker gate ran `go test ./internal/...` and `golangci-lint` on subsets, so nobody
exercised `staticcheck ./...`, gosec over `bench/`, or `govulncheck`. A green subset is not a green
gate.

## Tier 1 - every commit (fast, local pre-push; this IS the CI gate, must be green)

- [x] `just default` in full: gofumpt, go vet, `staticcheck ./...`, golangci-lint, errcheck, gosec,
      **govulncheck**, unit tests + coverage. (govulncheck is non-negotiable: an EDR must not ship
      known stdlib vulns. It is the thing that was silently failing.)  Automated: CI `default` job;
      locally via `just precommit`.
- [x] Hooks pass: no em/en dashes, no AI-attribution (enforced by `.githooks`; `just install-hooks`).
- [x] `go run ./tools/sigmacov -require-all ./rules`: every own rule loads (100%).  Automated:
      `just rules-check` (CI `default` job, and part of `just precommit`).
- [x] Every rule has a fixture and an OCSF golden (the `internal/engine` TestFixtures /
      every-rule-has-a-golden tests, part of `go test`).
- [x] OCSF goldens validate against the pinned schema (`just ocsf-validate`; CI `ocsf` job, and
      part of `just precommit`).
- [x] **Cross-compile clean**: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build .` and the same for
      `./internal/...`. banken's product cross-compiles to Windows today; keep it that way now that
      Windows support is on the roadmap. (The Linux test harness `tests/distros/distrocheck` is
      exempt - it is Linux-only by design.)  Automated: `just cross-compile` (CI `default` job).
- [x] **Binary-size guard**: the ~7 MiB static binary is a headline claim; `just size-check` fails if
      the release build exceeds 9 MiB (`max_binary_bytes` in the justfile; bump it deliberately).
      Automated in CI `default` job.
- [ ] **Idle-RSS guard**: the ~14 MiB RSS claim needs a running daemon, so it is not in the fast
      tier.  TODO (nightly deep tier; `bench/run.sh idle` measures it).
- [x] Short fuzz smoke: every `Fuzz*` target runs for a few seconds inside `just default` (`unit`
      depends on `fuzz`), so `just precommit` and the CI `default` job both include it. Targets are
      discovered with `go test -list`, so a new one is covered with no edit. The long campaign is
      Tier 3.

## Tier 2 - every PR / pre-merge to trunk (heavier, hokkaido KVM)

- [ ] `nix flake check`: the VM integration tests (vm, switch, switch-floor, switch-restart) and the
      wired emulation checks (sigmahq-emul).
- [ ] pySigma conformance differential: rules agree with the reference engine (`just conformance`).
- [ ] `nix run .#distro-matrix-mimi`: all 8 distros plus NixOS on their own kernels, with the mimi
      and Sysmon scenario suites. **This is "verify across all distros we test on" - it lives here,
      not per-commit.**
- [x] Benchmarks (indicative, non-gating) run and APPENDED to the per-commit benchmark history file
      (`bench/history.ndjson`, one JSON line per commit, see `bench/README.md`) so
      regressions/improvements are trackable over time; benchstat delta vs the committed baseline
      in the PR summary. The CI `bench` job appends and uploads; `just bench-history` appends a line
      measured locally (commit those from a trusted machine such as hokkaido).
- [ ] **Reproducible-build hash**: `nix build .#banken` twice (or `--rebuild`) and confirm the output
      hash is stable; publish the hash + the command that reproduces it. It is a trust claim in
      docs/design/standards.md.  TODO (wire the check).
- [ ] SBOM generated (`just sbom`, already a CI job).

## Tier 3 - per meaningful change / nightly (deep, expensive)

- [ ] **Stress test**: load hundreds of thousands of rules, then benchmark load + match (latency
      p50/p99, throughput eps, RSS) at that scale. Feed into the per-commit history.  TODO.
- [ ] **Profiling**: CPU flamegraph (pprof) + heap/allocation profile (`-inuse_space`/`-alloc_space`;
      heaptrack is KDE/C++ only, pprof is the Go analog); diff against the last profile.  TODO.
- [x] **Full fuzz campaign**: long `Fuzz*` runs on every parser, corpus kept.  Automated:
      `.github/workflows/fuzz.yml` (nightly; discovers every `Fuzz*` target, caches the corpus,
      uploads crashers).
- [ ] Atomic Red Team range: per-technique coverage score (the 24/115-on-merit trend).
- [ ] SigmaHQ whole-tree load-rate trend (not just rules/linux; the 97.6% figure).
- [ ] "Quiet host = zero alerts" false-positive baseline: an ordinary admin workload raises no
      alerts. We advertise it; prove it.  TODO (make it a standing test).

## Automation status

Wired today:

- `just precommit` - the whole Tier 1 in one command: `just default` (incl. the fuzz smoke),
  `just rules-check`, `just ocsf-validate`, `just cross-compile`, `just size-check`
- the CI `default` job, running the same guards
- the hooks
- `nix flake check`, `nix run .#distro-matrix-mimi`, `just conformance`, `just sbom`
- the nightly fuzz campaign (fuzz.yml)
- the CI `bench` job, which appends each commit's numbers to `bench/history.ndjson`

Still manual or TODO (Taskwarrior, project:banken.testing / banken.bench / banken.ci):

- a nightly deep-tier job
- the idle-RSS guard
- the stress + profiling harness
- the reproducible-hash check
- the false-positive baseline test

The CI `bench` job uploads the history file as an artifact but does not commit it back; a line
committed to the repo comes from `just bench-history`.
