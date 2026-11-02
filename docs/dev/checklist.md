# Per-commit checklist

What to run before a change lands, tiered by cost. Running the full distro matrix or the
stress/profiling suite on every commit is impractical (tens of minutes of KVM each), so the fast
gate runs on every commit and the heavy work runs per-PR or nightly.

This file is the SPEC. The goal is that each item is AUTOMATED (a `just` target, a CI job, or the
pre-commit hook), not a thing a human remembers. Where an item is not wired yet it is marked TODO
with its Taskwarrior anchor; wiring it is the work, this doc is the contract.

## Golden rule

Run the WHOLE `just default`, never a subset like `go test ./internal/...`. The CI breakage on
2026-11-02 (staticcheck + govulncheck red tree-wide) slipped through for exactly this reason: every
local and worker gate ran `go test ./internal/...` and `golangci-lint` on subsets, so nobody
exercised `staticcheck ./...`, gosec over `bench/`, or `govulncheck`. A green subset is not a green
gate.

## Tier 1 - every commit (fast, local pre-push; this IS the CI gate, must be green)

- [ ] `just default` in full: gofumpt, go vet, `staticcheck ./...`, golangci-lint, errcheck, gosec,
      **govulncheck**, unit tests + coverage. (govulncheck is non-negotiable: an EDR must not ship
      known stdlib vulns. It is the thing that was silently failing.)
- [ ] Hooks pass: no em/en dashes, no AI-attribution (already enforced by `.githooks`).
- [ ] `go run ./tools/sigmacov -require-all ./rules`: every own rule loads (100%).
- [ ] Every rule has a fixture and an OCSF golden (the `internal/engine` TestFixtures /
      every-rule-has-a-golden tests, part of `go test`).
- [ ] OCSF goldens validate against the pinned schema (`just ocsf-validate`).
- [ ] **Cross-compile clean**: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build .` and the same for
      `./internal/...`. banken's product cross-compiles to Windows today; keep it that way now that
      Windows support is on the roadmap. (The Linux test harness `tests/distros/distrocheck` is
      exempt - it is Linux-only by design.)
- [ ] **Binary-size + idle-RSS guard**: the ~7 MiB static binary and ~14 MiB RSS are headline
      claims; fail the gate if they balloon past a threshold.  TODO (wire into CI).
- [ ] Short fuzz smoke: run each `Fuzz*` target for a few seconds (`go test -run '^$' -fuzz=Fuzz...
      -fuzztime=10s` per parser). The long campaign is Tier 3.  TODO (wire the short run).

## Tier 2 - every PR / pre-merge to trunk (heavier, hokkaido KVM)

- [ ] `nix flake check`: the VM integration tests (vm, switch, switch-floor, switch-restart) and the
      wired emulation checks (sigmahq-emul).
- [ ] pySigma conformance differential: rules agree with the reference engine (`just conformance`).
- [ ] `nix run .#distro-matrix-mimi`: all 8 distros + NixOS on their own kernels, mimi M1-M5, Sysmon
      S1-S5. **This is "verify across all distros we test on" - it lives here, not per-commit.**
- [ ] Benchmarks (indicative, non-gating) run and APPENDED to the per-commit benchmark history file
      so regressions/improvements are trackable over time; benchstat delta vs the committed baseline
      in the PR summary.  (history file: TODO)
- [ ] **Reproducible-build hash**: `nix build .#banken` twice (or `--rebuild`) and confirm the output
      hash is stable; publish the hash + the command that reproduces it. It is a trust claim in
      docs/design/standards.md.  TODO (wire the check).
- [ ] SBOM generated (`just sbom`, already a CI job).

## Tier 3 - per meaningful change / nightly (deep, expensive)

- [ ] **Stress test**: load hundreds of thousands of rules, then benchmark load + match (latency
      p50/p99, throughput eps, RSS) at that scale. Feed into the per-commit history.  TODO.
- [ ] **Profiling**: CPU flamegraph (pprof) + heap/allocation profile (`-inuse_space`/`-alloc_space`;
      heaptrack is KDE/C++ only, pprof is the Go analog); diff against the last profile.  TODO.
- [ ] **Full fuzz campaign**: long `Fuzz*` runs on every parser, corpus kept.  TODO.
- [ ] Atomic Red Team range: per-technique coverage score (the 24/115-on-merit trend).
- [ ] SigmaHQ whole-tree load-rate trend (not just rules/linux; the 97.6% figure).
- [ ] "Quiet host = zero alerts" false-positive baseline: an ordinary admin workload raises no
      alerts. We advertise it; prove it.  TODO (make it a standing test).

## Automation status

- Wired today: `just default` (Tier 1 lint/test/vuln), the hooks, `just ocsf-validate`, `nix flake
  check`, `nix run .#distro-matrix-mimi`, `just conformance`, `just sbom`, the CI `bench` job
  (indicative, non-gating).
- TODO (Taskwarrior, project:banken.testing / banken.bench / banken.ci): a `just precommit` fast-tier
  wrapper, a nightly deep-tier job, the per-commit benchmark history file, the stress + profiling
  harness, the cross-compile + binary-size + reproducible-hash + fuzz-short CI steps, and the
  false-positive baseline test.
