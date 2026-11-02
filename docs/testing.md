# Testing

Heavily tested - a root daemon that parses untrusted log bytes and ingests rules has to be, so the
bar is "a malformed input or a hostile rule can degrade a detection, never crash the detector."

**Dev environment.** The shared dev toolbox is
[workbench](https://github.com/conor-sometimes/workbench) (it pins the same toolchain for the whole
banken family, banken and mimi alike):

```sh
nix run github:conor-sometimes/workbench#banken -- -c 'just default'   # the pinned toolchain, no install
```

Or `nix develop` on this repo gives the full toolchain `just` drives (Go, gofumpt, golangci-lint,
gosec, govulncheck, staticcheck, delve, ...) with nothing to install - then `just` lists the
targets and `just default` runs the whole gate. `nix develop .#conformance` adds the standards-gate
tools (uv + Nix's Pythons); off Nix, install the tools `just` names.

- `go test ./...` - table-driven cases for every parser, the rule compiler and the matcher, plus
  the `tests/fixtures/*.json` events (`NAME.expect-<rule>.json` must fire that rule;
  `*.expect-none.json` must fire nothing), golden-file parser output, and `pgregory.net/rapid`
  property sweeps.
- **Never-die contracts, as tests.** `TestCursorAlwaysRecoverable` (a missing/empty/corrupt state
  file always recovers to a fresh cursor), the engine's per-event and per-source panic guards (one
  pathological record can't take down a scan), and `TestRuleValuesAreInertData` (a rule value is
  matched as opaque text - shell substitutions, format verbs, templates, globs and path-traversal
  strings never expand or execute, so a remote rule can't become root code execution).
- **Go fuzzing** (`go test -fuzz`) - the whole untrusted surface:
  - `FuzzSigmaParse` - the rule **compiler**: arbitrary YAML must compile to a clean error or a
    usable rule, never a panic (a crash while loading rules is a crash of the detector).
  - `FuzzMatcherEquivalence` - the compiled Aho-Corasick prefilter must return the **exact same
    verdict** as the naive check-every-rule matcher, on arbitrary rules and events. A divergence
    would be a silently skipped detection.
  - `FuzzEnginePipeline` - the full read -> parse -> normalise -> match path on raw bytes, with no
    recover guard, so any latent panic surfaces.
  - `FuzzParseAuditd`, `FuzzParseLaurel`, `FuzzParseStubs`, `FuzzMatch`, `FuzzIOC` - each parser and
    matcher against random and malformed input.

  A 30-45s smoke of each target runs in CI; a longer campaign (3 min per target) reached
  **~73.6 million executions across the parser targets, zero crashes, zero equivalence
  divergences**. The per-target breakdown below is from the shorter smoke.

  | Target | Execs | Target | Execs |
  | --- | ---: | --- | ---: |
  | `FuzzEnginePipeline` | 5.75M | `FuzzMatch` | 3.75M |
  | `FuzzParseAuditd` | 3.96M | `FuzzParseLaurel` | 2.89M |
  | `FuzzIOC` | 2.44M | `FuzzMatcherEquivalence` | 2.05M |
  | `FuzzParseStubs` | 0.16M | `FuzzSigmaParse` | 0.14M |

- `tests/emulations/<family>.sh` - benign look-alikes of real malware (dummy data, unroutable "C2",
  cleaned up; see `tests/emulations/README.md`). The NixOS VM test (`tests/vm.nix`) runs each as an
  ordinary user against real auditd and asserts the rules that fire are *exactly* the family's
  expected set - a miss and a false positive both fail. Its first run found two bugs no fixture
  could: every exec reported its own binary as a target (so banken's own scan tripped
  `tamper_banken`), and NixOS's multicall coreutils hid `cat`/`rm`/`base64` behind `exe=coreutils`.
- **Performance is benchmarked and regression-tracked** - `just bench` / `just bench-compare`
  (`benchstat`) for the matcher and parsers, and `just bench-e2e` (`hyperfine`) for a full binary
  scan over a large synthetic log. See [Performance](performance.md).
- **CI** (`.github/workflows`) runs `go test -race`, `go vet`, `staticcheck`, `golangci-lint`,
  `errcheck`, `gosec`, `govulncheck`, a short fuzz smoke and the benchmarks on every push, a
  **nightly fuzz campaign** (5 min/target, corpus cached between runs), and validates the OCSF
  goldens against the official schema (`just ocsf-validate`). The VM test needs KVM and runs on the
  project's build host (`nix flake check`).

After cloning, run `just install-hooks` once: it points `core.hooksPath` at the repo's tracked
`.githooks/`, whose `commit-msg` hook keeps AI-tool attribution out of commit messages.
