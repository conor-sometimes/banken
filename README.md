# banken

番犬 — "watchdog". A small, host-wide EDR: it watches the machine's logs on a timer, matches them
against Sigma rules and IOC lists, and alerts. One Go binary, no agent runtime, no Python — a
poor-man's SentinelOne you can actually read.

The goal is **SentinelOne for the masses**: install it in one command, no fiddling — a sane default
ruleset, the log source auto-detected, a hardened unit and timer, enabled. Everything below is in
service of that (and of never lying about what's detected).

Deeper docs are in [`docs/`](docs/): [architecture](docs/architecture.md),
[writing rules](docs/writing-rules.md), [deployment](docs/deployment.md).

Not an agent thing: banken watches the *whole host*. A contained AI agent, a cron job, a logged-in
user — if it does something a rule flags, banken alerts. (The
[agent containment](https://github.com/conor-sometimes/nixos-agent-containment) is one consumer: it
adds its own tighter agent-specific rules on top.)

## How it works

    logs (auditd / journald / Laurel JSON / auth)  ->  banken [ parse -> normalise -> match ]  ->  alerts

One self-contained tool: banken **parses the logs itself**. A parser per source — raw auditd (the
multi-line execve/path/cwd records joined into one event), Laurel's JSON, journald, syslog/auth —
normalises to one common event that the rules match. A new log type is a new parser behind the same
interface; nothing else changes.

A systemd timer runs `banken` every interval; each run reads the events since the last cursor,
matches, and emits hits. One-shot by design — systemd owns the schedule, no daemon to babysit
(`banken --watch` for a self-timing daemon is a later add). Laurel stays supported as an input, but
banken no longer *needs* it: with the auditd parser the end state is `auditd + banken + a timer`.

## Log sources

A parser per source, all behind one interface, each normalising to the common event the rules
match. A new source is a new parser and nothing else changes.

| Source | What | Status |
| --- | --- | --- |
| **auditd** | raw Linux audit log — the multi-line SYSCALL/EXECVE/PATH/CWD/PROCTITLE records stitched back into one event (hex-decoded argv/proctitle, quoted and bare values) | **implemented** |
| **Laurel** | auditd → JSON ([Laurel](https://github.com/threathunters-io/laurel)), one reassembled event per line | **implemented** |
| journald | the systemd journal (`_COMM`/`_EXE`/`_CMDLINE`/`_UID`) | stubbed (interface placeholder) |
| syslog / auth | RFC 3164/5424 — `/var/log/auth.log`, `secure` (sshd / sudo / PAM logins) | stubbed (interface placeholder) |
| **generic JSONL** | one pre-normalised event per line — the universal adapter any external collector emits to (`-source generic:PATH`) | **implemented** |
| eBPF / Falco | kernel syscall + network events (via a helper → generic JSONL) | planned |
| network | Zeek / Suricata, for network IOCs | planned |

Both auditd and Laurel are wired up and tested this pass (table + golden + fuzz, see Testing); the
journald and syslog parsers exist as stubs behind the same interface (they drain their input and
emit nothing) so slotting the real logic in later touches nothing else. **IOC coverage follows the
sources:** file, process and command-line IOCs work against the auditd sources today; hash and
network IOCs arrive with the eBPF / network sources.

## Rules

Portable [Sigma](https://github.com/SigmaHQ/sigma) YAML, organised so a rule's *home* says what it
is, plus plain IOC lists for bulk feeds:

    rules/
      credential-access/    persistence/    execution/
      command-and-control/  privilege-escalation/   ...   # behavioural rules, by ATT&CK tactic
      malware/<family>/                                    # family-specific signatures (IOCs unique to a family)
      ioc/*.txt                                            # bulk IOC lists (filenames, IPs, domains), one per line

- **Behavioural rules** detect a *behaviour*, not a family, so they live by tactic (reading a
  credential is `credential-access/` whether AMOS, RedLine or a human did it). The SigmaHQ Linux
  set drops in by the same scheme as a noisy baseline.
- **Family signatures** are Sigma too (an IOC is just a matched value), kept under `malware/<family>/`.
- **Bulk IOC feeds** (thousands of values) go in `ioc/*.txt` as flat lists, one value per line, not
  one Sigma file each.

banken evaluates the field modifiers `contains` / `startswith` / `endswith` / `re` / `cidr` / `all`,
plain-value equality, `*`/`?` wildcards, keyword (bare string-list) selections, and conditions of
`and`/`or`/`not`/parens and `N of` / `all of` — with a clear load error (never a silent drop) on a
rule it can't evaluate. **Measured coverage: banken loads 100% of the SigmaHQ `rules/linux` set
(211/211)** — run `go run ./tools/sigmacov <sigma>/rules/linux` yourself. "Loads" means it compiles
and evaluates; a rule that needs a field only a future source provides (e.g. a network `cidr` rule)
loads and stays inert until that source lands, rather than failing. Verdict-level conformance against
the reference engine (pySigma) is the next bar — see the roadmap.

## Alerts

Pluggable sinks, any combination:

- **journal** — high/critical to the system journal (syslog), a one-line login summary for admins.
- **jsonl** — one file per day of alerts, kept `retentionDays`, so retention is a file delete.
- **webhook** — POST the alert JSON to a URL (generic, or Slack/Discord/ntfy shaping). The URL is a
  secret: it comes from `alerts.webhook.urlFile` (sops/agenix or a systemd credential), never inline
  in the Nix store. The service runs as root, so the webhook host just needs to be reachable.

**OCSF.** Both the jsonl and webhook sinks can emit alerts as [OCSF](https://schema.ocsf.io) 1.3.0
Detection Findings instead of banken's own JSON (`alerts.jsonl.format: ocsf`, `-jsonl-format ocsf`;
`alerts.webhook.style: ocsf`), so Security Lake, Splunk, Datadog or any OCSF-aware SIEM ingests them
with no per-product mapping, ATT&CK tactics and techniques included. Every baseline rule has a
committed finding golden, and CI validates them against the official schema with the OCSF project's
own validator (`just ocsf-validate`). Design: [docs/design/ocsf-output.md](docs/design/ocsf-output.md).

Matched alerts flow through one dispatch point, so **response actions** (kill a process, revoke a
key, isolate) slot in later without a redesign. For now: alert only.

## Performance

The rule count is not supposed to be something you worry about, so matching does **not** scan every
rule against every event. At load time every string literal across every rule
(`|contains`/`|startswith`/`|endswith`/equality) is compiled into one
[Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) automaton. For each
event, one pass per field finds the set of literals present anywhere in it — in time proportional to
the event length, *independent of how many rules exist* — and only the rules that could match that
set get the authoritative per-rule check (an inverted literal→rule index plus a sound upper-bound
test on the rule's condition). Regexp and negation rules that no literal can gate are kept in a small
always-evaluated set.

It is a pure prefilter in front of the unchanged per-rule matcher, never a replacement, so a rule it
skips provably could not have matched (the found-literal set is always a superset of the true
literals). That property is fuzzed: `FuzzMatcherEquivalence` asserts the compiled matcher returns the
exact same verdict as the naive "check every rule" matcher on arbitrary rules and events.

Measured on an M-class laptop, matching one event against a synthetic tree of distinct rules
(`go test -bench`):

| Rules | Naive (every rule) | Compiled matcher | Matcher allocs/op |
| ---: | ---: | ---: | ---: |
| 100 | 21 µs | 0.75 µs | 4 |
| 1,000 | 208 µs | 1.7 µs | 4 |
| 10,000 | 2,400 µs | 11 µs | 4 |

Naive matching grows linearly with the rule count; the compiled matcher stays flat enough to carry
the whole SigmaHQ Linux set, and its allocations per event are **constant** regardless of rule count.
(Parallelising across events with a goroutine pool is a later, complementary lever — the matcher is
read-only and so trivially parallel — but the algorithm is what makes rule count cheap.)

**Detection latency** — the number that matters for an EDR. `BenchmarkDetectionLatency` times a real
threat from log line to alert (parse one malicious record, match it against the full embedded
baseline): **~10 µs** per threat event (≈8 µs for a clean event). End-to-end latency in a deployment
is that compute plus at most one timer interval — the one-shot model's tradeoff — which `--watch` or
a shorter interval shrinks. So the interval, not the matching, is the latency knob.

## Security model

banken runs as root (it reads the root-owned audit log) and may one day pull rules from a remote
repo, so the rule channel must never become a way to run code as root — a detector you can turn into
a trojan is worse than no detector. The guarantee is layered:

1. **Rules are inert data, never code.** The Sigma subset has no eval path — no shell-out, no
   template or format expansion, no plugin loading, no rule-controlled file/URL/exec. A rule value is
   only ever matched as an opaque string; a regexp is Go's RE2 (linear time, no catastrophic
   backtracking, no code execution). YAML is parsed with `yaml.v3`, which has none of the
   object-instantiation gadgets that make `yaml.load`-style parsers dangerous. So even a
   fully attacker-authored rule can at worst produce wrong or missing *detections* — never execution.
   `TestRuleValuesAreInertData` locks this: shell substitutions, format verbs, templates, globs and
   path-traversal strings all stay literal.
2. **Response actions are operator policy, never rule-embedded.** A rule only emits a tag; the local
   operator config maps tags to actions (kill, quarantine). A remote rule can never carry its own
   "kill this / delete that."
3. **Trusted path (planned).** As root, banken should distrust rules from a directory writable by
   anyone but its owner (the classic local-unprivileged-user-edits-the-rule escalation) and flag it,
   with an opt-in strict mode to refuse. *Not yet implemented* — today banken only loads from the
   paths it is given; make the rules dir root-owned and `0755` yourself.
4. **The fetch is deprivileged and can't run code (planned).** When remote rule sync exists it will
   be a separate command (never the scan), neutering git's code-execution surfaces (hooks, filter
   drivers, fsmonitor) or using a plain tarball, and running as a dedicated low-privilege user.
   *There is no fetch today* — rules are local only, so this surface does not exist yet.
5. **Signed bundles (v2).** Remote rule/config bundles are signature-verified against a locally
   pinned public key with a monotonic version, so a compromised transport or repo host cannot push a
   rogue rule set in the first place.

The scan itself is one-shot and has no inbound or rule-fetch network surface by design; the only
outbound connection is the optional webhook POST from the scan process.

## Use (NixOS)

NixOS is supported first-class: the module, the package and the end-to-end VM test live in this
repo. Add the flake and enable it:

```nix
# flake.nix
inputs.banken.url = "github:conor-sometimes/banken";
# your nixosConfiguration's modules
modules = [ banken.nixosModules.default ];
```

```nix
services.banken.enable = true;   # that's the whole setup
```

`enable` turns on auditd with the rules banken reads (every execve, plus watches on
`/etc/shadow` and `/etc/gshadow`), a hardened oneshot unit, and a timer that runs a scan every
two minutes, alerting high and critical hits to the journal. Everything else is optional:

```nix
services.banken = {
  enable = true;
  interval = "30s";
  extraRules = [ ./my-rules ];                        # Sigma .yml and ioc/ lists, on top of the baseline
  alerts.jsonl = { enable = true; format = "ocsf"; };  # /var/log/banken, one OCSF finding per line
  alerts.webhook = { enable = true; urlFile = "/run/secrets/banken-webhook"; style = "slack"; };
};
```

Without flakes, import `module.nix` from a pinned checkout (see `default.nix`); the package alone is
`pkgs.callPackage ./package.nix { }`. The module is tested by `tests/vm.nix` (`nix flake check`):
a VM runs every emulation in `tests/emulations` against real auditd and asserts exactly the expected
rules fire, as OCSF findings.

## Testing

Heavily tested — a root daemon that parses untrusted log bytes and ingests rules has to be, so the
bar is "a malformed input or a hostile rule can degrade a detection, never crash the detector."

- `go test ./...` — table-driven cases for every parser, the rule compiler and the matcher, plus the
  `tests/fixtures/*.json` events (`NAME.expect-<rule>.json` must fire that rule; `*.expect-none.json`
  must fire nothing), golden-file parser output, and `pgregory.net/rapid` property sweeps.
- **Never-die contracts, as tests.** `TestCursorAlwaysRecoverable` (a missing/empty/corrupt state
  file always recovers to a fresh cursor), the engine's per-event and per-source panic guards (one
  pathological record can't take down a scan), and `TestRuleValuesAreInertData` (a rule value is
  matched as opaque text — shell substitutions, format verbs, templates, globs and path-traversal
  strings never expand or execute, so a remote rule can't become root code execution).
- **Go fuzzing** (`go test -fuzz`) — the whole untrusted surface:
  - `FuzzSigmaParse` — the rule **compiler**: arbitrary YAML must compile to a clean error or a usable
    rule, never a panic (a crash while loading rules is a crash of the detector).
  - `FuzzMatcherEquivalence` — the compiled Aho-Corasick prefilter must return the **exact same
    verdict** as the naive check-every-rule matcher, on arbitrary rules and events. A divergence would
    be a silently skipped detection.
  - `FuzzEnginePipeline` — the full read → parse → normalise → match path on raw bytes, with no
    recover guard, so any latent panic surfaces.
  - `FuzzParseAuditd`, `FuzzParseLaurel`, `FuzzParseStubs`, `FuzzMatch`, `FuzzIOC` — each parser and
    matcher against random and malformed input.

  Latest full campaign (≈30–45s each, 10 workers): **~21.1 million executions across the 8 targets,
  zero crashes, zero equivalence divergences.**

  | Target | Execs | Target | Execs |
  | --- | ---: | --- | ---: |
  | `FuzzEnginePipeline` | 5.75M | `FuzzMatch` | 3.75M |
  | `FuzzParseAuditd` | 3.96M | `FuzzParseLaurel` | 2.89M |
  | `FuzzIOC` | 2.44M | `FuzzMatcherEquivalence` | 2.05M |
  | `FuzzParseStubs` | 0.16M | `FuzzSigmaParse` | 0.14M |

- `tests/emulations/<family>.sh` — benign look-alikes of real malware (dummy data, unroutable "C2",
  cleaned up; see `tests/emulations/README.md`). The NixOS VM test (`tests/vm.nix`) runs each as an
  ordinary user against real auditd and asserts the rules that fire are *exactly* the family's
  expected set — a miss and a false positive both fail. Its first run found two bugs no fixture
  could: every exec reported its own binary as a target (so banken's own scan tripped
  `tamper_banken`), and NixOS's multicall coreutils hid `cat`/`rm`/`base64` behind `exe=coreutils`.
- **Performance is benchmarked and regression-tracked** — `just bench` / `just bench-compare`
  (`benchstat`) for the matcher and parsers, and `just bench-e2e` (`hyperfine`) for a full binary
  scan over a large synthetic log. See [Performance](#performance).
- **CI** (`.github/workflows`) runs `go test -race`, `go vet`, `staticcheck`, `golangci-lint`,
  `errcheck`, `gosec`, `govulncheck`, a short fuzz smoke and the benchmarks on every push, and
  validates the OCSF goldens against the official schema (`just ocsf-validate`). The VM test needs
  KVM and runs on the project's build host (`nix flake check`).

After cloning, run `just install-hooks` once: it points `core.hooksPath` at the repo's tracked
`.githooks/`, whose `commit-msg` hook keeps AI-tool attribution out of commit messages.

## Status

Early. v1 is Laurel-first input, the Sigma subset above, journal/jsonl/webhook alerts, one-shot
timer. Roadmap: `--watch` daemon mode, direct auditd ingestion (drop Laurel), journald and other
log sources, response actions, a tuned baseline over a week of real activity.

## Licence

GPL-3.0-or-later. Rules are plain Sigma — copy them out with `git subtree split rules/` if you want
them without the binary.
