# Design: YARA integration

Status: **proposal, not implemented.** Nothing in this document exists in the tree yet. It is written
to be reviewed, argued with, and then either built or shelved. Written 2026-10-31 against commit
`17c1d21`.

## 1. Summary and recommendation

banken matches *events* (one process execution, one file access) against Sigma rules and IOC lists.
YARA matches *content* — the bytes of a file (or a process's memory) against signatures. That is a
genuinely new detection surface: it does not fit the `Event` → `Matcher` path and should not be
forced into it. The right fit is **a scan of a file that an existing alert already pointed at**: when
a Sigma/IOC alert names a `TargetFilename` (or the `Image` that ran), banken asks "does that file trip
a YARA rule?", and a hit becomes a second, correlated alert carrying the YARA rule, the path and the
file's SHA-256. The same scanner runs at quarantine / evidence-collection time on the artifact copy,
which is the one place the scan is reliable (no race with the attacker deleting the dropper), and on
demand via `banken yara FILE`, mirroring `banken check`.

The hard question is not *where* but *how*. YARA is a C library (libyara) or a C program (`yara`);
there is no mature pure-Go engine. banken's whole dependency story is "one external Go module, CGO
off, a static binary you can read". Section 3 lays out the four real options. The recommendation:

> **Shell out to the `yara` CLI from a small `internal/yara` package that is always compiled in but
> only active when the operator enables it and names (or the package finds) a `yara` binary.** The
> Go binary stays pure, CGO-off and static with zero new modules. The hostile-input parsing (libyara's
> PE/ELF/Mach-O parsers chewing an attacker's file, libyara's rule compiler chewing a rule) happens in
> a **separate process** that can crash, hang or be killed without touching the scan — which is
> exactly banken's never-die rule, obtained for free from the process boundary rather than from a
> `recover()`. The in-process CGO binding is kept as a documented, build-tagged *future* backend
> behind the same `Engine` interface, not built now.

What it costs, honestly: an optional runtime dependency on a host binary (declared in the NixOS
module, absent by default); an `exec` per scanned file (tens of ms, plus rule-compile time unless
rules are precompiled); a text output format we must parse and pin with golden tests per supported
YARA version; and two relaxations of the hardened unit (`PrivateTmp`, `ProtectHome`) when YARA is on,
because the files worth scanning live in exactly the directories the sandbox currently hides. None of
these are hidden; all of them are confined to the opt-in path. The default build, the default
install, and the default test run are unchanged.

## 2. Why YARA is a new surface, not a Sigma-shaped one

| | Sigma / IOC (today) | YARA |
| --- | --- | --- |
| Input | a normalised `event.Event` (a few short strings) | file bytes (KB to GB), or process memory |
| Cost per check | ~10 µs, constant allocs, rule-count independent | ms to seconds, proportional to file size × rule set |
| Where the hostile bytes come from | the audit log (parsed by our fuzzed parsers) | the attacker's own file, parsed by libyara's format modules |
| Engine | ours, pure Go, inert data | a third-party C/Rust engine with its own CVE history |
| When it runs | every event, every run | rarely: only when something already looks wrong |
| What a hit means | "this behaviour happened" | "this file *is* (looks like) family X" |

Because of the cost and the trust profile, YARA must never sit on the per-event hot path. It is a
**confirmation step** on an alert that already exists, and an **evidence step** on an artifact banken
has already decided to keep. Those two triggers cover the useful cases (a dropped payload, a modified
binary, a persistence script) without turning banken into a filesystem crawler.

Memory scanning (`yara --pid`) is explicitly out of scope for v1: it needs `CAP_SYS_PTRACE` and
`/proc/PID/mem` access, both of which the unit's sandbox (`ProtectProc=invisible`, one capability)
rightly denies, and it is a different safety problem. See §10.

## 3. The crux: integrating a C engine into a pure, static binary

### 3.1 The four options

| Option | How | Keeps "one dep, CGO off, static"? | Hostile-input isolation | Latency | Ops / packaging | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| **A. CGO binding** (`github.com/hillu/go-yara`, or the `yara-x` Go API) | link libyara into banken, scan in-process via `ScanFileDescriptor` | **No.** CGO on, libyara + libcrypto/jansson/magic linked (static musl link is possible but fragile), a second Go module, `-race`/fuzz/`govulncheck` all now span C | **None.** A libyara parser bug on an attacker's file is a bug *in the root detector*; a hostile rule can crash the detector at load | best (~ms, rules compiled once per run) | Nix package grows a libyara input; every CI job needs libyara headers; `CGO_ENABLED=0` build recipe gone | rejected as the default; viable as a build-tagged later backend (option C) |
| **B. Exec the `yara` CLI** (recommended) | `exec.CommandContext(yara, flags..., rules, /proc/self/fd/3)` with the target file pre-opened by banken; parse stdout | **Yes.** No new module, no CGO; the binary is as static as today | **Strong.** Separate process, separate address space; a crash/hang is an `exec` error, killed on deadline; the child can be run with its own creds/limits | tens of ms exec + rule compile per invocation (or ~ms with precompiled `.yarc`) | an optional host binary (`pkgs.yara`); its output format is now an interface we depend on | **recommended** |
| **C. Build-tagged in-process backend** (`//go:build yara_cgo`) | option A behind a tag, same `Engine` interface, default build excludes it | Default build: yes. Tagged build: no, and now there are two binaries to reason about | none (as A) | best | two build variants, two CI matrices; "which banken is this?" becomes a question | keep as a documented later option; do not build now |
| **D. Sidecar helper → generic JSONL** | a separate program/script runs `yara`, writes hits as `event.Event` JSON lines; banken ingests via `-source generic:` and a Sigma rule turns them into alerts | **Yes**, and zero Go changes | strong (separate process, separate unit) | poor: the sidecar does not know what banken alerted on, so it either crawls directories or tails banken's own jsonl sink → a second timer cycle of latency and a feedback loop | one more unit, one more timer, one more config; fits the `docs/log-sources.md` story for *telemetry*, poorly for *response* | not as the primary; note it as the escape hatch for bulk/periodic scanning |

Option E, "a pure-Go YARA engine", does not exist in usable form. VirusTotal's `gyp` is a pure-Go
YARA *parser* (parse and serialise rule text, no matching), which could lint rules but is another
module for a problem the recommended design does not have. Writing our own matcher for the YARA
language (strings, hex patterns with jumps, regexes, the condition language, the `pe`/`elf`/`math`
modules) is a multi-year project and would be a worse YARA. Not considered further.

### 3.2 Why B over A/C: the process boundary is a security feature, not a compromise

It is tempting to read "shell out" as the lazy option and CGO as the serious one. Here it is the
reverse, for a reason that comes straight from the README's security model: *a detector you can turn
into a trojan is worse than no detector*. Everything YARA touches is hostile input:

- **The scanned file is attacker-authored.** libyara's `pe`, `elf`, `macho`, `dotnet`, `dex` modules
  parse it. Those modules have the CVE history you would expect of C binary-format parsers. In
  process (A/C), a bug there is memory corruption in a root process whose only job is to be
  trustworthy. In a child (B), it is a crashed child and an error line.
- **The rules may be attacker-authored** once remote rule sync exists (README security model, items
  3–5). libyara's rule compiler is a yacc grammar plus a regex compiler; a hostile `.yar` can crash
  it, and its `include` directive reads arbitrary files. In process, a hostile rule crashes the
  detector at load — a silent way to switch detection off, the exact failure the never-die contracts
  exist to prevent. In a child, it fails the YARA step and the Sigma scan proceeds untouched.
- **A hang is a DoS.** A pathological regex in a rule or a crafted file can make a scan take minutes.
  In process, that stalls the one-shot run and the cursor does not advance. In a child, it is a
  `context` deadline and a `SIGKILL`.

B also has the smaller *maintenance* surface for this repo: no C toolchain in CI, no cgo build
caveats in `just build`, `govulncheck` keeps covering 100% of the binary, and the default `go test
./...` stays exactly as fast and hermetic as now.

The price of B is real and is listed in §9. The two that matter most: the CLI's text output is an
interface we do not control (mitigated by driving the CLI with a fixed, minimal flag set and golden
tests per supported version — §6), and the hardened unit must be loosened in two places to let the
scan *see* the files (§5.5). If either proves unacceptable in practice, C is the fallback, behind the
same interface, with no change to the policy layer.

### 3.3 Classic YARA vs YARA-X

VirusTotal is replacing classic YARA (C, libyara 4.x, maintenance mode) with YARA-X (Rust, `yr`
CLI, 1.0 released 2025). The design treats the engine binary as pluggable: `internal/yara` has an
`Engine` interface with one implementation per CLI (`yaraCLI`, `yaraxCLI`), selected by config or by
which binary is found. v1 implements **classic `yara` only** and leaves `yr` as a second
implementation, because:

- `pkgs.yara` is what every distro ships today; it is what an operator will have.
- YARA-X compiles rule conditions to WebAssembly and executes them with `wasmtime`, a JIT. The unit's
  `MemoryDenyWriteExecute=true` (and the kernel `PR_SET_MDWE` systemd uses on recent kernels) is
  specifically designed to break JITs. **Whether `yr scan` runs under banken's unit must be verified
  on hokkaido before `yr` is offered**; if it fails, YARA-X needs its own, slightly weaker unit (a
  reason it may stay a sidecar, option D).
- YARA-X has a structured output mode (`--output-format`) that would make parsing trivially robust.
  That is the strongest argument *for* it and the reason the interface is kept pluggable.

Nothing in the policy layer (triggers, caps, alert mapping, tests) depends on which engine runs.

## 4. Integration model

### 4.1 Where it hooks in

```
 event ─► Engine.Match ─► []Alert ─► Dispatcher.Dispatch ─► Responder ─► sinks
                              │
                              └─► (new) yara.Scanner.ShouldScan(alert) ─► ScanPath ─► Alert{Kind: yara}
                                                                                    └─► Dispatcher.Dispatch
```

The scanner is a step **in the engine's `Process` loop**, after the triggering alert has been
dispatched: for each alert the engine built, it asks the scanner whether this alert warrants a scan;
if so it scans, builds zero or more derived alerts, and dispatches them through the same dispatcher.
Reasons for putting it in the engine rather than behind the existing `Responder` hook:

- `Responder.Respond(a Alert) error` takes the alert by value and returns no alerts; it can *act*,
  it cannot *enrich* or *emit*. Making a responder re-enter `Dispatch` to emit a derived alert is a
  loop hazard (yara alert → responder → scan → yara alert …) that would need a `Kind` guard in every
  responder. The engine already owns alert construction, the per-event panic guards, and the
  dispatcher reference, so the derived alert is built where the other alerts are.
- The `Responder` seam stays what the README promises it is: **operator-policy actions** (kill,
  quarantine, isolate). The quarantine action, when it exists, calls the *same* `yara.Scanner` on
  the artifact copy it just made (§4.2b). The scanner is a library both call sites share.

A YARA hit is a **separate alert**, `Kind: "yara"`, not a mutation of the triggering alert. The
triggering alert has already gone to the sinks by the time the scan finishes (and must — a slow or
failed scan must never delay or suppress the Sigma hit). The two are correlated by the `Trigger`
field on the YARA alert plus the shared `Event`.

### 4.2 Triggers

**(a) File-touching alerts, during a scan.** Operator policy in config, never rule-embedded (README
security model item 2). Defaults:

- the triggering alert's `Level` is at or above `yara.minLevel` (default `medium`);
- the path to scan is, in order, `Event.TargetFilename` if non-empty, else `Event.Image` if
  `yara.scanImage` is true (default **true** — the `Image` of a `download_ip_to_tmp` or
  `pipe_to_shell` hit is often the dropper itself, and binaries are what community YARA sets are
  best at);
- the path is not under an excluded prefix (`yara.excludePaths`, default `/proc`, `/sys`, `/dev`,
  `/var/log/audit`, `/var/log/laurel`, `/var/lib/banken`, and the jsonl sink's `dir` — the last two
  prevent banken scanning its own state and alert files, see §5.6);
- the scanner has not already scanned that (device, inode) this run (per-run dedupe) and has not hit
  `yara.maxScansPerRun` (default 25).

A Sigma rule can therefore *not* request a scan and can *not* name a path to scan: the only path
banken ever opens is one the audit log said a process touched. A remote rule can at most widen the
set of alerts (by matching more events); it cannot steer banken's root read into a file of its
choosing.

This trigger is **best-effort by construction** and the doc must say so wherever it is described:
banken is a one-shot timer, so the scan happens up to one interval after the file was written. The
dropper may be gone, truncated, or replaced. "File missing" is logged to stderr and counted, not
alerted (a missing file is noise at scale; the Sigma alert already fired). `--watch` with a short
interval shrinks the window. The reliable scan is (b).

**(b) Quarantine / evidence collection.** `docs/design/response-actions.md` does not exist at the
time of writing, so this is a contract, not a wiring diagram: when a quarantine action copies an
artifact to the state dir (something like `/var/lib/banken/quarantine/<sha256>`, root-owned, mode
`0000`), it calls `Scanner.ScanPath` on **the copy** and records the `yara.Result` (matches, hash,
size, engine version, rule-set version) in the artifact's manifest. This scan has none of (a)'s
problems: the copy cannot change, it lives inside `ReadWritePaths`, and the sandbox already sees it.
If response actions are designed with a different artifact layout, only the call site moves.

**(c) On demand.** `banken yara [flags] FILE...` — §4.4.

### 4.3 How a match maps to an `Alert`

`alert.Alert` grows one kind constant and three optional, kind-specific fields, following the
existing pattern of `IOC`/`Field` (optional, `omitempty`, camelCase JSON tags per `tagliatelle`):

| Alert field | Value for a YARA hit |
| --- | --- |
| `Kind` | `KindYara = "yara"` |
| `Rule` | the YARA rule identifier (`[A-Za-z_][A-Za-z0-9_]*`, e.g. `MAL_Linux_XMRig_Jan24`) |
| `RuleID` | `namespace:rule` when the CLI reports a namespace (`-e`), else empty |
| `Title` | `"YARA: " + rule`; if the rule set carries a `description` meta and we ever parse meta, that |
| `Level` | from a **YARA rule tag** `critical` / `high` / `medium` / `low` if present (`rule x : high malware {…}`), else `yara.defaultLevel` (default `high`) |
| `Source` | the triggering event's `Source` (or `"yara"` for the on-demand/quarantine paths with no event) |
| `Field` | which event field supplied the path: `TargetFilename` or `Image` (reuses the IOC convention of "which field fired") |
| `File` *(new)* | the path that was opened |
| `SHA256` *(new)* | hex SHA-256 of the exact bytes scanned (computed by banken from the fd it opened — §5.1) |
| `Trigger` *(new)* | `Kind/Rule` of the alert that caused the scan, e.g. `sigma/download_ip_to_tmp`; empty for on-demand |
| `Message` | `yara rule %q matched %s (sha256 %s, %d bytes), triggered by %s` |
| `Event` | the triggering event, verbatim |
| `Time` | the triggering event's time (so jsonl day-files line up with the Sigma hit) |

Why tags for severity rather than `meta:` fields: `yara -g` prints tags as identifiers in brackets
— trivially and unambiguously parseable. `-m` prints meta values, which are free-form strings that
may contain spaces and brackets, so parsing them from the one-line text format is ambiguous. The
cost: upstream rule sets express severity as `meta: score = 75` (YARA-Forge) or not at all, so most
imported rules land at `defaultLevel`. That is acceptable for v1 (a YARA hit on a file an alert
already flagged *is* high), and a `score`-aware meta parse is a contained later addition once the
output parser is proven. The Sigma rule-level vocabulary is reused so `JournalSink.severityFor` and
the summary line need no change.

What is deliberately **not** on the alert: matched strings, offsets, or any bytes of the file. The
scan is run without `-s`; an alert goes to a webhook, and a file banken was tricked into opening
(§5.1) must not have its contents echoed to Slack. Rule, path, hash, size — never content.

One file with N rule hits produces N alerts (one per rule), mirroring one event with N Sigma hits.
`yara -l` (`--max-rules`) caps N at `yara.maxMatchesPerFile` (default 10) so a rule set that
matches everything cannot flood the sinks.

### 4.4 `banken yara` subcommand

Mirrors `banken check` in shape and spirit (the detection engineer's fast path; touches no log, no
cursor):

```
banken yara [-rules DIR,...] [-engine /path/to/yara] [-json] FILE...
```

- Loads the YARA rules exactly as a scan would (tree `yara/` dirs + `yara.rules` + the embedded
  canary rule, §4.5), applies the same safety gate (`ScanPath`: regular file, size cap, timeout), and
  prints one line per match (`[level] rule  path  sha256`) or `no yara rules matched (N loaded)`.
- `-json` prints the `yara.Result` as JSON (for scripts and for recording golden expectations).
- `-engine` overrides config/discovery; a missing engine is a clear error naming what to install,
  not a silent no-match.
- Exit status 0 regardless of match (as `check`), unless `-exit-code` is given (open question §11).
- `banken yara -selftest` scans the embedded canary bytes against the embedded canary rule and prints
  the engine version — a one-line "is YARA wired up on this host?" for operators, the EICAR idea.

### 4.5 Rules: layout, sourcing, trust

**Layout.** YARA rules live in the rule tree, beside Sigma and IOC, and the loaders already ignore
them: `sigma.LoadTree` only takes `*.yml`/`*.yaml`, `ioc.LoadTree` only `ioc/*.txt`. So:

```
rules/
  credential-access/ … malware/<family>/ … ioc/*.txt      # as today
  yara/                                                   # NEW: *.yar / *.yara, any depth
    canary.yar                                            # embedded baseline (see below)
    forge/core/…                                          # an imported bundle, if the operator adds one
```

`yara.LoadTree(dirs...)` collects `yara/**/*.yar{,a}` under each configured rule dir (same
`existingDirs` treatment as Sigma; a missing `yara/` is fine). An on-disk file with the same name as
an embedded one overrides it, as for Sigma.

**Embedded baseline.** `//go:embed rules` already captures whatever is under `rules/`, so a
`rules/yara/canary.yar` ships inside the binary. It is a single, deliberately dumb rule matching a
banken-specific canary string (no real malware signature, no upstream licence question, no false
positives), so a fresh install can prove the wiring with `banken yara -selftest` and the golden test
(§6) has a rule to use. It is **not** a detection baseline: banken does not ship third-party YARA
signatures in the binary (size, licence, and the embedded-rule-in-a-static-binary update cadence are
wrong for signature feeds). Handing the embedded rule to the CLI means writing it to a file: a
`0600` file in the unit's `PrivateTmp` per run (cheap, and the only tmp write banken makes), or
skipped when an operator rule set is configured.

**Sourcing.** The on-disk path mirrors Sigma's: the operator (or the NixOS module) puts a rule tree
on disk and lists it under `rules:`. Recommended external source: **YARA-Forge** (`yarahq`) — it
aggregates the public sets (Neo23x0 signature-base, Elastic, ReversingLabs, …), de-duplicates,
quality-scores, and publishes `core` / `extended` / `full` packages as single `.yar` files with
`meta: score` and a known-good compile against current libyara. `core` is the right default feed:
low false-positive, a few thousand rules. Pin it like a flake input in the NixOS module; the fetch
is a Nix fetch, not a banken fetch (README security model item 4: there is no fetch in the scan).

**Precompiled rules.** Compiling a few thousand YARA rules takes on the order of a second per
`yara` invocation, which is fine for a handful of scans per run but wasteful. `yarac` (ships with
yara) compiles a tree to a `.yarc` that `yara -C` loads in milliseconds. A `.yarc` is bound to the
libyara major.minor that produced it — which is exactly the guarantee a Nix derivation gives: the
module compiles the rule set with the same `pkgs.yara` it installs, at build time, and points
`yara.compiled` at the store path. The CLI-and-tree path stays for non-Nix hosts and for
`banken yara -rules DIR` iteration. A `.yarc` also cannot carry `include` directives or externals,
which removes two hostile-rule surfaces (§5.4) at the same time.

**Trust.** Same rule as Sigma (README item 3, planned): as root, distrust a rules path writable by
anyone but its owner. For YARA this check should land *with* the feature, not after: a YARA rule is
closer to code than a Sigma rule (it has `include`, externals, and a compiler with a CVE history),
and the engine binary itself is a trust point — `yara.engine` is an **absolute path**, checked to be
root-owned and not group/world-writable before every exec; banken never searches `PATH` as root.
The NixOS module sets it to the store path.

### 4.6 Config shape and the NixOS module

Follows `internal/config` (YAML, camelCase, flag overrides on top, secrets never inline — there are
none here):

```yaml
yara:
  enable: false                        # default off: no binary needed, nothing changes
  engine: /run/current-system/sw/bin/yara   # absolute path; "" => try the known default locations
  compiled: ""                         # optional precompiled .yarc (wins over the tree when set)
  timeout: 10s                         # per scan, enforced by both `yara -a` and a Go deadline
  maxFileBytes: 67108864               # 64 MiB; larger files are skipped, not partially scanned
  maxScansPerRun: 25
  maxMatchesPerFile: 10
  minLevel: medium                     # scan on alerts at this level or above
  scanImage: true                      # also scan Event.Image when no TargetFilename
  defaultLevel: high                   # level for a hit whose rule carries no level tag
  excludePaths: [/proc, /sys, /dev, /var/log/audit, /var/log/laurel, /var/lib/banken]
```

Flags: `-yara` (enable), `-yara-engine PATH`, `-yara-rules DIR,...` for one-off runs; everything
else config-only. The NixOS module exposes the same shape under `services.banken.yara.*` with
`package = pkgs.yara`, derives `engine` from it, compiles `rules` to a `.yarc` in the store, and —
this is the part that must be visible in the module's description — **adjusts the unit's sandbox**
when `yara.enable` is true (§5.5).

## 5. Safety model

banken runs as root. With YARA on, it opens files an attacker chose the names of (through the audit
log) and hands their bytes to a C parser. Every item below treats the file as hostile, the rules as
hostile-until-trusted, and the engine as a crashable third party.

### 5.1 The file: open once, scan that inode, never execute, never echo

1. **Open discipline.** `os.OpenFile(path, O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY|O_CLOEXEC, 0)`.
   `O_NOFOLLOW` refuses a final-component symlink; `O_NONBLOCK` means a FIFO cannot block the open;
   `O_NOCTTY` means a tty device cannot become our controlling terminal. Then `fstat` and require
   `S_IFREG` — a directory, device, socket, FIFO or anything else is **skipped with a reason**, never
   scanned. Then compare `Size` against `maxFileBytes`; over the cap is skipped (a partial scan would
   be a false "clean").
2. **Scan the fd, not the path.** The child receives the open fd as fd 3 (`cmd.ExtraFiles`) and is
   told to scan `/proc/self/fd/3`. Whatever the path resolves to *now* is irrelevant: the bytes
   scanned are the bytes of the inode banken opened and stat'ed. This closes the path-swap race (the
   attacker replacing the file between banken's check and yara's open) and means the SHA-256 banken
   computes from the same fd is the hash of what was actually scanned. The alert reports both the
   path (for the human) and the hash (for the truth).
3. **Residual: intermediate symlinks.** `O_NOFOLLOW` only guards the last component; a symlinked
   parent directory can still redirect the open. A fully race-free resolve needs `openat2` with
   `RESOLVE_NO_SYMLINKS` (Linux 5.6+), which is not in the standard library's `syscall` package and
   would need `golang.org/x/sys` — a new module. v1 accepts the residual, because what the attacker
   gains is *banken reading a file of their choosing into yara* — and item 5 makes that read
   worthless to them. Revisit if `x/sys` arrives for another reason.
4. **Never execute, never write, never move.** The file is opened read-only and the child gets a
   read-only fd. There is no code path that `exec`s, `chmod`s, copies or deletes the target. (The
   quarantine *action* copies — that is its job, in its own design — and then calls the scanner on
   the copy.)
5. **Never echo content.** No `-s` (print matching strings), no `-D` (module data dump), no meta.
   stderr from the child is captured, truncated to 4 KiB, and only ever logged to banken's own
   stderr — never placed on an alert. A libyara error message can quote a line of a rule or the
   name of an unreadable include; neither goes to a webhook.
6. **Exclusions** (§4.2) keep the scanner out of `/proc` (where a "file" can be `kcore` or a
   process's memory), `/dev`, `/sys`, the audit logs (large, and the attacker writes into them by
   definition), and banken's own state.

### 5.2 The child: a short-lived, bounded, killable process

- `exec.CommandContext(ctx, engine, args...)` with `ctx` carrying `yara.timeout`; `cmd.Cancel`
  sends `SIGKILL` (not the default `SIGINT`), `cmd.WaitDelay` is set so a child that ignores signals
  or leaves a grandchild holding the pipes still returns. `SysProcAttr{Setpgid: true}` and the kill
  goes to the process group. `yara -a <seconds>` is passed as a belt to the Go braces.
- Arguments are a fixed list banken composes: `-N` (`--no-follow-symlinks`), `-a <timeout>`,
  `-l <maxMatchesPerFile>`, `-g` (tags), `-w` (no warnings on stderr), `-C <yarc>` or the rule
  file(s), then `/proc/self/fd/3`. No argument ever comes from a rule or an event; the path in the
  event is *opened* by banken, not passed as a string.
- Environment is empty except `LC_ALL=C`; cwd is `/`; stdin is `/dev/null`; stdout and stderr are
  read through `io.LimitReader` (1 MiB / 4 KiB) so a child that prints forever cannot make banken
  allocate forever.
- Credentials: inside the hardened unit the child inherits root with a bounding set of exactly
  `CAP_DAC_READ_SEARCH`, `NoNewPrivileges`, the seccomp filter, `ProtectSystem=strict` and
  `MemoryDenyWriteExecute`. It needs none of that to read fd 3 and the rule file. Dropping to an
  unprivileged uid via `SysProcAttr.Credential` is attractive but **does not work in general**:
  opening `/proc/self/fd/3` re-checks permission on the inode with the opener's credentials, so a
  `0600` root-owned dropper would be unreadable to `nobody`. Noted as an optimisation for
  world-readable files only, not a safety property we rely on (§11).
- Memory: Go's standard library cannot set an rlimit on a child without a pre-exec hook it does not
  expose. The honest answer is that the child's memory is bounded by the unit's (future) `MemoryMax`
  and by the input size cap. A yara scan of a 64 MiB file against a few thousand rules is tens of MB.

### 5.3 Never-die, concretely

A YARA failure of any kind — binary missing, binary not executable, rule compile error, scan timeout,
child crash (`SIGSEGV`), output unparseable, output truncated — is **one error in `Result.Errors`
and one stderr line**, counted in the run summary (`banken: yara: 3 scanned, 1 matched, 1 failed
(timeout)`). It never:

- fails the run (`scanOnce` returns nil as before; the cursor advances on `ParseErr` alone, which
  YARA cannot set);
- suppresses or delays the triggering alert (already dispatched before the scan starts);
- panics (the scan runs under the same `recover` guard shape as `safeMatch`; and a child crash is
  not a panic at all, it is an `*exec.ExitError`).

A scan that is *skipped* (not enabled, no binary, file missing, not regular, too large, excluded,
cap hit) is a `Result.Skipped` reason, distinct from an error, so the summary tells the operator
"nothing to do" from "something broke".

The one failure that must be loud at startup, not per scan: `yara.enable: true` with no usable
engine. That is a misconfiguration, logged once per run as a `banken: yara: enabled but …` line,
and the run continues without YARA. It does not abort — a broken optional feature must not stop
Sigma detection — but it must not be silent either.

### 5.4 Hostile rules

Until signed bundles exist, a rule tree is as trusted as its directory. For YARA specifically:

- **`include "…"` is refused.** YARA's `include` reads an arbitrary path as rule text, and the
  classic CLI has no flag to disable it (libyara can, via the include callback; the CLI does not
  expose it). banken pre-screens every `.yar` it is about to hand over with a line-level check
  (`^\s*include\s`) and rejects the file with a `RuleError`, the same "reported, never silently
  dropped" contract as a bad Sigma rule. With `-C` precompiled rules, includes do not exist.
- **External variables** (`-d VAR=VALUE`) are never passed; a rule that references an undefined
  external fails to compile, which is the right outcome.
- **Modules** cannot be disabled per invocation in the classic CLI; all compiled-in modules are
  available to rules. This is the main reason the parse happens in a child.
- **Trusted path** (§4.5): root-owned, not group/world-writable, for both the rules and the engine
  binary; checked before every exec, not once at startup.
- The rule pre-screen and the output parser are **fuzzed** (§6) because a hostile rule's job, if it
  cannot run code, is to crash the thing reading it.

### 5.5 Sandbox interplay: the unit currently hides the files worth scanning

This is the least clean part of the design and it must be in the review, not discovered in a VM.
`packaging/systemd/banken.service` (and the module that mirrors it) sets:

- `PrivateTmp=true` — the unit sees its own empty `/tmp` and `/var/tmp`. A `download_ip_to_tmp`
  alert names `/tmp/x`; the scanner would open the unit's private `/tmp/x` and report "missing".
  **Every dropper the baseline rules are written to catch lands in exactly these directories.**
- `ProtectHome=true` — `/home`, `/root`, `/run/user` are inaccessible. Persistence scripts and user
  droppers live there.
- `ProtectSystem=strict` — the rest of the filesystem is read-only, which is fine: reading is all
  the scanner does.
- `ProtectProc=invisible` — `/proc/1/root` (the "escape hatch" to the real `/tmp`) is invisible, so
  there is no clever way round `PrivateTmp`.

So, when `yara.enable` is true, the unit must change: `PrivateTmp=false` and `ProtectHome=read-only`.
Both are weakenings, and the design does not pretend otherwise:

- `PrivateTmp=false` exposes banken to the classic shared-`/tmp` attacks (symlink races on tmp
  files). banken writes nothing to `/tmp` — except the embedded canary rule file (§4.5), which must
  then be written under `/var/lib/banken` (its `StateDirectory`) instead, with `O_EXCL`, so the
  design moves it there unconditionally and the private tmp is not needed at all.
- `ProtectHome=read-only` lets a parser bug in banken (not the child) read user files. The parsers
  are fuzzed precisely so that this is unlikely, and the child does the dangerous parsing; the
  residual is accepted and documented in the module option's description so the operator chooses it.

The quarantine-time scan (§4.2b) needs neither relaxation, which is one more reason it is the
reliable one. An operator who wants YARA but not the relaxed unit gets exactly that: `yara.enable`
with the unit untouched means only quarantine-time and on-demand scans see files, and (a) reports
"missing/skipped" for anything under `/tmp` or `/home`. The module should make that combination
expressible rather than forbidden (§11).

`MemoryDenyWriteExecute=true` is kept: classic `yara` does not JIT. It is the known blocker for
YARA-X (§3.3).

### 5.6 Loops and self-matching

- The YARA alert is dispatched with `Kind: yara`; the scanner's `ShouldScan` returns false for that
  kind, so a YARA alert never triggers a scan. One level of derivation, by construction.
- banken's own jsonl alert files contain rule names and, with YARA, YARA rule names and hashes. A
  community rule that matches its own identifier as a string (it happens) would fire on
  `alerts-YYYY-MM-DD.jsonl` if it were ever scanned; the jsonl `dir` and `/var/lib/banken` are in
  the default exclusions so it is not. The exclusion list is merged with, not replaced by, the
  operator's.
- The audit log is excluded for the same reason and for size.

### 5.7 Resource exhaustion

An attacker who can generate alerts can generate scans. The caps — `maxScansPerRun`, per-run
(device, inode) dedupe, `maxFileBytes`, `timeout`, `maxMatchesPerFile`, bounded child output — put
a hard ceiling on one run's YARA cost of `maxScansPerRun × timeout` wall-clock worst case (25 × 10 s
≈ 4 min at the defaults, which is longer than a 2 min timer interval; see §11 on whether the
default should be lower, or scans should run concurrently with a small worker pool). Scans are
sequential in v1; the first thing to parallelise if it matters is this loop, not the matcher.

## 6. Test strategy (and how it stays optional)

The rule: **`go test ./...` on a machine with no `yara` binary passes, and exercises everything
except the real engine.** The engine is behind an interface; the policy, parsing, gating and alert
mapping are tested with a fake; the real engine is tested in a build/environment-gated test that
skips itself cleanly.

| Layer | Test | Needs `yara`? |
| --- | --- | --- |
| Output parser | `TestParseYaraOutput` golden: `testdata/yara-4.5.4.out` (recorded real CLI output: no match, one match, match with tags, match with namespace, `-l` truncation, warnings on stderr) → expected `[]Match`. One golden per supported engine version. | no |
| Output parser | `FuzzParseYaraOutput`: arbitrary bytes never panic, never produce a `Match` with an invalid identifier | no |
| Rule pre-screen | `TestRuleLintRejectsInclude` table + `FuzzRuleLint` | no |
| File gate | `TestScanPathGate`: in a `t.TempDir()`, a regular file, a directory, a FIFO (`syscall.Mkfifo`), a symlink to a regular file, a file over `maxFileBytes`, a path under an excluded prefix, a missing path → the expected `Skipped` reason, and the engine fake records that it was **not** called for any but the regular file | no |
| Trigger policy | `TestShouldScan`: level threshold, `TargetFilename` vs `Image` precedence, `scanImage` off, per-run dedupe by inode, `maxScansPerRun`, `Kind: yara` never re-scanned | no |
| Alert mapping | `TestAlertFor`: tags → level, default level, `Trigger`, `Field`, `SHA256` present, no content fields; JSON round-trip via the jsonl sink keeps camelCase (`tagliatelle`) | no |
| Engine integration | `TestEngineProcessScansOnFileAlert`: a Sigma rule on `TargetFilename|contains: /tmp/`, an event naming a temp file, the fake engine returning one match → the dispatcher sees the Sigma alert **then** the YARA alert, and a fake that returns an error or panics yields a Sigma alert plus one error and no YARA alert | no |
| Never-die | `TestYaraFailureNeverFailsRun` through `run()` in `main_test.go` style: `yara.enable: true` with `engine: /nonexistent` → exit 0, alerts still written, one stderr line | no |
| **Golden, real engine** | `TestYaraCLIGolden`: `t.Skip` unless `BANKEN_YARA` names a binary (or `-tags yara_integration`). The embedded canary rule against (1) a file containing the canary string → exactly one match named `banken_canary`; (2) `tests/fixtures/*.json` (benign bytes) → no match; (3) a 1-byte timeout against a large synthetic file → `Err` is a timeout, no match, run continues. | **yes** |
| Subcommand | `TestRunYara` with the fake engine (mirrors `TestRunCheck`); the `-selftest` path is covered by the golden test above | no |

Determinism: the canary rule is `rule banken_canary : low { strings: $c = "BANKEN-YARA-CANARY-7f3e…"
condition: $c }` — a fixed ASCII string, no regex, no modules, so the match is identical across
engine versions and the no-match case cannot be flaky. The golden *output* files are the thing that
drifts with engine versions, and they drift visibly (a new version gets a new recorded file, and the
parser must pass all of them).

CI: the default job is unchanged. A second, separate job `yara` installs the distro `yara`
(`apt-get install -y yara` on `ubuntu-latest`) and runs `go test ./internal/yara -run Golden` with
`BANKEN_YARA=/usr/bin/yara`. On hokkaido, the module's VM test (when it lands) enables
`services.banken.yara` with `pkgs.yara` and asserts `banken yara -selftest` passes under the real
unit — which is also the test that catches the §5.5 sandbox problem if the module gets it wrong.
`just test` stays as is; `just test-yara` is the new, opt-in recipe.

## 7. Interface sketches (signatures only)

```go
// internal/yara — the policy layer and the engine seam. No CGO, no new modules.
package yara

type Config struct {
    Enable            bool          `yaml:"enable"`
    Engine            string        `yaml:"engine"`            // absolute path to the yara binary
    Compiled          string        `yaml:"compiled"`          // optional .yarc; wins over the tree
    Rules             []string      `yaml:"rules"`             // extra .yar files/dirs beyond <tree>/yara/
    Timeout           time.Duration `yaml:"timeout"`
    MaxFileBytes      int64         `yaml:"maxFileBytes"`
    MaxScansPerRun    int           `yaml:"maxScansPerRun"`
    MaxMatchesPerFile int           `yaml:"maxMatchesPerFile"`
    MinLevel          string        `yaml:"minLevel"`
    ScanImage         bool          `yaml:"scanImage"`
    DefaultLevel      string        `yaml:"defaultLevel"`
    ExcludePaths      []string      `yaml:"excludePaths"`
}

// Match is one YARA rule hit. Never carries matched bytes or offsets.
type Match struct {
    Rule      string   // identifier
    Namespace string   // "" if the engine reported none
    Tags      []string // identifiers
}

// Result is one ScanPath outcome: scanned (Matches, possibly empty), skipped
// (Skipped non-empty, Err nil), or failed (Err non-nil). Exactly one of the
// three shapes holds.
type Result struct {
    Path    string
    Size    int64
    SHA256  string
    Matches []Match
    Skipped string // "not a regular file", "too large", "excluded", "missing", "cap reached", ...
    Err     error
    Engine  string // engine name+version, for the record
}

// Engine runs a scan of an already-open, already-vetted file against a rule
// set. Implementations: yaraCLI (v1), yaraxCLI (later), a build-tagged
// in-process backend (maybe), fakeEngine (tests).
type Engine interface {
    Name() string
    Version(ctx context.Context) (string, error)
    Scan(ctx context.Context, f *os.File, rules RuleSet, maxMatches int) ([]Match, error)
}

// RuleSet is what the engine is handed: either a precompiled file or the
// screened source files. Built by Load; never built from a string at scan time.
type RuleSet struct {
    Compiled string   // path to .yarc, or ""
    Sources  []string // screened .yar paths
}

// RuleError mirrors sigma.RuleError: a file that failed the pre-screen.
type RuleError struct{ Path string; Err error }

// Load gathers <dir>/yara/**/*.yar{,a} for each dir (plus cfg.Rules, plus the
// embedded canary materialised under stateDir), pre-screens each (no include),
// checks the trusted-path rule, and returns the set plus every problem.
func Load(cfg Config, stateDir string, dirs ...string) (RuleSet, []RuleError)

// NewCLIEngine validates the binary (absolute, root-owned, not writable) and
// returns the classic-yara engine.
func NewCLIEngine(path string) (Engine, error)

// Scanner is the policy layer: what to scan, the file gate, the caps, the hash,
// the alert mapping. It is safe for sequential use within one run.
type Scanner struct { /* cfg, eng, rules, perRun dedupe + counters */ }

func New(cfg Config, eng Engine, rules RuleSet) *Scanner

// ShouldScan applies the trigger policy to a dispatched alert and returns the
// path to scan and which event field supplied it.
func (s *Scanner) ShouldScan(a alert.Alert) (path, field string, ok bool)

// ScanPath is the whole safe pipeline for one path: open (O_NOFOLLOW|...),
// fstat gate, size gate, exclusions, hash, Engine.Scan on the fd under the
// deadline. Never panics past its boundary; never returns a partial scan as
// "clean".
func (s *Scanner) ScanPath(ctx context.Context, path string) Result

// AlertsFor turns a Result with matches into one alert per match, correlated to
// the trigger. A Result with no matches, a Skipped reason, or an Err yields nil.
func (s *Scanner) AlertsFor(trigger alert.Alert, field string, r Result) []alert.Alert

// Summary is the one-line per-run tally for stderr.
func (s *Scanner) Summary() string

// parseOutput parses classic `yara -g [-e]` stdout for a scan of exactly one
// known target string. Exported for the golden tests and the fuzz target.
func ParseCLIOutput(stdout []byte, target string) ([]Match, error)

// LintSource rejects a rule file that uses include (and any future forbidden
// construct) before it reaches the compiler.
func LintSource(src []byte) error
```

```go
// internal/alert — additions only.
const KindYara = "yara"

type Alert struct {
    // ... existing fields unchanged ...
    File    string `json:"file,omitempty"`    // the path scanned (KindYara)
    SHA256  string `json:"sha256,omitempty"`  // hash of the bytes scanned (KindYara)
    Trigger string `json:"trigger,omitempty"` // "kind/rule" of the alert that caused the scan
}
```

```go
// internal/engine — one optional collaborator; New's signature is unchanged.
func (e *Engine) SetYara(s *yara.Scanner)   // nil = off (the default)
// Process: after dispatching each alert, if s != nil && ShouldScan -> ScanPath ->
// AlertsFor -> Dispatch, all inside the existing per-event recover guard; errors
// go to Result.Errors; Result gains YaraScans / YaraMatches counters for the log line.
```

```go
// internal/config — one new section, defaults in Default().
type Config struct {
    // ... existing ...
    Yara yara.Config `yaml:"yara"`
}
```

```go
// main.go — wiring and the subcommand.
// run(): if cfg.Yara.Enable { eng, err := yara.NewCLIEngine(cfg.Yara.Engine); on err log once, continue without }
//        rules, problems := yara.Load(cfg.Yara, stateDir, cfg.Rules...); log problems like Sigma's
//        engine.SetYara(yara.New(cfg.Yara, eng, rules))
// run(): case "yara": return runYara(args[1:], stdout, stderr)
func runYara(args []string, stdout, stderr io.Writer) error
```

Nothing above changes `event.Event`, the parsers, `sigma`, `ioc`, the cursor, or any sink. The
`Responder` interface is untouched; the quarantine action (future) calls `Scanner.ScanPath` directly.

## 8. Maintainability: the moving parts, counted

New: one package (`internal/yara`, roughly five files: config/load, gate+scan, cli engine, output
parse, alerts), one subcommand file (`yara.go` beside `check.go`), one embedded rule file, one test
data dir of recorded CLI outputs, one justfile recipe, one CI job, one module option group. Changed:
three optional fields and one constant in `alert`, one setter and one loop step in `engine`, one
struct field in `config`, ~15 lines in `main.go`.

Reused rather than re-invented: the rule tree and `existingDirs` convention; the `RuleError`
"reported, never dropped" contract; the `Level` vocabulary and `severityFor`; the `Field` "which
field fired" idea from IOC; the `Dispatcher` as the one exit; the engine's recover guard; the
`check`-style subcommand; the `testdata/*.golden` recorded-output pattern from the parsers; the
fixture files as benign no-match inputs; the `tagliatelle` camelCase JSON convention.

The interface surface we do *not* control is one: the classic `yara` CLI's one-line text output,
driven with a fixed flag set and pinned by goldens. If a future version changes it, the golden for
that version fails to parse, the parser grows a case, and nothing else moves. If YARA-X's
structured output turns out to be usable under the unit, `yaraxCLI` replaces most of the parser
with `json.Unmarshal` behind the same `Engine`.

## 9. Risks

| Risk | Likelihood | Impact | Mitigation / where it is decided |
| --- | --- | --- | --- |
| The file is gone or changed by scan time (one-shot timer) | high, by design | a missed confirmation, never a missed Sigma alert | documented as best-effort; quarantine-time scan is the reliable one; `--watch` narrows it |
| Sandbox hides `/tmp`, `/home` from the scan | certain unless the unit changes | silent "missing" on the most valuable files | §5.5: module relaxes `PrivateTmp`/`ProtectHome` with YARA on; VM test asserts a `/tmp` scan works |
| CLI output format drift across yara versions | low-medium | parse error → scan "failed", logged, never a crash | goldens per version; fixed flag set; never `-s`/`-m` |
| libyara bug on a hostile file or rule | medium over time | child crash; with CGO it would be root memory corruption | the process boundary is the design; rules are pre-screened; trusted path |
| YARA-X's JIT vs `MemoryDenyWriteExecute` | high for `yr` | `yr` unusable under the unit | classic `yara` is v1; verify `yr` on hokkaido before offering it |
| Community rule sets are noisy at `high` | medium | journal/webhook noise | YARA-Forge `core` as the recommended feed; `defaultLevel` is a knob; `maxMatchesPerFile` |
| Per-run cost ceiling exceeds the timer interval | low at defaults, real under attack | a long run; timer coalesces, nothing lost | caps; lower default `maxScansPerRun` or a small worker pool (§11) |
| Precompiled `.yarc` / engine version mismatch on non-Nix hosts | medium | `yara -C` refuses to load → scan failed, logged | the tree path is the non-Nix default; Nix pairs them by construction |
| `include` or a crafted rule in an operator tree | low today, higher with remote sync | file read by the child; compile crash | lint rejects `include`; `.yarc` has no includes; trusted-path check |
| Scanning an exec'd `Image` means scanning system binaries often | medium | wasted scans, cap pressure | per-run inode dedupe; `scanImage` knob; exclusions can add `/nix/store` or `/usr` if an operator wants |
| The embedded canary rule is materialised on disk each run | certain | one small state-dir write per run | `O_EXCL` under `StateDirectory`, overwritten atomically, skipped when `compiled` is set |

## 10. Non-goals for v1

- Memory / process scanning (`--pid`). Needs `CAP_SYS_PTRACE` and a different safety story.
- Filesystem crawling / scheduled full scans. That is a different product (and the option-D
  sidecar is the right shape for it if ever wanted: a timer, `yara -r`, hits as generic JSONL).
- Shipping third-party signature sets inside the binary.
- Parsing YARA `meta:` (score, description, reference). Severity is by tag; everything else lands
  at `defaultLevel` until the output parser has earned trust.
- In-process CGO backend. Designed-for (the `Engine` seam), not built.
- Hash IOCs. The scanner computes SHA-256 anyway, and `ioc` has no hash kind yet; wiring the hash
  into the IOC set is a natural follow-up (the README promises hash IOCs "with the eBPF sources" —
  this would deliver them earlier, for files alerts already named), but it is its own small design.

## 11. Open questions for Conor

1. **Is the sandbox relaxation acceptable?** YARA-on-alert is near-useless without
   `PrivateTmp=false` + `ProtectHome=read-only` (§5.5). Options: (a) the module flips both when
   `yara.enable`, documented loudly; (b) a separate `banken-yara.service` with the looser sandbox
   that only ever runs scans (more parts, but the main unit stays as tight as today; the scan
   request would have to cross units — a spool dir — which is close to the sidecar); (c) accept
   that on-alert scanning only sees non-tmp, non-home files and rely on quarantine-time scanning.
   The design recommends (a) with (c) expressible.
2. **Default `scanImage: true`?** It makes scans of `/usr/bin/curl` happen on every
   `download_ip_to_tmp` hit (deduped per run, cheap, but pointless). Alternative: scan `Image` only
   when it is under a scratch/home prefix. Which default?
3. **Default `defaultLevel: high` vs `medium`?** `high` goes to the journal and the webhook; a
   noisy community set would be noisy there. `medium` keeps it to jsonl/webhook. The design says
   `high` with YARA-Forge `core`; is that the right bet for "SentinelOne for the masses"?
4. **Caps.** `maxScansPerRun: 25` × `timeout: 10s` can exceed a 2 min interval under attack. Lower
   defaults (10 × 5 s), or a 2–4 worker pool for the scan loop in v1?
5. **`banken yara` exit status.** Mirror `check` (always 0) or `-exit-code` for scripting (1 on
   match, 2 on error)? The design leans `-exit-code` opt-in.
6. **Child credentials.** Drop the child to an unprivileged uid when the target is world-readable
   (fast path), root otherwise? It is a real hardening for the common case but two code paths. v1
   proposes root-in-the-sandbox only.
7. **Rule tree layout.** `rules/yara/` as proposed, or `rules/malware/<family>/*.yar` beside the
   family's Sigma rules (nice locality; the loaders already ignore `.yar`, so it is purely a
   convention question)? The design picks `yara/` so `yarac` has one directory to compile.
8. **YARA-X.** Worth a one-hour spike on hokkaido now (`yr scan` under the unit with
   `MemoryDenyWriteExecute`) to know whether the structured-output engine is on the table, before
   the parser for the classic text format is written?
9. **Should a YARA hit be able to escalate the trigger?** E.g. a `medium` Sigma hit whose file
   matches a `critical` YARA rule: today the two alerts are independent; a later correlation step
   could re-emit the Sigma alert at the higher level. Out of scope unless you want it in v1.
10. **Where does the `x/sys` line sit?** `openat2(RESOLVE_NO_SYMLINKS)` would close the last
    symlink residual (§5.1) at the cost of a second Go module. Keep the "one dependency" line even
    for `golang.org/x/*`, or is `x/sys` the kind of module that line was not about?

## 12. Claims to verify at implementation time

Written from memory of the classic YARA 4.x CLI; each is cheap to confirm against `yara --help` on
the installed version before the parser is written, and the goldens will catch any that are wrong:

- `-a`/`--timeout=SECONDS`, `-l`/`--max-rules=NUMBER`, `-N`/`--no-follow-symlinks`, `-g`/`--print-tags`,
  `-e`/`--print-namespace`, `-w`/`--no-warnings`, `-C`/`--compiled-rules` exist with these meanings.
- Default output is `<rule> <target>` per match, one line; with `-g`, `<rule> [tag,tag] <target>`;
  with `-e`, `<namespace>:<rule> …`. Target is printed verbatim as given (so `/proc/self/fd/3` is
  the known suffix the parser strips).
- `yara` opens the target by path, so `/proc/self/fd/3` with the fd inherited via `ExtraFiles`
  scans the already-open inode (standard magic-link behaviour; confirm no `O_NOFOLLOW` inside yara
  defeats it — `-N` concerns recursive directory walks, not the argument itself).
- The classic CLI has no flag to disable `include` (hence the lint) and no stdin target mode (hence
  the fd trick rather than a pipe).
- `yarac` output is accepted by `yara -C` only for the same libyara major.minor.
- `yr` (YARA-X) uses `wasmtime` with a JIT by default and therefore needs writable-then-executable
  memory; confirm against the unit's `MemoryDenyWriteExecute` on hokkaido.
