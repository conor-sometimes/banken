# Design: runtime-refreshable rules

Status: **proposal, not implemented.** Nothing in this document exists in the tree yet. It is written
to be built from. Where it names code, it names what is there today (file:line) and what would change.

## The one scenario this is built around

> A new threat is described on a security blog. We need to quickly write a rule, push it, and have it
> applied across the entire fleet within minutes, with no binary redeploy.

Everything below serves that loop: a detection engineer writes a rule in a git repo, every host pulls
the repo to a path on disk, and banken recompiles all of its rules in against the already-running
daemon. A new threat costs a rule change, never a binary rebuild and redeploy. The loop is closed at
the end of this document (see "The incident runbook").

## 1. Current state (what the code does today)

banken already compiles rules at runtime, discovers them recursively, loads multiple directories, and
lets on-disk rules override the embedded baseline. The gap is narrow and specific: the rule set is
built once at process start and never rebuilt, and on NixOS the on-disk rule tree is itself baked into
the Nix store, so a rule change still means a rebuild there. Both are addressed below.

What exists:

- **Compile is already a runtime step.** `sigma.Compile([]byte)` parses a rule's YAML and builds its
  matchers (selections, conditions, regexps, CIDRs) in memory (`internal/sigma/load.go:153`). "Compiled
  into the binary" via `//go:embed rules` (`embed.go:11`) embeds the baseline rule *bytes*, not compiled
  code; those bytes are still parsed and compiled at process start by `sigma.LoadFS` (`internal/sigma/load.go:78`).
  So "rules are not compiled at build time" is already true of the engine -- what is fixed at build
  time is only which *baseline* ships in the binary.
- **Recursive discovery already exists.** `sigma.LoadTree(dirs...)` walks each dir with `filepath.WalkDir`,
  loads every `*.yml` / `*.yaml` under any subdirectory, skips the `ioc/` subtree, dedups by path, and
  returns every rule that compiled plus a `RuleError` per file that did not -- one bad rule never stops
  the good ones, and a bad rule is reported, never silently dropped (`internal/sigma/load.go:27-71`).
- **Multiple dirs and override are already modelled.** `config.Config.Rules []string`
  (`internal/config/config.go:19`) is a list of rule-tree dirs. `loadRules` loads the embedded baseline
  first, then the on-disk dirs, with on-disk winning on a filename clash, keyed by rule name
  (`main.go:390-407`). The default dir is `/etc/banken/rules` (`internal/config/config.go:105`).
- **A preflight-ish subcommand exists.** `banken check` compiles the baseline plus `-rules` dirs and
  reports which rules fire on one described event (`check.go:24-83`). It validates rules as a side
  effect but is built for testing an event, not for validating a whole tree with a non-zero exit.
- **The engine builds its matcher once.** `engine.New(rules, iocs, disp)` constructs a
  `sigma.Matcher` and stores it (`internal/engine/engine.go:30-32`); the matcher is immutable after
  `NewMatcher` (`internal/sigma/matcher.go:58-129`). The daemon (`runDaemon`, `main.go:280`) builds the
  engine once in `run` (`main.go:193`) and never rebuilds it. There is no reload path.
- **The daemon is signal-driven, SIGINT/SIGTERM only.** `watch` and `follow` use
  `signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)` to stop cleanly (`main.go:274`, `main.go:371`).
  There is no SIGHUP handler, no control socket, and no HTTP server anywhere in the Go tree (grep for
  `net.Listen` / `ListenAndServe` / `/metrics` returns nothing in non-test code). A Prometheus endpoint
  is only a proposal (`docs/design/standards.md:16`).
- **ReDoS is already closed.** Rule regexps compile with the standard library `regexp` (RE2), which is
  linear-time and cannot backtrack-explode; `internal/sigma/redos_test.go:22-52` locks this in with
  textbook evil patterns against 40 KB inputs under a 2s deadline. A hostile rule's regex cannot wedge
  the detector. `Compile` is also fuzzed (`internal/sigma/fuzz_test.go`), and matching runs under a
  per-event panic guard (`engine.safeMatch`, `internal/engine/engine.go:157-165`), so one crafted event
  degrades to a logged error, never a crash.
- **The sandbox is strict.** The NixOS unit runs banken as root (for the audit log) with every other
  power removed: `ProtectSystem = "strict"` (the whole filesystem read-only except the writable paths
  named), `ReadWritePaths` limited to the jsonl dir, `StateDirectory = "banken"` (`/var/lib/banken`,
  mode 0700) the only writable state, `CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH" ]`,
  `NoNewPrivileges`, `SystemCallFilter = [ "@system-service" ]`, and crucially
  `PrivateNetwork = !(webhook || otlp)` -- with no egress sink, banken has no network at all
  (`module.nix:375-422`). This constrains the design: a refreshable rules dir must be readable by the
  daemon (reading is always allowed under `ProtectSystem=strict`), and the thing that does the
  git pull (which needs network and git) must **not** be the banken daemon.
- **NixOS bakes rules into the store.** `settings.rules = [ "/etc/banken/rules" ] ++ map (p: "${p}") cfg.extraRules`
  interpolates each `extraRules` path, copying the tree into the Nix store (`module.nix:31`), and the
  config is written to `/etc/banken/banken.yml` (`module.nix:340`). So today, changing a rule on NixOS
  means editing the store input and rebuilding -- exactly the coupling this feature removes.
- **IOC lists are a parallel intake.** `ioc.LoadTree` / `Set.ReadFS` load the `ioc/` subtree that
  `sigma.LoadTree` deliberately skips (`main.go:474-483`, `internal/ioc/ioc.go:73`). A threat-intel
  worker is adding STIX/TAXII/MISP IOC ingestion in parallel (`docs/design/standards.md:25`); `rules/ioc`
  does not exist in the tree yet. This design refreshes the Sigma rule set and the IOC set together
  (they load from the same dirs) and does not design over the IOC intake -- it reuses whatever
  `ioc.LoadTree` grows into.

Summary: the compiler, recursive discovery, multi-dir config, override semantics, and ReDoS/panic
safety are already here. What is missing is (a) a way to rebuild the rule set against a running daemon,
(b) a validate-all-then-swap that can never leave the daemon with no rules, (c) a dedicated on-disk
dir that is not baked into the store, and (d) the fleet plumbing (puller + reload) on both NixOS and
stock distros.

## 2. Config schema

Keep it declarative and boring. Two ideas, no magic:

- `rules:` (exists) stays the list of rule-tree dirs, loaded on top of the embedded baseline, recursive,
  `*.yml` / `*.yaml`, `ioc/` carrying IOC lists. Unchanged.
- Add `refreshDirs:` -- a list of dirs that are **refreshable at runtime** and, on NixOS, **not copied
  into the Nix store**. This is the fleet's rules-repo checkout on disk. It is the only new concept.

```yaml
# /etc/banken/banken.yml
rules:
  - /etc/banken/rules          # store-baked baseline extensions (NixOS extraRules), as today
refreshDirs:
  - /var/lib/banken-rules       # a git checkout, pulled by a separate unit, refreshed at runtime
```

Discovery, extensions, and skip rules are exactly `LoadTree`'s existing contract (recursive, `.yml` /
`.yaml`, skip `ioc/`); `refreshDirs` are walked the same way. No new file format, no per-file front
matter, no enable flag inside a rule beyond the `optional:` field rules already have
(`internal/sigma/load.go:132`).

Precedence (make it explicit, because override is how a rule gets silently weakened -- see section 8):

1. embedded baseline (lowest)
2. `rules:` dirs, in listed order
3. `refreshDirs:` dirs, in listed order (highest)

Later wins on a filename clash, as `loadRules` already does by name (`main.go:398-400`). The one change
from today: every override of a lower-precedence rule is **logged at each refresh** (name, winning path,
overridden path), because an override can mask a baseline detection. Enable/disable stays the existing
`optional:` / `optionalRules` / `observeRules` model (`internal/config/config.go:21-34`); nothing new.

Per-source grouping is just directory layout: one subdir per upstream (a tactic tree, a vendor feed),
which `WalkDir` already flattens. The refresh status (section 9) reports counts per top-level dir so an
operator can see "47 from the fleet repo, 12 from local" without a config key for it.

## 3. Runtime compile pipeline

"Compile" in banken is concrete and already runtime: `sigma.Compile(bytes)` -> parse YAML -> build
`selection` / `condition` / compiled `*regexp.Regexp` / `netip.Prefix` matchers (`internal/sigma/load.go:153-202`);
then `sigma.NewMatcher(rules)` folds every string literal across every rule into one Aho-Corasick
automaton and an inverted literal->rule index, so per-event cost is independent of rule count
(`internal/sigma/matcher.go:9-129`). A refresh re-runs exactly this pipeline over the current dirs and
builds a fresh `*Matcher`.

Performance with thousands of rules: the per-event path is already prefiltered and rule-count-independent
by construction (the Aho-Corasick prefilter plus the per-rule upper-bound gate). The cost that grows
with the rule count is the *build* -- parsing N files and constructing one automaton over all literals --
which happens off the hot path during a refresh, not per event. Rebuild is O(total rule bytes); for a
few thousand rules it is milliseconds to low tens of milliseconds, done once per refresh. Section 6
bounds it so a pathological dir cannot turn a refresh into a stall.

## 4. Decoupling from the binary

The embedded baseline **stays**. It is the zero-fiddle floor: a fresh install detects with nothing on
disk (`embed.go:5-9`), and the baseline is the thing that guarantees the daemon can never end up with
zero rules (section 6). Runtime dirs overlay it, exactly as `loadRules` already composes them
(`main.go:390-407`).

What changes:

- The rule set moves from a value captured once at `engine.New` time to a value the engine can swap
  (section 5). No change to the matcher's internals.
- A new `refreshDirs` path is read at runtime and, on NixOS, is a plain on-disk path rather than a
  store input (section 7). `rules:` keeps its store-baked behaviour for operators who want their
  extensions pinned and reproducible.

Migration is additive and backward compatible: an operator who sets nothing keeps today's behaviour
(baseline + `/etc/banken/rules`, no refresh). An operator who wants the fleet loop adds one
`refreshDirs` entry and the puller unit. No existing config breaks.

## 5. The refresh mechanism UX

**Recommendation: SIGHUP to the daemon is the primary trigger, wired to `systemctl reload banken` via
`ExecReload`, with `banken check <dir>` as the preflight and a systemd path/timer unit as the optional
auto mode.** Reasons, in order:

- The daemon is already signal-driven (`signal.NotifyContext`, `main.go:274`). SIGHUP is the smallest
  possible addition: one more signal in the `NotifyContext` set and a reload branch in `runDaemon`. No
  new socket, no new file descriptor, no new syscall -- it stays inside `SystemCallFilter=@system-service`
  and adds zero attack surface to a root daemon. SIGHUP-means-reload is the oldest convention in the
  book; operators and `systemctl reload` already expect it.
- A control socket (a unix socket in `/run`) was considered and rejected for v1. It would be a new
  listener on a root daemon, a new path to permission, and a new syscall family
  (`RestrictAddressFamilies` currently allows only `AF_UNIX` already, so it is technically possible) --
  real surface for no capability SIGHUP does not already give. Revisit only if the daemon later needs
  request/response control (e.g. "reload and tell me the per-file errors on this fd"); until then the
  errors go to the journal and the status file (section 9).

Triggers:

- **Primary:** `systemctl reload banken` -> `ExecReload = kill -HUP $MAINPID` (NixOS and any systemd
  distro). Equivalently `kill -HUP` for non-systemd.
- **CLI sugar:** `banken reload` finds the running daemon (its `MAINPID` via systemd, or a pidfile in
  `StateDirectory`) and sends SIGHUP, so an operator never has to know the pid. Thin wrapper; the
  mechanism is still SIGHUP.
- **Preflight:** `banken check <dir>` (section 6) validates a whole tree and exits non-zero on any bad
  rule, so a refresh is never triggered on a tree that will not compile.
- **Optional auto modes** (off by default, operator opts in):
  - a `systemd.path` unit watching the `refreshDirs` checkout (`PathChanged=`), firing `banken reload`
    on write -- the detection engineer pushes, the puller pulls, the path unit reloads, hands-free;
  - a `systemd.timer` that runs `git pull && banken check && systemctl reload banken` on an interval
    (the simplest fleet mode, and the one that works identically on stock distros via cron).

The CLI talks to the daemon only by signal; it does not share memory or a socket. This keeps `banken`
a single static binary with no IPC layer.

## 6. Atomicity and safety (the part that must not be wrong)

The invariant: **a refresh never crashes the daemon, never drops the currently-good rule set, and
never leaves it with zero rules.** A single bad rule is a logged per-file error, nothing more.

Mechanism -- validate-all-then-swap:

1. On SIGHUP, build a *new* candidate set off to the side: `loadRules(cfg)` + `loadIOCs(cfg)` +
   `sigma.NewMatcher(newRules)`. This mutates nothing live.
2. `sigma.LoadTree` already returns `([]*Rule, []RuleError)` -- every rule that compiled plus a problem
   per file that did not (`internal/sigma/load.go:33`). Collect the problems; they are per-rule and
   non-fatal by design.
3. Gate the swap. Refuse to swap (keep the old set, log loudly) only on a *whole-set* failure:
   - the candidate has zero rules (would blind the host), or
   - the resource guard trips (below).
   A swap with some per-file errors is allowed -- those rules are simply absent, reported, and the
   good rules load, exactly as `loadRules` does at startup today.
4. Swap atomically. Store the matcher behind an `atomic.Pointer[sigma.Matcher]` (and the IOC set behind
   its own) inside the engine; `engine.Match` loads the pointer per call. The follower and the periodic
   scanner (`runDaemon`, `main.go:294-336`) run in separate goroutines and both call through the engine,
   so the pointer swap is the one safe publication point. In-flight events finish against whichever set
   they loaded; the next event sees the new set. No lock on the hot path.
5. Write the refresh status (section 9) and log a one-line summary: loaded N, failed M, swapped / kept.

Preflight / dry-run: extend `banken check` with a directory mode, `banken check <dir>` (today it only
takes `-rules` plus an event, `check.go:24`). It compiles the whole tree, prints per-file errors and a
total, and exits 0 for a clean tree, non-zero (2) if any rule failed to compile or the tree is empty.
This is what a detection engineer runs before committing, and what the fleet timer runs before reload,
so a broken rule is caught on the engineer's laptop, not on 500 hosts.

Behaviour on partial failure: the good rules load, the bad ones are named in the journal and the status
file, the daemon keeps running. On a *whole-set* failure (empty, or guard tripped) the daemon keeps the
old set and logs an error at `levelErr` -- the operator sees it under `journalctl -u banken -p err`.

Resource guard (a rule is close to code, so bound it):

- ReDoS is already closed by RE2 (`internal/sigma/redos_test.go`); no per-rule regex timeout is needed
  on the match path.
- Bound the *build*, not the match: a cap on rule count and on total pattern bytes across a refresh
  (configurable, generous defaults -- e.g. 50k rules, a few MB of literals), and a compile deadline on
  the whole refresh. A dir that blows past the cap is a whole-set failure: old set kept, error logged.
  This stops a hostile or accidental "ten million generated rules" push from exhausting memory or
  stalling the daemon mid-swap.
- The build runs in its own goroutine with the deadline; the live set serves events throughout.

## 7. The fleet workflow

The rules-repo model, end to end:

- **Repo layout** mirrors the existing tree (`docs/writing-rules.md`): tactic subdirs
  (`credential-access/`, `persistence/`, ...), `malware/<family>/`, `ioc/*.txt` for bulk indicators.
  `WalkDir` flattens it, so the repo can be organised for humans. One repo per fleet, or one per team
  merged into a host's `refreshDirs` list.
- **Host checkout path convention:** `/var/lib/banken-rules` (a sibling of `StateDirectory`), owned by
  a dedicated puller identity, world-readable, listed in `refreshDirs`. The banken daemon only *reads*
  it (allowed under `ProtectSystem=strict` with no extra `ReadWritePaths`), so the daemon never needs
  git or network.
- **Who pulls:** a separate unit, `banken-rules-pull.service`, run as a `DynamicUser` (or a dedicated
  `banken-rules` user), that is the *only* thing with git and network. It `git pull`s into
  `/var/lib/banken-rules`, runs `banken check /var/lib/banken-rules` (preflight), and on success runs
  `systemctl reload banken`. On preflight failure it leaves the previous checkout in place and exits
  non-zero (the timer records the failure; the daemon keeps its good set regardless). This keeps the
  network-touching, repo-trusting half strictly outside the detection daemon's sandbox.
- **How refresh is invoked fleet-wide:** a `banken-rules-pull.timer` (NixOS) or a cron/systemd timer
  (stock distros) runs the pull+preflight+reload on an interval (e.g. every 1-5 minutes). A faster path
  for "right now" is the same unit triggered by config management (Ansible/Salt/`clush`) across the
  fleet. The optional `systemd.path` watch (section 5) covers hands-free reload once the checkout lands.
- **NixOS (`module.nix`):** add `services.banken.refresh = { enable; repo; dir; interval; verify; }`.
  When enabled, the module defines `banken-rules-pull.{service,timer}`, adds `dir` to the daemon's
  `refreshDirs`, and sets `ExecReload` on `banken.service`. The daemon's own sandbox is unchanged except
  that `dir` becomes a readable path (no new `ReadWritePaths`); the puller unit carries the network and
  git, not banken. `extraRules` (store-baked) stays for operators who want pinned, reproducible rules;
  `refresh` is the opt-in runtime path. This is the one place the store-coupling is broken, deliberately
  and only for the dir the operator marks refreshable.
- **Stock distros (the distro matrix):** the package ships the same two units (or a cron entry) and a
  `banken check` preflight, pointed at `/var/lib/banken-rules` by a drop-in. The mechanism (git pull ->
  check -> `systemctl reload banken`) is identical; only the packaging differs. A host with no systemd
  uses cron + `kill -HUP`.

## 8. Trust, provenance, and audit

A rule is powerful: it can add detections, and because an on-disk rule **overrides a baseline rule by
filename** (`main.go:398-400`), whoever can write the rules dir can also *weaken or mask* a baseline
detection by shadowing it with a never-matching rule. That, not ReDoS (already closed), is the sharp
edge. Threat model:

- **Who may write the dir / push the repo.** The host checkout is root/puller-owned and world-readable
  but not world-writable; only the puller unit writes it, only from the configured repo. Push access to
  the repo is the real trust boundary -- treat the rules repo's write access as equivalent to "can
  blind detections on the whole fleet," and protect it like production code (branch protection,
  required review, no force-push).
- **Integrity of what is pulled.** Recommend verified git: the puller checks the signature on the
  pulled `HEAD` (signed commits / signed tags, `git verify-commit` / allowed-signers) before accepting
  a refresh, with `verify = true` as the fleet default. A failed verification leaves the previous
  checkout and refuses the reload. A checksum/manifest of the tree is a lighter alternative where git
  signing is not available. The source repo URL is pinned in config, not discovered.
- **Sandbox implications.** The split is the point: banken stays network-free and git-free inside its
  strict sandbox and only reads the dir; the puller is a separate, unprivileged identity that carries
  the network and the repo trust. Compromising the puller cannot touch the audit log or the cursor;
  compromising banken cannot reach the network. Neither half alone is the whole attack.
- **Override audit + baseline protection.** At each refresh, log every rule that overrides a
  lower-precedence rule (name, winning path, overridden path), so a shadowing attack is visible in the
  journal and the status file rather than silent. Offer an optional `protectBaseline` toggle that
  *forbids* a disk rule from overriding an embedded baseline rule (it is loaded under a new name or
  rejected), for operators who want the baseline immutable.
- **Audit log + provenance record.** On each refresh, record what loaded: counts, per-file errors, the
  source repo and resolved commit SHA, and the timestamp. Surface it two ways: a status file written
  atomically to `StateDirectory` (section 9) and, once the Prometheus endpoint lands
  (`docs/design/standards.md:16`), a `banken_rules_*` metric family including a `commit` label. This is
  how "which rule version is this host running" gets a real answer.
- **Rollback.** Because the checkout is a git repo, rollback is `git reset --hard <good-sha> &&
  systemctl reload banken`, fleet-wide via the same push path (revert the bad commit; every host pulls
  the revert). The daemon's keep-old-set-on-failure behaviour (section 6) is the automatic first line;
  the git revert is the deliberate one.

## 9. Observability

An operator must be able to answer "did the new rule actually go live on this host?" without guessing.

- **Refresh status file:** written atomically (temp + rename) to `/var/lib/banken/refresh-status.json`
  on every refresh (and at startup): timestamp, outcome (`swapped` / `kept-old` / `startup`), rules
  loaded, rules failed (with per-file path + error), IOC count, source repo + commit SHA per dir, and
  the list of baseline overrides. `StateDirectory` is already the one writable path (`module.nix:385`),
  so no sandbox change. `banken status` prints it.
- **Metrics** (tie into the proposed Prometheus endpoint, `docs/design/standards.md:16`):
  `banken_rules_loaded`, `banken_rules_failed`, `banken_last_refresh_timestamp_seconds`,
  `banken_rules_by_source{dir=...}`, and a `banken_rules_info{commit=...}` gauge carrying the loaded
  commit. The same numbers as the status file, scrapeable fleet-wide, so a dashboard shows every host's
  rule version and last-refresh age at a glance.
- **Confirming a specific rule is live, two ways:** (1) read the status file / metric and confirm the
  commit SHA matches the pushed one and the rule is not in the failed list; (2) run the rule's trigger
  through `banken check -json '<event>'` on the host, which compiles the *same on-disk tree the daemon
  loaded* and shows the rule firing. The second is the ground-truth check used in the runbook.
- **Journal line per refresh:** one `levelInfo` summary (`loaded N, failed M, swapped`) and one
  `levelErr` line per failed file, matching how startup already logs rule errors (`main.go:159-161`).

## 10. The incident runbook

The loop, command by command. A new threat is on a blog; a credential-dumping tool writes to
`/dev/shm/.cache` and reads `/etc/shadow`.

On the detection engineer's laptop (clone of the fleet rules repo):

```sh
# 1. Write the rule (standard Sigma, banken's subset; see docs/writing-rules.md).
cat > credential-access/shadow_read_from_shm.yml <<'YAML'
title: Shadow read by a binary staged in shared memory
level: high
tags: [attack.credential-access, attack.t1003.008]
detection:
  stage:
    Image|startswith: /dev/shm/
  shadow:
    CommandLine|contains: /etc/shadow
  condition: stage and shadow
YAML

# 2. Preflight: compile the whole tree, non-zero exit on any bad rule.
banken check .
#   -> "N rules compiled, 0 errors"  (exit 0)

# 3. Prove the rule fires on the threat, and does not on a benign event.
banken check -image /dev/shm/.cache 'cat /etc/shadow'
#   -> "[high] shadow_read_from_shm  Shadow read by a binary staged in shared memory"
banken check 'cat /etc/passwd'
#   -> "no rules matched"

# 4. Commit (signed) and push.
git add credential-access/shadow_read_from_shm.yml
git commit -S -m "cred-access: detect /etc/shadow read by a /dev/shm staged binary"
git push
```

On every host (driven by the fleet timer, or run now via config management):

```sh
# 5. Pull the repo into the host's refreshable checkout (the puller unit does this;
#    network + git live here, outside banken's sandbox).
git -C /var/lib/banken-rules pull --ff-only
git -C /var/lib/banken-rules verify-commit HEAD      # provenance gate (verify=true)

# 6. Preflight on the host, then refresh the running daemon (no redeploy, no restart).
banken check /var/lib/banken-rules && systemctl reload banken
#    equivalently: banken reload   (sends SIGHUP to the running daemon)

# 7. Confirm the rule is live on THIS host.
banken status
#   -> last refresh: <ts>  outcome: swapped  loaded: N  failed: 0
#      source: git@fleet/banken-rules  commit: <sha matching the push>
banken check -image /dev/shm/.cache 'cat /etc/shadow'
#   -> the rule fires: compiled from the same on-disk tree the daemon just loaded
```

Fleet-wide, step 5-6 is one timer tick (or one `clush -g prod 'banken-rules-pull'`); the whole fleet is
detecting the new threat within one interval, with no binary redeploy. Rollback if the rule misfires:
`git revert <sha> && git push`, and the same loop carries the revert to every host; the daemon's
keep-old-set-on-failure already protected any host whose preflight caught a breakage.

The user-facing twin of this runbook, written for an operator rather than a builder, is
`docs/scenarios/new-threat.md` ("New threat detected").

## 11. Open questions, risks, non-goals

Open questions:

- **`banken reload` pid discovery.** Via systemd `MAINPID` is clean on systemd hosts; a pidfile in
  `StateDirectory` covers non-systemd. Decide whether the CLI writes/reads a pidfile or shells to
  `systemctl` -- a pidfile keeps the binary self-contained; `systemctl` is simpler where it exists.
- **Reload on the one-shot (timer) model.** With no live sensor, banken runs as a `oneshot` on a timer
  (`module.nix:381`), not a daemon -- there is nothing running to SIGHUP. In that mode a "refresh" is
  just the next scan loading the new dir; the puller only needs to land the checkout, no reload. The
  reload path matters only for the long-running daemon (sensor on). Document both; do not build a
  pretend reload for the one-shot.
- **IOC refresh coupling.** The IOC set refreshes with the Sigma set (same dirs). Confirm with the
  threat-intel worker that the STIX/TAXII/MISP intake they are building loads from the same `refreshDirs`
  path, so one refresh covers both; do not design a second mechanism.
- **Preflight parity.** `banken check <dir>` must compile rules with the *same* code path the daemon
  uses, or a rule can pass preflight and fail the daemon (or vice versa). It already shares
  `sigma.Compile`; keep it that way and add a test that asserts they agree.

Risks:

- **Shadowing a baseline rule to blind a detection** is the sharpest risk (section 8). Mitigations:
  override audit logging, optional `protectBaseline`, and treating repo write access as production
  access. This is the one to get right.
- **A compromised puller pushing a malicious tree.** Bounded by the puller/daemon split (no detection
  or network reach) and the provenance gate (signed commits). Residual: a valid-but-malicious signed
  commit from an insider -- out of band, handled by repo review, not by banken.
- **Refresh storms.** A path-watch plus a fast-pushing engineer could trigger many rebuilds. Debounce
  the reload (coalesce within a few seconds) and/or rely on the timer interval as the natural rate
  limit.

Non-goals for v1:

- No control socket / request-response IPC (SIGHUP only).
- No hot-reload of config *other than rules* (sources, sinks still need a restart).
- No in-daemon git client or network (the puller is separate, always).
- No per-rule hot enable/disable over the wire (that is the `optional:` model plus a push).
- No rule signing *inside* banken beyond verifying the git provenance of the checkout (rule-level
  signatures, if ever, are a later, separate design).
