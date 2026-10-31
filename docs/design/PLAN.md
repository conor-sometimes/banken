# Build plan: response-actions + OCSF + YARA (synthesized)

Three Fable design specs landed overnight — [response-actions](response-actions.md),
[ocsf-output](ocsf-output.md), [yara-integration](yara-integration.md). This is the map that
reconciles them into one ordered build. Read this first; the three specs hold the detail.

The headline: **all three independently found the same foundation**, so we do that once, then the
three features sit on top with almost no overlap.

## Phase 0 — the shared foundation (do first, unblocks all three)

A single small PR. Every spec is blocked on it:

1. **`Event.PID` / `Event.PPID` / `Event.ProcessStart`.** Both parsers already *see* pid/ppid and
   drop them (auditd keeps them in `rec.fields`; Laurel reads `SYSCALL` and ignores `.pid/.ppid`);
   neither carries a start time — add it where available, else leave zero.
   - OCSF needs `process.pid` (`at_least_one [pid,uid]`).
   - Response needs pid **and** start time (the pid-reuse-safety proof: `starttime ≤ EventTime`).
   - Expose as Sigma fields `ProcessId` / `ParentProcessId` via `Event.Field` (free prefilter
     dimension, and SigmaHQ rules use them). **Decision #9/#2 below.**
2. **`Rule.Tags` → `Alert.Tags`.** `sigma.rawRule` silently drops `tags:` today; only 1 of 7
   baseline rules declares any. Decode them, carry to the alert, and **tag the other six rules**
   (both the OCSF and response specs proposed tag sets — merge them; no directory-name guessing).
   - OCSF maps `attack.*` tags → the finding's ATT&CK metadata.
   - Response uses `tag:` as an action selector.
3. **`Alert` gains `File` / `SHA256` / `Trigger`** (optional; YARA-kind alerts fill them).

That one PR is the keystone. It also changes parser goldens (expected) and lightly touches the
matcher — land it, re-baseline goldens, green, then branch into the three features.

## Order after Phase 0 (by effort × dependency)

1. **OCSF output — first.** Smallest, stdlib-only, **no new sink** (an `Encoder func(Alert)([]byte,error)`
   seam; `jsonl.format: ocsf`, `webhook.style: ocsf`). Only needs Phase 0's pid + tags. Pure
   interop/CV win, low risk, fast confidence. Detection Finding class 2004, pinned OCSF **1.3.0**.
   Golden-per-rule + a pinned schema-validation CI step (via the existing `uv` runner).
2. **Response actions — the flagship** (kill is v1/high-priority). The two-layer, two-unit design:
   a pure testable `Decide(Input) Decision` in `internal/response` (the scan only writes JSON work
   orders to a spool, sandbox untouched) + a separate least-privilege `banken-respond` unit that
   re-decides from on-disk policy and executes via `pidfd` (reuse-safe kill), **cgroup freeze**
   (reversible-first), and `renameat2` quarantine. Phased: decision-layer-in-observe → freeze/kill →
   quarantine. This is where "should-kill is testable" lives (see below).
3. **YARA — after response.** Recommended as a **`yara` CLI shell-out** (`internal/yara`), where the
   *process boundary is the security feature* (hostile file + hostile rules parsed in a child, killed
   on a deadline = never-die for free). Best wired at **quarantine time** (scan the artifact copy in
   the state dir — needs no sandbox relaxation), which is why it follows response. On-alert scanning
   of `/tmp`,`/home` needs a sandbox relaxation — **decision #Y1**, lean quarantine-only for v1.

## Reconcile once, not three times

- **Alert struct:** `Tags` (shared, Phase 0) + `File/SHA256/Trigger` (YARA). OCSF and response both
  *read* the alert; neither needs more fields than these. Add them in Phase 0 + the YARA PR, never
  piecemeal.
- **`engine.Process` seam:** both response and YARA act *after* each alert is dispatched (the
  `Responder` is by-value / no-return, so it can't enrich — don't try). Ordering in the scan:
  dispatch → response work-order spool → (quarantine happens in the respond unit) → YARA scans the
  quarantined artifact. One post-dispatch hook, two consumers.
- **Testing discipline (unified):** all three mirror `engine/fixtures_test.go`.
  - response: `tests/response/NAME.expect-<action>.json` (alert+policy+self+budget → decided action)
    — **this is "should-kill" made testable, no process ever killed**; `exec.Fake` for the executor;
    real primitives only in a build-tagged, root+cgroupv2 VM integration test.
  - OCSF: golden-per-rule + `TestEveryRuleHasAnOCSFGolden` + schema validation.
  - YARA: `exec.Fake`/recorded-CLI goldens + fuzz; one real-engine golden gated on `BANKEN_YARA`.
  Same shape as detections — every policy entry / rule / mapping has a fixture.

## Decisions for Conor (consolidated — the ~10 that matter)

**Shared / Phase 0**
- **D1.** Field names + expose `ProcessId`/`ParentProcessId` to the Sigma matcher? *(lean yes — free
  prefilter dimension, SigmaHQ uses them.)*
- **D2.** Deterministic content-digest alert `uid` (OCSF) vs random UUID? *(lean digest — dedups the
  cursor's self-healing re-reads.)*

**OCSF**
- **D3.** Pin **1.3.0** (Amazon Security Lake ceiling) vs 1.4.0+ (cleaner, drops Security Lake custom
  sources)? *(lean 1.3.0.)*
- **D4.** `product.vendor_name` = `"banken"`? Declare `security_control`/`action_id` only once
  response actions exist? *(lean yes / defer.)*

**Response**
- **D5.** Two units (least-privilege spool + `.path`) vs one wider scan sandbox? *(lean two units —
  keeps the scan's hard sandbox byte-for-byte.)*
- **D6.** Asymmetry: `tag:`-only selectors may map only to **reversible** actions; `kill` must be
  `rules:`-pinned? *(lean yes.)*
- **D7.** Default-refuse on uid-0 targets unless `allowRoot: true`? Frozen-tree cgroup = plain
  `/sys/fs/cgroup/...` vs transient systemd scope? *(lean refuse-root-by-default / plain cgroup.)*

**YARA**
- **Y1.** On-alert scan (needs `PrivateTmp=false`/`ProtectHome=ro`) vs **quarantine-only** for v1?
  *(lean quarantine-only — the reliable one, no sandbox hole.)*
- **Y2.** YARA-X (`yr`) deferred: its wasmtime JIT trips `MemoryDenyWriteExecute` — a 1-hour
  hokkaido spike before committing to the classic CLI parser.

**Ethos**
- **D8 — DECIDED (Conor, morning): official Go-team libs (`golang.org/x/*`) are accepted.** So
  `golang.org/x/sys` is in-bounds for `pidfd`/`openat2`/cgroup. The story is restated as *"one
  external dependency (`yaml.v3`) plus the Go team's extended stdlib (`x/sys`), CGO-free static
  binary."* Still no CGO, still static — x/sys is pure-Go syscall wrappers.

**Nice convergence (bonus, from the standards brainstorm)**
- The attackrange scorecard can gain an **"expected response"** column (assert the decided action
  from the response ledger) — response-fixtures × attack-range in one scoreboard. And response
  actions map cleanly to **MITRE D3FEND** ("detections ATT&CK-mapped, responses D3FEND-mapped").

## What stays honest (flagged by the specs, not papered over)
One-interval latency (response is cleanup, not prevention). No start time in raw audit → bounded by
event time. Freeze moves a process out of its systemd cgroup. Rename-quarantine is same-fs only
(`EXDEV` → in-place neuter, never copy). A root attacker can undo everything — the ledger +
`tamper_banken` are the real defence. YARA adds an optional host-binary dep + an exec per scan;
OCSF's `raw_data` is the normalised event, not the original audit line.

## Suggested sequencing
Phase 0 PR → OCSF (fast win) → response Phase 1 (decide + observe + the should-kill corpus) →
response Phase 2 (freeze/kill executor, VM-tested) → response Phase 3 (quarantine) → YARA
(quarantine-time) → the bonus scoreboard/D3FEND alignment.
