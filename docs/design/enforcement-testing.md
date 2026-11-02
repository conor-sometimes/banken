# Enforcement testing - how to prove the executor kills the right thing and nothing else

Status: **design, not implemented.** Written 2026-11-02 against `5febddb` (branch
`distro-matrix-mimi`). Nothing here is built; the executor it describes is built but **real
enforcement is DISABLED and not armed anywhere** (`internal/response/exec/exec.go:6-20`). Three
pieces of enforcement testing are being built in parallel and are taken as given, not re-designed:
the responder wiring (alert -> `Decide` -> executor -> ledger, task `00c2aded`), the coverage
scorecard ("enforcement killed on X/X rules" over `tests/emulations/`, task `bee5bc37`) and the
whack-a-mole stress (random should-kill / should-NOT-kill mix, zero innocents slain, task
`7f4ad9a2`). This doc is what comes *after* those: the ways enforcement can still go wrong once a
kill lands on the right rule in a clean VM, and the test that proves each one does not.

Read `response-actions.md` (the spec) and `response-actions-research.md` (the pid-reuse argument)
first. Section references like "spec 5.1" point into the spec. Where this doc cites a line number
it is the line in the tree at `5febddb`; where the code and the spec disagree, the code is what gets
tested and the disagreement is listed as a finding.

The one-sentence shape: **enforcement has two failure directions, and the first is unforgivable.**
Killing an innocent process is a false positive with a body; failing to kill a payload is the
status quo banken already lives with. So the strategy is asymmetric: *every* false-positive vector
gets a test that must pass before enforcement is armed on any host, and the evasion vectors get
tests whose job is to measure and record, not to gate.

---

## 1. What the parallel work already proves, and what it does not

| Already covered (in flight) | Not covered (this doc) |
| --- | --- |
| a kill lands on each emulation that trips a kill-policy rule (scorecard) | *how long* it took to land, and what the payload did in the meantime (section 4.1) |
| random innocents in the same VM are never killed (whack-a-mole) | innocents that *look* like the target: same name, same path, same user, reused pid, reused start tick (section 3) |
| a reused pid number is not killed (whack-a-mole pid-reuse) | the unverifiable case: no start time readable at all (section 3.1, the sharpest finding) |
| denylisted pid 1 / sshd / uid 0 are not killed | a *payload* that names itself `sshd` and so becomes un-killable (section 3.4) |
| one rule, one kill, one process | trees, double-forks, respawners, re-execs, D state (section 4) |
| dry-run does nothing in unit tests | dry-run proven inert *structurally*, under a syscall filter (section 5.3) |
| `Enforce` defaults false in Go | the real host is still in observe a month from now (section 5.4) |

---

## 2. Findings in the executor as built (test targets, not blame)

Reading `exec_linux.go` with the adversarial hat on produced these. Each is a test in section 3-5
and a seeded task; none are fixed here (scope: docs only).

| # | Where | What | Direction |
| --- | --- | --- | --- |
| F1 | `exec_linux.go:118-132` | the identity proof runs only `if startErr == nil`. If `/proc/<pid>/stat` is unreadable (hidepid, a race with exit, a pid namespace quirk) **or** both `ProcessRef.StartTime` and `EventTime` are zero, no identity check runs and the action proceeds on a pinned-but-unproven process | wrong-target |
| F2 | `decide.go:165`, `exec_linux.go:112` | the denylist matches `filepath.Base(exe)`. A payload at `/tmp/.x/sshd` is "protected". `tests/emulations/masqdaemon.sh` already does exactly this with `true` | evasion (immunity) |
| F3 | `exec_linux.go:98,109` | `Live.CgroupPath` is read and returned but never used for refusal; the spec's live cgroup rail (`init.scope`, the executor's own) and the live uid-0 rail do not exist in the executor | wrong-target |
| F4 | `exec_linux.go:472-505` | `targetSet` is a ppid walk. A descendant that double-forked and was reparented to pid 1 (or a subreaper) is not a descendant any more and escapes `scope: tree` | evasion |
| F5 | `exec_linux.go:509-526`, `434-455` | tree members are signalled or migrated by a fresh `pidfd_open(pid)` **without** a start-time proof of their own; only the root pid is proven. The window between the `/proc` walk and the act is microseconds, but it is a window | wrong-target (tiny) |
| F6 | `exec_linux.go:234-240` | `Kill(process)` returns `Method: pidfd` on a successful `pidfd_send_signal`; nothing confirms the process *exited*. A task in uninterruptible sleep takes the SIGKILL and keeps existing | honesty |
| F7 | `exec_linux.go:155-182` | `Freeze` is not idempotent as the spec promises (spec 3.3 "returns the existing Handle"): a second `Freeze` of the same tree creates a second cgroup and records the first quarantine cgroup as the pids' `Orig`; thawing handle 1 then handle 2 moves pids into a directory handle 1 already removed | wrong-state |
| F8 | `exec_linux.go:250` | after `cgroup.kill` the cgroup dir is removed immediately and the error ignored; tasks are still exiting so `rmdir` returns EBUSY and the dir leaks | hygiene |
| F9 | `exec_linux.go:395-426` | `Collect` never calls `identify()`; it snapshots `/proc/<pid>` by raw pid. Evidence attributed to an alert can be an innocent reuser's environ | wrong-target (evidence) |
| F10 | `exec_linux.go:101` | liveness is `pidfd_send_signal(fd, 0)`, a signal syscall, so a dry-run executor cannot be run under a filter that forbids all signal syscalls; the spec said `poll(pidfd)` (spec 5.1 step 3) | testability |
| F11 | `decide.go:120-126` | the rate-limit budget is global. 500 alerts from a decoy rule spend `perRun` before the real payload's alert is decided; the attacker buys immunity with noise | evasion |
| F12 | `decide.go:184-195` | first matching entry wins, so one rule maps to exactly one action; "freeze the process AND quarantine its file" cannot be expressed | capability (see `quarantine.md`) |

F1 and F2 are the two that would make a careful operator refuse to arm. F1 is the pid-reuse crux
with a hole in it; F2 hands every piece of malware a one-word cloak.

---

## 3. Direction one: banken kills the WRONG thing

Ranked by how bad the outcome is multiplied by how plausible the trigger is. Everything in this
section is a **gate**: red means do not arm.

### 3.1 Unverifiable target must be refused (F1) - rank 1

**Threat.** The alert names pid 4242 from auditd (no start time). By drain time the original has
exited and an innocent process holds 4242. `pidfd_open` pins the innocent. `readStartTime` fails
(the innocent is in a pid namespace with `hidepid=2`, or exits and is replaced *again* between the
open and the read, or `/proc` is simply not readable to the responder because of a unit hardening
typo). `startErr != nil`, the proof is skipped, the innocent dies.

**Test (unit, Linux, no root).**
- `TestIdentifyRefusesWhenStartUnreadable`: spawn `sleep`, build a `ProcessRef` with its pid, and
  make `readStartTime` fail (inject via a package-level `procRoot` variable pointing at an empty
  `t.TempDir()`, or run the test binary with `/proc` masked using `unshare -m` + a tmpfs bind). Assert
  `Verify` returns `ErrStaleTarget` with reason `unverifiable`, never `nil`.
- `TestIdentifyRefusesWhenNoReference`: `ProcessRef{PID: child}` with zero `StartTime` **and** zero
  `EventTime`. Assert refusal. Today it returns `nil` and `Kill` would act.
- Property (`rapid`): for any `ProcessRef` whose identity cannot be proven (no readable start, no
  reference), `Verify` != nil. Pair with the existing `TestVerifyStaleByStartBound`
  (`exec_linux_test.go:124`).

**Invariant to write into the executor doc comment:** *no proof, no action.* `ErrStaleTarget`
is a good ledger line; a kill with `live.StartTime.IsZero()` is a bug.

### 3.2 Pid reuse across the tick boundary - rank 2

The whack-a-mole test proves an obvious reuse (a pid recycled minutes later) is refused. The
tighter cases:

- **Same tick.** `identityTick` is 10 ms (`exec_linux.go:40`). A reuser forked within the same
  clock tick as the original's start passes `|start - ref.StartTime| <= 1 tick` when the source
  *does* carry a start time (mimi/eBPF). Test: `TestReuseWithinTick` forces a reuse by pinning
  `pid_max` low in a VM (`sysctl kernel.pid_max=300` in a fresh pid namespace), fork-exits in a
  tight loop until a child reclaims the original's pid, and records how often the reuser's start
  tick equals the original's. Assert: the executor refuses when exe differs **and** tick matches
  (today exe mismatch is recorded, not refused - spec 5.1 says that is deliberate for `bash ->
  curl`; the test quantifies how often the deliberate choice would have killed an innocent and
  the number goes in the doc).
- **EventTime bound with clock step.** Step the VM clock backwards 5 s between the event and the
  drain (`date -s`), with `SkewTolerance` at its 2 s default. The bound `start <= EventTime + skew`
  now admits a reuser forked up to 3 s after the event. Assert the exe comparison catches it when
  the exe differs; record the residual (same exe, clock stepped) as **known, accepted, logged**.
  This is the honest limit from research section 2 made into a number.
- **Zombie.** The original exits but is not reaped (parent ignores SIGCHLD). `pidfd_send_signal(fd,
  0)` succeeds on a zombie; `/proc/<pid>/stat` still exists; the pid cannot be reused. Assert `Kill`
  returns `ErrGone` or a no-op, never an error that aborts the drain, and that the ledger line says
  `zombie`.

Needs: root + a fresh pid namespace (`unshare -pf`) for the `pid_max` trick; otherwise plain Linux.

### 3.3 The live rails that do not exist yet (F3) - rank 3

The spec evaluates the denylist in `Decide` *and again* in the executor "against the live process
(its real exe, real cgroup, real uid)" (spec 7.2). The executor checks exe basename only.

**Test (VM, root, cgroup v2).** `TestLiveRailsRefuse`: for each of
- a `sleep` started inside `init.scope` (`systemd-run --scope --slice=-.slice`, or move it there by
  writing `cgroup.procs`),
- a `sleep` in `sshd.service`'s cgroup (write its pid into that unit's `cgroup.procs`),
- a `sleep` running as uid 0 with policy `allowRoot: false`,
- the responder's own pid and its parent,
build a `ProcessRef` whose *alert fields* are innocent (`Image: /tmp/x`, `User: alice`, so `Decide`
passes) and call `Kill`. Assert `ErrDenied` from the executor, with the rail named. Today all four
die.

This is also where the research's "cgroup-unit rail" (research section 4) gets its test: a name
list with a fixture per name, plus a unit list (`init.scope`, `sshd.service`, `systemd-journald.service`,
`auditd.service`, `dbus-broker.service`, `banken.service`, `banken-respond.service`) with a fixture
per unit.

### 3.4 Denylist by basename is a cloak (F2) - rank 4, and the one that cuts both ways

A payload copied to `/tmp/.x/sshd` cannot be killed. `masqdaemon.sh` is the emulation. This is an
*evasion*, but it is listed under direction one because the fix (match on something the attacker
does not control) is also what stops the opposite error: an operator's legitimate `/opt/myapp/bin/init`
helper being treated as pid 1's kin and never acted on when it should be.

**What to match instead.** A denylist entry is protected only when the live exe's realpath is under
a trusted prefix (`/nix/store`, `/usr`, `/bin`, `/sbin`, `/run/current-system/sw/bin`, `/run/wrappers/bin`)
**or** the live cgroup is one of the protected units (3.3). A basename match outside those is
recorded as `masquerade: true` in the ledger and does **not** protect.

**Test.** `TestMasqueradeIsNotProtected` (VM or plain Linux): copy `sleep` to
`$tmp/sshd`, `$tmp/systemd`, `$tmp/auditd`, `$tmp/banken`, run each, `Kill` each with a kill-pinned
policy. Assert they die, and assert the ledger carries `masquerade: true`. Then the inverse,
`TestRealDaemonsAreProtected`: `Verify` on the real `sshd` (resolved through `/proc/<pid>/exe`) and
the real pid 1 returns `ErrDenied`. Both must pass before arming. Today the first fails.

Also exercise the two spoofs that do *not* work, so the doc can say so with a test behind it:
`exec -a sshd /tmp/payload` (changes argv[0], not `/proc/<pid>/exe`) and `prctl(PR_SET_NAME)`
(changes `comm`, not exe). Both must still die.

### 3.5 Parent vs child - rank 5

`buildTarget` (`decide.go:197-218`) targets `Event.PID`, the process that performed the audited
syscall. `scope: tree` walks *down* from it. Two properties to pin:

- **Never up.** Property test: for any alert, `Decision.Target.Process.PID == Alert.Event.PID`, and
  the executor's `targetSet(root, tree)` never contains `readPPID(root)` or any ancestor. An
  operator typing a GTFOBins one-liner in their shell gets the one-liner's tree killed, never the
  shell, never sshd-session above it. Add the sweep to `FuzzDecideNeverCrossesRails` (spec 10.1)
  and a `targetSet` unit test with a three-deep chain asserting the grandparent is absent.
- **Child alert, parent payload.** A rule keyed on `ParentImage` (webshell spawns `id`) names the
  *child* pid. Killing `id` leaves the webshell. This is correct behaviour for the executor and a
  policy-design limit: write the fixture `webshell_child.expect-kill.json` whose expectation
  documents that the parent survives, and put "a parent-keyed rule should map to `freeze`, not
  `kill`, and the operator finishes the job" in the policy guidance. Do **not** add `scope: parent`.

### 3.6 An innocent process matching a rule - rank 6

The detection corpus owns rule precision; enforcement amplifies a miss into a kill. Two gates:

- `TestBenignNeverActsEvenUnderKillAll` (fast, Mac-safe): replay every `tests/fixtures/*.expect-none.json`
  through the engine and `Decide` with a synthetic `enforce` policy that maps **every** loaded rule
  to `kill` with `allowRoot: true` and an empty denylist. Every decision must be `no-policy-match`
  (nothing fired) - this is the detection corpus's promise, re-asserted at the point where it
  matters.
- **Baseline hour** (VM): boot the module VM with `mode: enforce`, the same kill-all policy, the
  executor armed, and no emulation. Run the ordinary system for one simulated hour (timers,
  `nix-collect-garbage`, a user logging in over ssh and running `ls`, `find`, `tar`, `curl` to
  TEST-NET-1). Assert the `actions-*.jsonl` ledger has zero `executed` lines and every process that
  was alive at the start is alive at the end (snapshot `/proc` pids + start times before and after).
  This is the whack-a-mole's "innocents" set extended to *the whole machine*, with no should-kill
  noise to hide behind.

### 3.7 Policy misconfiguration - rank 7

A kill entry pinned to `proc_creation_lnx_file_and_directory_discovery` kills every `find`. The
loader cannot know that is wrong. What it can do:

- **Blast-radius replay.** `banken respond simulate --policy new.yml --since 7d`: replay the
  `decisions-*.jsonl` ledger (every alert banken saw, observe mode included) through `Decide` with
  the candidate policy and print "would have killed N processes across M rules, top rules: ...".
  The test is a golden over a recorded week of decisions. An operator who sees "would have killed
  1,204 `find`s" does not arm that entry. Pure, fixture-testable, no VM.
- **Lint warnings** at `ParsePolicy`: a `kill` entry pinned to a rule at `level: low|medium`, or to
  a rule whose fixture set contains an `expect-none` sibling that differs only in argv (a sign the
  rule is behaviourally broad). Warning, not error, as the spec's "rule name no loaded rule has"
  warning.
- `TestEveryKillEntryHasADenylistFixture`: for every `kill` entry in every test policy there is a
  fixture where the same alert with the image rewritten to each built-in denylisted name yields
  `denylist`. Spec 10.1 has it as a replay; make it a per-entry requirement so a new kill entry
  cannot land without it.

### 3.8 Rate limit as an evasion that also causes the wrong *inaction* (F11) - rank 8

Not a wrong-kill, but a wrong-*skip* the attacker chooses: flood `netconn.sh`-style noise through a
freeze-mapped tag, spend `perRun: 3`, and the real `xmrig_dropper` alert in the same run hits
`rate-limit`.

**Fix shape** (design, for the task): budget per policy entry (`rateLimit` on the `Entry`, default
inherits the global) and evaluate `kill` entries before `freeze` entries within a run regardless of
alert order (the responder sorts decided-but-not-yet-budgeted actions by severity before spending).
**Test:** 500 decoy alerts + 1 kill-pinned alert in one run, random order; assert the kill is
`executed` and the decoys share the remaining budget. Fast test over the `Fake` executor.

### 3.9 Tree members without their own proof (F5) - rank 9

Microseconds, but a property with a clean statement: *every pid the executor signals has been pinned
and proven, or is inside a cgroup the executor froze before it could change.* The cgroup path
already satisfies the second half (frozen on arrival). The SIGSTOP fallback and `pidfd-tree`
fallback do not. **Test:** build `targetSet`, then before `sigAll` kill one member and spin
`fork-exit` until its pid is reclaimed by an innocent (pid-namespace `pid_max` trick); assert the
innocent is not signalled. Expect this to need per-member start-time capture during the walk
(capture `starttime` in the same `/proc/<pid>/stat` read `readPPID` already does, verify it at
signal time). Root + pid namespace.

---

## 4. Direction two: banken FAILS to kill, or is evaded

These tests **measure**. A red here is a number in the README's honesty table, not a blocker to
arming (an un-killed payload is where banken already is).

### 4.1 The detect-to-kill window, as a measured quantity - rank 1

Everything in this direction lives inside one number: how long between the audited syscall and the
SIGKILL. The spec says "up to one interval" (spec 1, non-goals). Make it a histogram the scorecard
prints next to coverage.

**Harness (VM).** A *heartbeat victim*: a payload (wrapped emulation, as the whack-a-mole does) that
after tripping its rule appends `$(date +%s%N)` to `/tmp/hb.<pid>` every 10 ms until killed. The
kill time is the last heartbeat; the event time is the audit record's timestamp (already in the
alert as `Event.Time`); the decision and executed times are in the two ledgers. Report, per run:

```
time-to-kill  p50 2.31s  p90 2.9s  p99 4.1s  max 61.0s  (n=48)
  of which: scan interval wait  p50 1.9s | decide+spool 4ms | path-unit fire 180ms | drain+identify+kill 11ms
```

Break the window into its parts so the next optimisation is obvious (it will be the interval, which
is the `--watch` argument). Assert nothing except that the histogram was produced and `max` is below
`spool.maxAge` (10 m) - a kill that lands after expiry is a bug in the expiry, not latency.

**Damage-in-the-window.** Give the heartbeat victim a second job: write 1 MiB/s of "loot" to a
scratch file. Report bytes written before death. This is the honest cost of post-event response, in
a unit an operator understands, and it is the number that justifies the `--watch` mode work.

### 4.2 Fire-and-exit - rank 2

Most of `tests/emulations/*.sh` exit in milliseconds; the real-world droppers they imitate often
do too (`curl | sh` finishes, the installed miner is a *different* pid). The scorecard wraps them to
stay alive, which is right for proving the kill path. Separately record the unwrapped truth:

- Run every emulation **unwrapped** under a kill-all enforce policy. Classify each ledger line:
  `executed`, `gone` (the payload exited first), `stale` (pid reused), `denied`. Report `gone` as a
  fraction: "N/M emulated payloads were already gone at drain time". It is a property of the timer
  model, not a bug, and it belongs in the README next to coverage.
- The follow-on that *is* actionable: for `gone` payloads whose rule also names a
  `TargetFilename`, the file quarantine still applies (the dropped file outlives the dropper). The
  quarantine scorecard in `quarantine.md` section 8 covers it. This is the strongest argument that
  quarantine is not optional for a post-event responder.

### 4.3 Fork bombs, respawners and double-forks (F4) - rank 3

Three victims, one assertion each (VM, root, cgroup v2):

- **Respawner.** `while :; do (payload &); sleep 0.05; done`. `scope: process` on the loop pid
  leaves the latest payload alive; `scope: tree` via `cgroup.kill` must leave none. Assert zero
  survivors by walking `/proc` for the payload's exe after the kill. This is the test that *argues
  for* `cgroup.kill`: run it also with `cgroup.kill` artificially unavailable (mount a tmpfs over the
  file) to exercise the `pidfd-tree` fallback and record how many escape.
- **Fork bomb.** `:(){ :|:& };:` with `ulimit -u 200`. Assert `cgroup.kill` ends it, the executor
  returns within a deadline, and the responder unit's own cgroup is untouched (the bomb never
  migrates *into* `banken-respond.service`).
- **Double-fork daemonizer.** `setsid sh -c 'payload &'` so the payload's parent dies and it is
  reparented to pid 1. The ppid walk (`exec_linux.go:472`) misses it. Assert... today: it survives.
  The design fix: when the alert pid's original cgroup is *dedicated* (a transient scope or a
  service unit, i.e. not `session-N.scope` and not `user@N.service`'s top cgroup), walk the cgroup's
  `cgroup.procs` instead of ppid; when it is shared (a login session), ppid is the only safe walk
  and the orphan is recorded as `escaped-reparent` with its pid, for the operator. Test both
  branches.

### 4.4 Re-exec under a benign name - rank 4

`exec /usr/bin/sleep` from the payload: same pid, same start time, exe now `/usr/bin/sleep`. The
identity proof passes (deliberately; spec 5.1) and the kill lands. Assert it does. Then the cloak
variant (3.4): `cp payload /tmp/sshd && exec /tmp/sshd`. Today: immune. After the 3.4 fix: dies,
`masquerade: true`. One test, two phases, same victim.

### 4.5 SIGKILL vs uninterruptible sleep (F6) - rank 5

A task in `D` state takes the signal and dies when it leaves `D`; one stuck in `D` forever (hung
NFS, a wedged driver) does not die for anyone, root included. banken cannot fix that; it must not
*claim* a kill it did not get.

**Design:** after `pidfd_send_signal(SIGKILL)`, `poll(pidfd, POLLIN, 500ms)`. `POLLIN` within the
wait: `exited: true`. Timeout: read `/proc/<pid>/stat` state, record `exited: false, state: D`, and
the journal line says "signalled, not confirmed dead". **Test (honest about difficulty):** a true
unbreakable `D` is hard to manufacture in a VM. Use the approximations: (a) a reader blocked on a
FUSE filesystem whose daemon never answers (`TASK_KILLABLE`, so SIGKILL *does* work - this proves
the confirmation path, not the stuck path); (b) a frozen task (`cgroup.freeze=1`, `TASK_FROZEN`):
assert SIGKILL kills a frozen task, which the spec asserts and nobody has verified on 6.12 yet. The
truly stuck case is documented as untestable without a buggy driver, and the code path is covered
by the timeout branch with a `sleep` that the test simply does not let exit (SIGSTOPped) - it
exercises the "not confirmed" ledger line.

### 4.6 Cgroup escape - rank 6

A frozen task cannot run, so it cannot escape. Its unfrozen *allies* can move it:

- an unprivileged sibling in the same session cannot write `banken.quarantine/<id>/cgroup.procs`
  (0750 root) - assert EACCES from a non-root helper (VM);
- a root attacker can, and the spec says so (spec 9). The test is the ledger's: move a frozen pid
  out by hand, run `banken respond list`, assert it reports `handle X: pid Y no longer in cgroup
  (moved)` instead of `frozen`. Detection of the escape, not prevention.
- systemd: `systemctl daemon-reexec` and `systemctl restart user@1000.service` while a tree is
  frozen in `banken.quarantine/`. Assert the frozen pids are still there and still frozen (systemd
  does not touch foreign root-level subtrees - spec 5.2 asserts this; prove it on 26.05's systemd).

### 4.7 Freeze that does not take, thaw that does not restore (F7) - rank 7

- `TestFreezeIdempotent`: `Freeze` twice on one tree. Assert the second call returns the first
  handle (or `ErrAlreadyFrozen` with the handle) and creates no second cgroup. Then `Thaw` once:
  every pid is back in its *original* cgroup (`/proc/<pid>/cgroup` equals the pre-freeze read) and
  running (the heartbeat file grows again). Today the double-freeze leaves pids homeless.
- `TestFreezeCatchesForkDuringMigration`: a victim that forks every 1 ms; `Freeze(tree)`; assert
  `cgroup.events` reads `frozen 1` and that no process with the victim's exe exists outside the
  quarantine cgroup. The fixpoint loop the spec describes (spec 5.2 step 3) is not in the code
  (`cgroupFreeze` is one pass over a one-pass walk) - this test shows whether frozen-on-arrival
  alone is enough.
- Cgroup dir leak (F8): after `Kill(tree)`, wait for `cgroup.events` `populated 0`, then `rmdir`;
  assert `ls /sys/fs/cgroup/banken.quarantine/` is empty after 100 kills.

### 4.8 Evasion through the decision layer - rank 8

- **Source laundering.** The attacker cannot write to the audit log as a non-root user except
  through what they *do*, but they can choose a `comm`/argv that makes Laurel's enrichment emit a
  field banken parses into `Image`. Fuzz: `FuzzDecideNeverTargetsFromUntrustedSource` - a forged
  generic-JSONL alert never produces `Action != none`. Exists in spec 10.1; keep.
- **Level laundering.** A rule's `level` is in the rule file, not the event; no attacker control.
  Nothing to test beyond `below-min-level` fixtures.
- **Budget exhaustion.** Section 3.8.
- **Spool poisoning.** The scan is the only writer of `/var/lib/banken/spool` (`StateDirectory`,
  root 0700). A forged work order asking for a kill the on-disk policy would not decide must be
  downgraded (spec 3.5 step 1). Test with the `Fake`: a work order carrying `kill` for a pid the
  policy would `freeze`; assert `failed: downgraded by executor`. Spec 10.2 has it; it is the single
  most important protocol test and should be in the first responder PR.

---

## 5. Invariants: correctness and safety properties to assert as tests

### 5.1 Idempotency

| Call | Second call must | Test |
| --- | --- | --- |
| `Kill` | `ErrGone`, no error that aborts the drain, ledger `already-dead` | `TestKillTwice` (plain Linux) |
| `Freeze` | same handle, no second cgroup | `TestFreezeIdempotent` (4.7) |
| `Thaw` | no-op with ledger note, never an error from a missing dir | `TestThawTwice` |
| `Quarantine` | same handle, file not moved again | `quarantine.md` section 7 |
| `Restore` | no-op with ledger note | `quarantine.md` section 7 |
| drain of the same work order | executor called again, ledger says `already-applied`, order deleted | spec 10.2 |

### 5.2 The ledger always records (write-ahead)

The invariant: **for every real action there is a ledger line written *before* the act that names
the work order, and one after that names the handle or the error.** A crash between the act and the
second line leaves a `requested` without an `executed`, which the next drain turns into `gone` or
`already-applied` - inferable, never silent.

**Test:** fault injection in the drain. Wrap the executor in a `Fake`-like decorator that runs the
real primitive and then `os.Exit(137)`s before returning. Restart the drain. Assert the ledger has
`requested` -> (gap) -> `gone`/`already-applied` for the order and the victim is dead exactly once.
Also the converse the spec names (spec 7.4): make the ledger directory read-only; assert the
responder writes **no** work order (an action without a record is worse than no action) and surfaces
the error.

### 5.3 Dry-run is truly inert - proven structurally, not by inspection (F10)

Unit tests assert dry-run "does nothing" by checking the victim is alive afterwards. Stronger: run
the dry-run executor where doing anything is *impossible* and assert it still succeeds.

**Test (VM or any systemd host, no root needed for the user manager):**

```
systemd-run --user --wait -p SystemCallFilter=~@signal:kill,tkill,tgkill,pidfd_send_signal,rt_sigqueueinfo \
            -p SystemCallFilter=~rename,renameat,renameat2,link,linkat,unlink,unlinkat,chmod,fchmod,fchmodat \
            -p ProtectControlGroups=yes -p ReadOnlyPaths=/ \
            go test ./internal/response/exec -run 'DryRun'
```

If the dry-run executor passes under that filter, it *cannot* have signalled, renamed, chmodded or
written a cgroup. Today it fails: liveness is `pidfd_send_signal(fd, 0)` (`exec_linux.go:101`),
which the filter blocks. Switch liveness to `poll(pidfd)` (the spec's step 3) and the structural
proof holds for every dry-run path. Also assert the filter is *working* by running one real-enforce
test under it and seeing EPERM, so the proof is not a vacuous pass.

The `Quarantine` dry-run reads the whole file to hash it (`exec_linux.go:308`) with no size cap; a
dry-run on a 40 GiB file or a hung NFS mount blocks the drain. Cap at `maxFileBytes` (see
`quarantine.md` section 4) and test with a sparse 1 TiB file.

### 5.4 Enforce-off on the real host, continuously

Three layers, cheapest first:

1. **Nix module assertion.** `services.banken.response.enable` defaults false; when true,
   `mode` defaults `observe` and the rendered `banken-respond.service` is only emitted when
   `mode = "enforce"` **and** an explicit `armEnforcement = true`. A `nix eval` test asserts the
   default config contains neither the unit nor `enforce: true`. Runs on hokkaido in
   `nix flake check`, no VM.
2. **`banken respond status`** prints `mode`, `enforce` (the executor gate), kill-switch presence,
   the policy hash, and the last 24 h action count. `verify.sh`-style: the hokkaido deploy check
   greps `enforce: off` until Conor decides otherwise. One line, in the same place the containment
   verify runs.
3. **Live canary.** A weekly `+maint` run on hokkaido: trip one kill-pinned rule (the wrapped
   `xmrig.sh`, kept alive 3 intervals) and assert it is **still alive** and the decisions ledger has
   an `observe-mode` line for it. Observe mode proven inert on the real host, against the real
   audit pipeline, every week until the day it is meant to stop being inert - at which point the
   same canary flips to asserting the kill.

### 5.5 Restore-ability of reversible actions

For `freeze` the test is 4.7 (pids home, running, heartbeat resumes). For `quarantine` it is the
round-trip property in `quarantine.md` section 7: content, mode (including setuid), owner, mtime,
xattrs identical after quarantine + restore, on same-fs and on EXDEV.

### 5.6 The responder's own sandbox lets it act

A hardened unit can *silently disarm* the executor: a missing `pidfd_open` in `SystemCallFilter`
is EPERM, which `identify` turns into an error, which the ledger records as `failed` - and nobody
reads the ledger. **Test (VM):** with the real `banken-respond.service` unit from the module, each
primitive succeeds once (kill, freeze+thaw, tree-kill, quarantine+restore, collect) and each
*disallowed* thing fails (connect a socket, write outside `ReadWritePaths`, read `/home`). Plus a
unit test that the `SystemCallFilter` list in `module.nix` is a superset of the syscalls
`exec_linux.go` makes (grep the `sys*` constants and the `syscall.` calls; compare to the rendered
unit). Cheap, and it catches the day someone adds `openat2`.

---

## 6. Ranked summary

| Rank | Test | Direction | Needs | Gate? |
| --- | --- | --- | --- | --- |
| 1 | unverifiable target refused (3.1, F1) | wrong-target | Linux | **yes** |
| 2 | masquerade not protected / real daemons protected (3.4, F2) | both | Linux | **yes** |
| 3 | live cgroup + uid rails (3.3, F3) | wrong-target | root VM | **yes** |
| 4 | benign baseline under kill-all, fixtures + hour (3.6) | wrong-target | fast + VM | **yes** |
| 5 | dry-run under a syscall filter (5.3, F10) | inertness | systemd user manager | **yes** |
| 6 | write-ahead ledger + crash injection (5.2) | custody | fast | **yes** |
| 7 | spool downgrade-only (4.8) | evasion/custody | fast | **yes** |
| 8 | pid reuse at the tick and clock-step edges (3.2) | wrong-target | root + pidns | yes (record residual) |
| 9 | never-up property + child/parent fixture (3.5) | wrong-target | fast | yes |
| 10 | time-to-kill histogram + damage-in-window (4.1) | measure | VM | no (report) |
| 11 | fire-and-exit `gone` fraction (4.2) | measure | VM | no (report) |
| 12 | respawner / fork bomb / double-fork (4.3, F4) | evasion | root VM | no (report) |
| 13 | freeze idempotency + fork-during-migration + dir leak (4.7, F7, F8) | state | root VM | yes |
| 14 | post-kill confirmation, D-state honesty (4.5, F6) | honesty | VM | no |
| 15 | per-entry budget vs decoy flood (3.8, F11) | evasion | fast | no |
| 16 | tree members proven (3.9, F5) | wrong-target (tiny) | root + pidns | no (record) |
| 17 | blast-radius `simulate` (3.7) | misconfig | fast | tooling |
| 18 | responder sandbox lets it act (5.6) | silent disarm | VM | yes |
| 19 | Collect identity (F9) | evidence | Linux | yes |
| 20 | enforce-off on the real host, weekly canary (5.4) | inertness | hokkaido | standing |

"Gate" means: red blocks arming on any host. The whack-a-mole and scorecard remain the first two
gates; this table is what sits behind them.

---

## 7. What is hard to test, said plainly

- **A true unbreakable `D` state** needs a buggy driver or a dead NFS server. The confirmation path
  is tested with stand-ins (4.5); the stuck case is documented, not proven.
- **Pid reuse within one 10 ms tick** needs `pid_max` pinned low in a private pid namespace and a
  fork-exit spin; it is deterministic enough to be a test but it will be slow (seconds) and
  root-only. It measures a residual the design accepts; it does not eliminate it.
- **The clock-step case** can be forced in a VM but on a real host depends on NTP behaviour banken
  does not control. The exe comparison is the mitigation and the number is recorded.
- **A root attacker** thaws, restores, moves cgroups and edits the ledger. Every test in 4.6 and
  5.2 can only prove banken *notices*. The spec never claimed more (spec 9); the tests must not
  either.
- **Benign-baseline completeness.** An hour of a quiet VM is not a month of a real host. The weekly
  canary (5.4) and the observe-mode decisions ledger on hokkaido are the real baseline; the VM hour
  is the floor.
- **Latency numbers** from a KVM guest on hokkaido are the guest's, not a laptop's or a loaded
  server's. Report them with the interval setting and the guest spec beside them.

---

## 8. Tasks seeded from this doc

Seeded in Taskwarrior under `project:banken.response` with `+design` or `+roughedge`; the ids are in
the PR description. One task per finding F1-F11 (F12 is in `quarantine.md`), plus one each for the
time-to-kill harness, the benign-baseline hour, the dry-run syscall-filter proof, the write-ahead
crash injection, the blast-radius `simulate`, the responder-sandbox test, the weekly observe canary,
and an `EMUL_KEEP=1` mode for the emulation scripts so payloads and dropped artifacts stay alive /
on disk for the enforcement and quarantine scorecards (coordinated with `7f4ad9a2` and `bee5bc37`).
