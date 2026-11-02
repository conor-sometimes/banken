# Test harness review: how much to trust the green

Reviewed 2026-11-02 against branch `distro-matrix-mimi` (banken) and `main` (mimi), by reading
every harness file end to end. No builds were run and no test was modified; where a claim below
could only be settled by a run it says so and names the one command that settles it.

Scope: the KVM VM proofs and their shared library (`tests/lib/enforce-spawn.nix`,
`tests/response-*.nix`, `tests/vm.nix`, `tests/switch*.nix`, `tests/sigmahq-emul.nix`,
`tests/attackrange.nix`, `tests/bench.nix`), the live distro matrix (`tests/distros/*`), the
emulations and fixtures, the Go test layer (`justfile` fuzz smoke, goldens, skip guards,
`ocsf-validate`, CI wiring), and mimi's `tests/vm.nix` and `tests/kernels.nix`.

Ratings: **solid** = the assertion is on the real effect and the harness cannot easily pass with
the product broken; **soft** = proves the headline but has at least one proxy assertion or a
hand-maintained oracle that can rot; **fragile** = can go green with the product broken, or is
not gating at all.

## 1. Calibration: the issues already found this session

| Known issue | Status after reading the code |
| --- | --- |
| Wall-clock `-fuzztime` smoke raced go test's deadline | Fixed: `justfile` `fuzz` is `2000x` (a count). The only remaining wall-clock budget is the nightly `.github/workflows/fuzz.yml` (300 s per target, its own 20 min job timeout, under go's 10 min default); that is intended and not per-commit. Nothing else in the tree passes `-fuzztime`. |
| bash 5.3 exec-optimisation made the victim the wrong binary | Fixed in `enforce-spawn.nix` (`_STAY = "sleep 100000 ; :"`), and the proofs now assert both "victim dead" AND "an executed pidfd kill line for that pid", so the "refused for the wrong reason" shape would be red, not green. The lesson is documented in the header. |
| B1 set-equality broke because fixtures drifted behind new rules | Fixed for the own-rule families that drifted (fixtures added), but the CLASS is still open: the fast oracle (`TestFixtures`) only checks "at least one event fires the named rule" per file, so it can never catch a new rule co-firing on an old emulation. Worse, it is about to bite again from the other side: see "sigmahq families run with an empty expectation" below. |
| `TestDryRunDefaultDoesNotAct` passed non-root, failed root | Fixed in product (E1: dry-run records the would-be refusal) and the test comment says so. The environment-split class remains: every `requireCgroupV2Root` test and the root-only immutable assertion in `quarantine_linux_test.go` run ONLY inside the matrix's E1 (manual, root). |
| Distro matrix not in per-commit CI | Confirmed: `ci.yml` runs `just default` + rules-check + cross-compile + size-check + ocsf-validate. No KVM test of any kind runs per commit; `nix flake check`, the matrix, sigmahq-emul and the four response proofs are all by hand on hokkaido. |
| "4 red iterations were all harness bugs" | Consistent with what the code shows: the harnesses carry a lot of shell-in-python-in-nix plumbing and the bugs found below are all in that plumbing or in hand-kept lists, not in assertions on the product. |

## 2. Per-harness review

### 2.1 `tests/lib/enforce-spawn.nix` (shared spawn / scan / heartbeat helpers)

Rating: **solid** for what it does; the two hard lessons are baked in correctly.

What it actually does: the marker lives only in the final exec's argv (shell carrier reads it from
a file; image carrier passes it only to the exec'd copy of bash), every launcher exec-replaces
(`runuser -- setsid bash -c "... exec ..."`), and the trailing `:` stops bash exec-optimising into
`sleep`. `enf_spawn` records `$$` from the bootstrap shell, which is the victim's pid after the
chain of execs, and asserts `kill -0` before returning. `enf_scan` is the correct post-split
definition of "a scan is done": daemon oneshot exited AND spool empty AND helper inactive.

Residual risks (none a false green on their own):

- For the image carrier the trigger tokens DO sit in `runuser`'s and `setsid`'s argv (the
  bootstrap string is passed verbatim). This is fine only while every image-carrier rule keys on
  `Image|endswith`; a CommandLine-only rule used with an image carrier would make the launchers
  marker-carriers again, and the only thing stopping that is the comment at the top of the file.
  The library does not check it.
- `_spool_drained` / `enf_wait_drained` poll `ls -A spool` and `systemctl is-active`. There is a
  window between the path unit's inotify firing and the helper going active in which the spool
  can be non-empty and the helper inactive; `wait_until_succeeds` happens to tolerate this because
  the spool is non-empty then. The reverse (spool empty, helper about to start on a second order)
  cannot happen since orders are written before the trigger. OK, but it is reasoning, not a
  barrier.
- `hb_stalled` is 200 ms settle + 1 s window on a 10 ms beat. Correct direction for the victim
  (static file cannot grow). For the innocent (`assert not hb_stalled("I")`) a 1 s stall of a
  forking shell under a loaded KVM host is possible: flaky-red, low.
- `enf_alive` is `kill -0` as root, so a zombie answers "alive" and would turn a successful kill
  into a red "STILL ALIVE", never a green.

### 2.2 `tests/response-enforce.nix` (kill proof + X/X scorecard + boundary phase)

Rating: **soft**. The kill proof itself is solid; the scorecard's denominator and attribution are
not what the printout claims.

Claims vs exercised:

- The core assertion is real: every victim must be dead AND have a ledger line with
  `phase=executed, enforced=true, handle.dryRun=false, handle.method=pidfd`, landed via the
  real `banken-respond.service` drain. The innocent must survive and have no kill line. Good.
- "enforcement killed on X/X rules": `X = len(distinct_killed)` is printed as both numerator and
  denominator. It is tautological by construction; the real gate is the `failures` assert just
  above it, which does cover every `killCases` entry. The LINE is theatre, the gate is not.
- Rule attribution is not checked. `killed_pids` is keyed by pid only; the scorecard credits
  `c["rule"]` as "proven killed" without ever reading which rule the executed order named. A
  victim whose argv also trips a second kill-mapped rule would be credited to the first even if
  the first's policy mapping were broken. Cheap to fix: match `alert.rule` (or `decision` /
  `order` rule) on the executed line to `c["rule"]`.
- Coverage oracle is hand-kept and already stale. `killCases` (48 rules) + `deferredRules` (13)
  = 61; the rule tree has 62. `browser_credential_access` is in neither list, so the "every
  own-rule that CAN be tripped by a long-running process" claim silently omits a rule and nothing
  compares the two lists to `rules/`. Same class as the fixture drift. Fix: assert at Nix eval
  time that `killRules ++ deferredRules == every rule name under rules/`.
- The transient demonstrator line is always True: `transient_gone = (pid in gone_pids) or
  (not alive and pid not in killed_pids)`; the second disjunct holds for any exited process.
  It is printed, not asserted, so no gate is affected, but the scorecard line "decided, ErrGone:
  True" is not evidence that a decision was ever made.
- Boundary phase, forged stale-image order: asserts `phase == "failed"` and only PRINTS the error.
  Any failure (pidfd_open EPERM, a helper crash mid-order) passes as "refused by the live identity
  rail". Assert `ErrStaleTarget` text (or an error class field) in the line. The following
  `assert bnd_innocent not in {...} or phase == "failed"` is a tautology after the previous
  assert.
- Forged orders carry `"policy": "sha256:forged"` and are accepted by the helper. If that is
  intended (the helper re-decides from its own policy) it should be stated in the test; if the
  helper is meant to bind orders to a policy hash, this test is proving it does not.

Flaky-red: the `auditctl -m ENFORCE_READY` + grep barrier is a sound ordering argument (auditd
writes its queue in order). Boot-time drain under `minLevel: low` + kill-all means boot execs that
trip rules (modprobe etc.) get ErrGone orders; harmless, noisy ledger.

### 2.3 `tests/response-whackamole.nix` (randomised mix, zero collateral)

Rating: **soft**. Zero-collateral and should-kill-dies are solid; the three "refused" claims and
the pid-reuse claim are proxy signals or optional.

- `uid0_refused` and `trusted_refused` are set when the process is ALIVE and not in the executed
  kill set. Nothing checks that a decision was made and refused by the uid-0 rail or by the
  trusted-prefix rail. The audit rules (`module.nix`: every execve, no auid filter) do deliver the
  root exec to banken, so detection is plausible, but "survived" == "refused" is exactly the
  "proxy signal, not the real effect" shape. If the root victim's rule did not fire at all (level
  gate, parse quirk), the test prints "real uid-0 refused: True". Fix: find the decision or action
  line for that pid and assert its rail/reason.
- Phase C pid-reuse: if `ns_last_pid` does not land the pid, the test prints a NOTE and passes
  overall. Honest about it, but it means a future run can silently stop proving the start-time
  bound live. It reproduced on the recorded runs; make `reuse_hit` a gate with a few retries, or
  the scorecard line "pid-reuse refused: not force-reproduced this run" will one day be the
  steady state nobody reads.
- Should-kill victims are only checked for death, not for an executed kill line (enforce.nix
  does both). A victim dying for an unrelated reason would count as a kill.
- `masq_seen["recorded"]` accepts ANY decision line with `masquerade:true` from any iteration;
  fine while /tmp/mqN/sshd is the only masquerade, as the comment says.
- Phase A `new_exec` and all ledger reads slice by line count; OK because nothing truncates the
  ledger mid-run.
- Interleave "jitter" is `machine.succeed("true")`: ordering is randomised by `shuffle`, timing
  is not. Fine, just not what the header implies.

Flaky-red: `random.seed(1312)` makes the shuffle deterministic. `/usr/local/sbin/e{it}` per
iteration avoids ETXTBSY. The ns_last_pid trick depends on no other fork racing in; the fallback
is a NOTE, so this is a flaky-pass-with-less-coverage, not a flaky red.

### 2.4 `tests/response-freeze.nix` (freeze / thaw / F7 / F8)

Rating: **solid**. The best of the four proofs.

- Asserts the real effects: `cgroup.events` says `frozen 1`, both tree pids in `cgroup.procs`,
  heartbeat file static for the victim and growing for the innocent, manifest `orig` equals the
  pre-freeze cgroup string read from `/proc/pid/cgroup`, thaw puts each pid back to exactly that
  string, the cgroup dir is gone, tombstone written, second thaw a no-op, unknown id exits 1,
  11 tree kills leave zero dirs.
- The order replay for F7 is copied from the spool BEFORE the drain, so it is the daemon's real
  order, not a hand-forged one. Good.
- `v_pids` is a subset of manifest pids on purpose (transient beat child); correctly reasoned.
- Weak spots: the freeze is driven through `systemctl start banken-respond.service` by hand after
  re-arming the path unit (fine, same unit). Phase D's zero-leak is "no dirs" after `enf_scan`,
  which already waits for the helper to be idle, so no race. Only the innocent-heartbeat check is
  load-sensitive (see 2.1).

### 2.5 `tests/response-quarantine.nix` (neuter / rename / restore)

Rating: **soft**. Very thorough on file identity and restore guards; two harness shapes can
inherit a previous phase's result, and the rename path is not the production path.

Claims vs exercised, stated honestly in the header and worth repeating for the reviewer: under
the real armed helper (`ProtectSystem=strict` + per-path `ReadWritePaths`) a quarantine ALWAYS
takes the in-place NEUTER branch (EXDEV across bind mounts). The RENAME branch, the stored-inode
binding (Q1 rename half), the squatter refusal (D1) and the rename restore (C, Q1) are proven only
under an UNSANDBOXED by-hand `banken respond drain` as root. So: the production path is proven for
neuter (B1, B2, D2, E, F); rename is proven for operator tooling. The test name and scorecard say
"quarantine enforcement proof"; the reviewer should read it as "neuter under the helper, rename by
hand".

- `latest_quar()` returns the newest executed quarantine line in the WHOLE ledger. A phase where
  nothing fired inherits the previous phase's line. Today each phase is rescued by accident: B1
  expects neuter after A's rename, B2's inode check fails against B1's manifest, D1 expects rename
  after C, D2 expects neuter after D1. Reorder two phases, or add a phase with the same method as
  its predecessor, and a non-firing emulation passes. Fix: slice from a `before` count (as
  vm.nix does) or key by the order id written for that phase (as phases E and F already do).
- Phase F picks `ls spool | head -1` as "the" order. With one order it is right; with a stray
  second order (a background exec_from_tmp, a boot-time leftover) it may pick the wrong one, and
  because `chattr +i` makes every order fail, the assertion still passes.
- `trip_exec` is `runuser -u alice -- /tmp/q/payload -c true`: the dropper is transient by design
  and the process is gone at drain. Correct for a file action; it means no test here ever
  exercises quarantine where the dropper is still alive (the executor binds to the inode, not the
  pid, so this is acceptable, but note it).
- The 2 GiB sparse timing `dt` is printed as "(soft)", not gated. Fine.
- All the restore and refusal checks (occupied, inode replaced, -to /etc, -to store, FIFO,
  symlink, /dev/null, /etc/passwd, unmapped rule) assert both the rc/phase AND the on-disk state of
  the target. These are real.

### 2.6 `tests/vm.nix` (module VM: own emulations must fire exactly their fixtures)

Rating: **fragile** today, for one reason that needs a run to confirm.

- `families` is every `tests/emulations/*.sh`, including the 102 `sigmahq_*.sh`. Those have no
  fixtures, so `expectedAll` gives them `[]`, the `unprovable` filter keeps them (`any` over an
  empty list is false), and the loop asserts banken's OWN rules fire NOTHING on each of them. At
  least three of them trip own rules by inspection:
  `sigmahq_base64_exec.sh` (`echo .. | base64 -d | bash` -> own `deobfuscate_and_run` and
  `pipe_to_shell`), `sigmahq_susp_execution_tmp_folder.sh` (exec of a /tmp copy -> own
  `exec_from_tmp`), `sigmahq_netcat_reverse_shell.sh` (`nc -e /bin/sh` -> own `reverse_shell`).
  The last commit that says "tests/vm.nix: green" (29f30fd) predates every sigmahq batch, and
  the last log line claiming `nix flake check` green (2026-11-02, testing swarm) predates batches
  3 to 6. Either vm.nix is red right now, or it has not been run since. One
  `nix build .#checks.x86_64-linux.vm -L` settles it. The same enumeration is in the distro
  matrix (2.9), so B1 there has the same problem.
  Fix: enumerate families from fixtures, not from the emulations dir (or exclude the `sigmahq_`
  prefix explicitly in both places), and add a fast Go test that every non-sigmahq emulation has
  at least one fixture.
- `BANKEN-EMUL-SKIP` is honoured silently: a family that skips is printed, not failed, and the
  module VM installs a fixed package list. If a tool goes missing from
  `environment.systemPackages` the family stops being proven and the test stays green. Only
  `gtfosudo`, `portscan`, `sniff` carry the marker; the VM has `nmap`, `tcpdump` and sudo via
  wrappers, so today nothing skips, but there is no "zero skips expected" assert as there is in
  sigmahq-emul.nix (which correctly treats a skip as a harness bug).
- TTP granularity: a family passes if ANY of its TTPs fires the rule. `revshell.sh` has three
  shapes (bash /dev/tcp, python socket, nc -e); if the python or nc selection in `reverse_shell`
  silently broke, the family still passes on bash /dev/tcp. 30 of the 61 own-rule emulations are
  multi-TTP. The fixtures are per-family too. Per-TTP proof would need one fixture event per TTP
  (which the fixtures mostly have) plus an assertion that every event in the fixture fires, not
  just one.
- The module-eval proofs (daemon unit byte-identical with enforce on/off, no helper by default,
  helper when armed, assertions fire with a positive control) are forced at eval time through the
  `# module-eval:` interpolation. This is clever and real; a broken invariant fails the build
  before the VM boots. Solid.
- Window-based attribution: each family is judged on the alert lines added between its run and
  its scan. Any background exec in that window (timers, tmpfiles) lands on the family. In a stock
  NixOS test VM this is quiet; it is a flaky-red source, not a false green.

### 2.7 `tests/switch.nix`, `tests/switch-floor.nix`, `tests/switch-restart.nix`

- `switch.nix`: **solid**. Audit off, so the alert can only come off the mimi stream; the port
  is unique and checked in the alert AND in mimi's own stream; OCSF class and rule name asserted;
  `--watch` and no timer asserted. Latency is measured, not gated. 20 s wait is generous.
- `switch-restart.nix`: **solid** on the one thing it checks. The grep for
  `"data_sources":["mimi"]` is a byte-exact JSON shape; a serialisation change turns it red,
  never green.
- `switch-floor.nix`: **fragile by design, and listed as a flake check**. It contains ZERO
  assertions: it prints the cursor, config, journal and alert grep, sleeps 12 s, prints again and
  exits 0. As a diagnostic it is useful; as `checks.x86_64-linux.switch-floor` it is a guaranteed
  green that the justfile's `integration` recipe and the flake comment present as "runs the live
  hokkaido shape". Either add the assertion (`reverse_shell` with `data_sources` mimi AND the
  auditd floor still firing) or move it out of `checks`.

### 2.8 `tests/sigmahq-emul.nix` (upstream SigmaHQ Linux set, named rule must fire)

Rating: **soft**, and the most honest harness in the tree about its own noise.

- Gates hard on the process_creation layer: the named rule(s) must fire, no other
  process_creation rule beyond `BACKGROUND` may fire; auditd/network twins are reported, not
  gated. A skip is a failure (correct: the image's package list is under test control).
- The expected map is hand-kept per family (as it must be: upstream rules have no fixtures here),
  so the twin lists are the oracle and will drift when SigmaHQ changes a rule; the pin
  (`r2026-07-01`, fetched by hash) makes that drift deliberate rather than silent. Good.
- Ambient floor comes from ONE benign run. Any rule that fired in that one window is excused for
  the whole run (`residual = fired - ambient`). Also `proc_creation_lnx_file_deletion` is both a
  BACKGROUND noise rule and the target of `sigmahq_file_deletion`, so that family can pass on a
  system `rm` landing in its window. Small, but it is a false-green shape.
- Window attribution again: a background exec that trips a process_creation rule outside
  `BACKGROUND` fails a random family. Flaky-red.
- It does not check that own rules stay quiet (that is vm.nix's job, see 2.6, where it is
  currently broken in the other direction).

### 2.9 Live distro matrix (`matrix_test.go`, `distrocheck/main.go`, `mimicheck.sh`, `sysmoncheck.sh`)

Rating: **soft**. The boot/install/report plumbing is well built; the detection objective
inherits the same enumeration bug as vm.nix and several objectives are proxy signals.

- `expectedRules()` globs every `emulations/*.sh` into `want[family] = []`, then adds fixture
  rules. The 102 `sigmahq_*` families therefore get an empty expectation and B1 runs them against
  the own-rule set expecting silence (same three counter-examples as 2.6). Unless the matrix has
  been run since batch 3 (the log's last 8/8 green predates it), B1 is red on every distro for
  those families. Note the README still says B1 "built"; the "status as of 2026-11-01" line is
  honest about the date.
- Vacuous pass: `TestMatrix` runs one subtest per `rep.Checks` entry. A report with ZERO checks
  passes the distro. Today that cannot happen because `run()` always emits A1 first, but
  `expectedRules` ignores glob errors, so a payload with no emulations yields no B1 subtests at
  all and nothing notices. Assert a minimum objective count (or compare `rep.Checks` ids to
  `objectives()`).
- B1 ordering/barrier: `runFamily` sleeps 1 s "to let auditd write", then scans. There is no
  `auditctl -m` barrier as in the KVM proofs. On a loaded guest (eight VMs in parallel, three at a
  time) a family's execve records can land after its scan: red (miss), not green, but it is the
  likeliest flake in the matrix. Use the same user-record barrier the VM proofs use.
- A2 "no config file": `containsRule(journal("err"), "reverse_shell")` after `runFamily("revshell")`
  with a `before` index into the journal. The journal index is a line count of
  `journalctl -p err -o cat`; if journald rate-limits or reorders, the slice is off. Low.
- A3 "the timer fires on its own": polls the journal for `pipe_to_shell` for 200 s after
  `runFamily("xmrig")` with the timer enabled. It never checks that the unit was started BY the
  timer (e.g. `systemctl show banken.service -p ActiveEnterTimestamp` vs the timer's
  `LastTriggerUSec`, or `InvocationID` attribution). A scan started any other way in that window
  (there is none today, but `scan()` is one call away) would pass it.
- A4/D1/D2: `systemd-analyze security` level, no AVC/AppArmor denial naming banken, no unexpected
  warning lines. These are reasonable but D2 only greps denials that NAME banken; a denial on the
  helper unit name or on `/usr/bin/banken` labelled differently would be missed. Also D2 reads
  `ausearch -ts boot` so a denial before auditd started is invisible.
- E1 (the whole Go suite in the guest, as root): this is the ONLY place the root-gated tests
  run (`requireCgroupV2Root`, the root-only immutable assertion in `TestStoredFileIsNeutered`),
  and the only place a root-vs-non-root split like the dry-run bug can surface. It runs by hand.
  Until the matrix is scheduled, every `os.Geteuid()`-gated assertion is effectively unrun
  between manual matrix runs. The response VM proofs cover the cgroup behaviour live, which
  softens this, but the unit-level F7/F8 tests are not those.
- M1-M5 (`mimicheck.sh`): M3 "probe loaded" = mimi alive and sink non-empty (fine). M4 ties the
  canary to `"name":"mimicanary"` (fine). M5 accepts ANY `reverse_shell` line with
  `data_sources ["mimi"]`, without the port; there is no earlier reverse-shell activity in the
  guest so it is correct today, but it is weaker than S4/S5 and than switch.nix, which pin the
  port. BTF absent is a FAIL for M2-M5 (recorded, not skipped): honest.
- S1-S5 (`sysmoncheck.sh`): S3 "banken --watch following the sysmon source" is `kill -0` one
  second after start, i.e. "did not crash in 1 s". S5 then proves the real effect, so S3 is a
  harmless proxy. The `SYSMON-SKIP` path exits 0 and is recorded in Info, never a check: an MS
  repo outage or a package rename silently removes S1-S5 from the matrix; a reader of the test
  output sees fewer subtests, not a skip. Consider an `S0` check that the skip reason is one of
  the documented ones.
- `parseStages` accepts `<id> PASS|FAIL <detail>` lines from stdout; an emulation or tool that
  happens to print a line starting with `M3 PASS` (none does) would be parsed. Theoretical.
- Report channel (raw virtio disk, JSON to first NUL, partial report after every check) is a
  good design: a guest that dies mid-run still reports how far it got, and a guest that never
  ran distrocheck is a `t.Fatalf` with serial tail, not a pass.

### 2.10 Emulations and fixtures as the oracle

Rating: **soft**. The project rule "no rule without a fixture" is enforced
(`TestEveryRuleHasAFixture`), which is more than most projects have. The gaps are structural:

- Two oracles, two semantics. `TestFixtures` (fast, per commit) is "at least one event in this
  file fires the named rule". vm.nix and B1 (slow, manual) are "the set of rules fired by the
  live emulation equals the set of expect-* files". A new rule that co-fires on an old emulation
  passes the fast oracle and breaks the slow one; that is the drift already seen, and it will
  recur on every new rule. A fast approximation exists: for each family with an emulation, run
  every event of every fixture of that family through the engine and assert the UNION of fired
  rules equals the family's expect-* set. It is not the live events, but it catches the
  co-firing class at commit time.
- Fixture events are hand-written (`"image": "/usr/bin/bash"`, pid 5000), not captured from a
  live run. The README says "the events a run produces are also saved as fixtures"; they are
  not (no capture path exists in any harness). So the fast oracle proves the matcher against
  what someone THINKS the parser emits. The parser goldens cover the parser separately; the two
  are never joined except in the VMs.
- 14 fixture families have no emulation at all (all `expect-none` baselines plus three
  `credential_file_read` variants: `dd_shadow`, `renamed_binary_shadow`,
  `renamed_useradd_shadow`). Every rule does have at least one live-emulated fixture, so no rule is
  fixture-only, but those three TTP shapes are replay-only.
- `netcat` and `password_cracker` (optional) and all `agent_*` + `honeytoken_access` (13 rules)
  are excluded from every live harness by the `unprovable` filter and proven by replay only;
  the enforce proof covers the two optional ones live under `optionalRules`. The exclusion is
  documented in three places consistently.
- The skip marker is a stdout string match (`"BANKEN-EMUL-SKIP" in out`); a script that prints
  the marker AND then runs its TTP would be skipped while still generating events that land on
  the NEXT family's window. None does today.

### 2.11 Go test layer (`just default` / CI)

Rating: **solid** for what runs per commit, with the environment caveat.

- Fuzz smoke: `2000x` per target, discovered via `go test -list` (new targets picked up). A
  count budget cannot race the deadline. 2000 executions is a smoke, not a search; the nightly
  300 s campaign is where crashers are found, and its corpus is cached per target. Note the
  smoke's `go test -list ... 2>/dev/null || true`: a package that fails to COMPILE lists no fuzz
  targets and the loop moves on silently; `gotestsum ./...` right after catches the compile
  error, so no false green, just a confusing order of failure.
- Goldens: parser (`-update`), OCSF (`-update-ocsf`), respond view (`-update`). All three are
  explicit-flag regeneration with "review the diff" in the comment; none regenerates on a miss.
  Good. OCSF goldens are produced from the fixture events through the real mapper, so they move
  with fixtures; `ocsf-validate` then runs the official validator over them, excluding the
  documented `nopid.*` case. `--fail-on-validation-errors` is captured into `rc` and gated.
  Solid, with the caveat that it validates mapper output on FIXTURE events; live alerts are E4,
  "to build".
- Skip guards (`internal/response/exec`): `requireCgroupV2Root` skips unless root AND cgroup v2
  AND mkdir under /sys/fs/cgroup works. In CI and on hokkaido as `claude` these ALWAYS skip.
  The quarantine immutable assertion is inside `if os.Geteuid() == 0`. These are the
  "t.Skip that silently never runs" class; they run only in E1. The equivalent behaviour IS
  proven live by response-freeze.nix and response-quarantine.nix, so the risk is a unit-level
  regression (F7 store logic, populated-0 wait) with the VM proof as the only net.
- `TestEveryRailReached` in `decide_test.go` asserts the suite exercises every Rail constant:
  a good pattern that the enforce scorecard should copy for its kill/deferred lists.
- `mutation` (gremlins on `internal/sigma`) is periodic, not gated: fine, but note the
  "tests catch regressions" claim rests on it being run.
- `-race -count=1` on every package per commit: no cache masking. `nix flake check` on
  hokkaido, by contrast, IS cached: a check whose inputs did not change is not re-run, so a
  "green flake check" after a product change in `internal/` is real (the package input changed),
  but after a change only in a sibling test file it is a cache hit. Not a false green, but a
  "did it actually run" question the reviewer should ask of any flake-check claim.

### 2.12 `tests/attackrange.nix` and `tests/bench.nix`

- `attackrange.nix`: a scorecard, not a gate; the test passes when the range completes. The
  scorer separates "on merit" from hits that are only `privilege_escalation_attempt`, which is
  the right honesty. Window attribution per atomic (drain scan, run, scan) has the same
  background-noise exposure as B1, which inflates "detected" slightly rather than deflating it.
- `bench.nix`: header says "NOT YET RUN". It copies JSON out; no assertion. Not a proof of
  anything yet, and should not be cited as one.

### 2.13 mimi: `tests/vm.nix`, `tests/kernels.nix`

Rating: **solid**, small and tight.

- Both assert the unit is `active`, `NRestarts == 0`, the sink exists and is non-empty, the
  canary exec appears with `process.name == mimicanary` AND `process.file.path ==
  /tmp/mimicanary` (the CO-RE-read field), and vm.nix also asserts `schema == mimi/2`.
- The crash-loop check is `sleep 3` then `NRestarts == 0` with `RestartSec = 2`. It catches an
  immediate crash (the 209/STDOUT regression it was written for). A crash after a few seconds
  of runtime (ring buffer, a late attach) would pass; the canary check afterwards partly covers
  that (the sink must still be growing when the canary runs), but a crash AFTER the canary is
  invisible. Re-read `NRestarts` at the end of the script.
- `kernels.nix` is three kernels (6.1, 6.6, 6.12); 5.15 was dropped at EOL. "Loads on any
  BTF-capable kernel" is exercised on nixpkgs kernels; the vendor-kernel evidence is the
  matrix's M3-M5, which is manual.
- mimi's GitHub CI runs fmt/clippy/`mimi-types` tests and a cargo build only. Neither VM check
  runs anywhere but by hand on hokkaido. No per-commit eBPF test exists.

## 3. Ratings table

| Harness | Rating | One-line reason |
| --- | --- | --- |
| `lib/enforce-spawn.nix` | solid | marker discipline and exec-opt lesson baked in; scan-done definition correct |
| `response-enforce.nix` | soft | kill proof real; X/X denominator tautological, no rule attribution, `browser_credential_access` in neither list, stale-order check is phase-only |
| `response-whackamole.nix` | soft | zero-collateral real; uid-0 / trusted "refused" = survived, pid-reuse optional |
| `response-freeze.nix` | solid | every assertion on the real cgroup/heartbeat/manifest effect |
| `response-quarantine.nix` | soft | thorough, but `latest_quar()` can inherit a prior phase; rename path is by-hand only |
| `vm.nix` | fragile | runs 102 sigmahq families with an empty own-rule expectation (likely red or unrun); skips silent |
| `switch.nix` / `switch-restart.nix` | solid | mimi-only source, port-pinned, byte-exact source check |
| `switch-floor.nix` | fragile | zero assertions, listed as a flake check |
| `sigmahq-emul.nix` | soft | honest noise model; single-run ambient floor and file_deletion double role |
| distro matrix (A-E) | soft | good plumbing; same sigmahq enumeration bug; 1 s sleep instead of a barrier; A3 does not attribute to the timer; vacuous pass possible |
| distro matrix M/S | soft | real integrations; M5 not port-pinned; S3 is "alive after 1 s"; SYSMON-SKIP removes objectives silently |
| emulations + fixtures | soft | every rule has a fixture, but fast oracle is at-least-one while live is set-equality; fixtures hand-written |
| Go layer (`just default`, CI) | solid | count-budget fuzz, explicit golden update, official OCSF validator; root-gated tests never run per commit |
| `attackrange.nix` | n/a | scorecard, not a gate (and says so) |
| `bench.nix` | n/a | not yet run, no assertions |
| mimi `vm.nix` / `kernels.nix` | solid | real CO-RE field asserted; crash-after-canary invisible; manual only |

## 4. Hardening list (highest false-green risk first)

1. **Stop running `sigmahq_*` emulations against the own-rule set with an empty expectation**
   (vm.nix line 20-21, `matrix_test.go` `expectedRules`). Enumerate families from fixtures or
   exclude the prefix in both; add a Go test that every non-sigmahq emulation has a fixture. Then
   run `nix build .#checks.x86_64-linux.vm -L` once to learn whether vm.nix is red today.
2. **Give `switch-floor.nix` an assertion or take it out of `checks`.** As it stands it is a
   permanent green in `nix flake check` and in `just integration`.
3. **Tie the enforce scorecard's lists to the rule tree** at eval time
   (`killRules ++ deferredRules == rules/`), fix the X/X print to use `len(killCases)` as the
   denominator, and assert the executed kill line's rule equals `c["rule"]`.
   `browser_credential_access` is the first rule this would have caught.
4. **Replace survival-as-refusal in whackamole** with a ledger assertion on the uid-0 and
   trusted-prefix victims (find the decision/action line for the pid, assert the rail). Make
   `reuse_hit` a gate with retries.
5. **Slice the quarantine ledger per phase** (`before` count or order id) instead of
   `latest_quar()`; pick the phase F order by the dropper's image path, not `head -1`.
6. **Add a fast set-equality oracle**: per family, the union of rules fired over all its fixture
   events must equal its expect-* set. This is the commit-time guard for the fixture-drift class.
7. **Make vm.nix fail on a skip** (as sigmahq-emul.nix does) since the VM's package list is
   under test control; keep the skip semantics only in the distro matrix.
8. **Barrier in distrocheck B1**: `auditctl -m <family>` + grep the audit log before the scan,
   replacing `time.Sleep(1s)`. Removes the likeliest matrix flake.
9. **Assert the stale reason** in the enforce boundary phase (`ErrStaleTarget` text in the
   failed line), and either assert or drop the always-True transient line.
10. **Attribute A3 to the timer** (`LastTriggerUSec` / unit `InvocationID`), and assert a
    minimum objective count per distro so an empty report cannot pass.
11. **Per-TTP proof**: assert every event of a multi-event fixture fires its rule (fast), and
    consider one marker per TTP in the emulations so the live harnesses can report which shape
    fired. Lower priority: the family-level pass is a real pass, just coarser than the emulation
    headers claim.
12. **Schedule the matrix** (or at least `nix flake check` + E1 on one distro) nightly on
    hokkaido via a systemd timer under the claude user, so the root-only and live-telemetry
    classes stop accumulating between manual runs. Pin M5 to the port like S4/S5.
13. mimi: re-read `NRestarts` at the end of both VM scripts.

## 5. Verdict for the deep review

Trust, and cite as evidence:

- `response-freeze.nix` (freeze/thaw/F7/F8) as proven live.
- `response-enforce.nix` for "a detected long-running victim is SIGKILLed via the real helper
  and the innocent survives", NOT for "48/48 rules" until item 3 lands; read the scorecard as
  "48 victims", with one rule (`browser_credential_access`) unaccounted for.
- `response-whackamole.nix` for zero collateral and for the masquerade-both-ways pair; treat
  "uid-0 refused" and "trusted sshd refused" as plausible-but-unproven until item 4; treat
  pid-reuse as proven on the recorded runs only.
- `response-quarantine.nix` for NEUTER under the real helper, restore round-trips, and every
  refusal guard; for RENAME only as by-hand operator tooling, which the header already says.
- `switch.nix` and `switch-restart.nix` for the mimi integration.
- The per-commit Go layer, including the fuzz smoke after the count fix, and `ocsf-validate` for
  the goldens.
- mimi's two VM checks, with the note that they are run by hand.

Treat with suspicion:

- `tests/vm.nix` and distro-matrix B1 until item 1 is done and a run is on record after it;
  today the likeliest state is red-or-unrun for the sigmahq families.
- `switch-floor.nix`: it proves nothing.
- Any "X/X" or "N refused" scorecard line: the gates behind them are mostly real, the printed
  numbers are partly tautologies.
- Any claim that rests on the distro matrix or `nix flake check` having run "recently": ask for
  the date and the commit; neither runs per commit, flake checks are cached by input, and the
  log's last green matrix predates the sigmahq batches 3 to 6 and the response work.
- `bench.nix` and `attackrange.nix` as proofs: they are instruments, by their own headers.

The product code has, on the evidence here, been more reliable than the harnesses that test it.
The harness failures cluster in three places: hand-maintained lists that nothing reconciles with
the rule tree (killCases/deferred, fixtures vs new rules, families enumerated from the wrong
directory), proxy signals printed as proofs (survived == refused, X/X with X on both sides, a
diagnostic listed as a check), and environment splits (root-only tests, KVM-only checks) that
only a manual run exercises. All three are cheap to close; items 1 to 5 above are an afternoon.
