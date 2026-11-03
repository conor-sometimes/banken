# Response actions -- research and validation

Status: **research, not a spec.** This doc does not design the subsystem. `response-actions.md`
already does that, thoroughly. This doc exists to do three things:

- check every external claim that design rests on against current, cited facts
- make the hard calls the spec left open or left implicit
- survey how real EDRs do Linux response, so banken's shape is a deliberate choice, not an accident

Read `response-actions.md` first. Section references like "spec 5.1" point into it.

Written against the tree at `59a319a` (2026-11-02), branch `distro-matrix-mimi`. Every kernel floor
and standards claim below carries a citation to a primary source. Where a source could not pin a
version exactly, that is said so. ASCII only, hyphens not dashes, on purpose (repo house rule).

The one-line verdict, up front: **the spec is correct and buildable as written.** The pid-reuse
handling is sound, and it is the crux - do not weaken it. banken response should stay **userspace**;
in-kernel enforcement is a different product and is correctly deferred. The two external standards
(OpenC2, D3FEND) map onto the existing action set cleanly. Adopt them as a thin shim and a docs
table respectively, not as a redesign.

---

## 1. Kernel primitives: verified floors, guarantees, failure modes

banken's own target is NixOS 26.05 (kernel 6.12 LTS line), which clears every floor below by a wide
margin. The floors matter for two reasons only:

- the honesty of the "portable static binary" story (a banken built for an older distro in the
  EDR-Telemetry comparison)
- runtime feature detection (the executor must degrade, not crash, on a kernel that lacks
  `cgroup.kill` or the v2 freezer)

Every primitive below is therefore gated at runtime by probing for the file/syscall, never by a
`uname` version compare. This is the same discipline systemd's freezer helper uses: it stats
`cgroup.freeze` rather than checking the kernel version. [systemd cgroup-util]

| Primitive | First kernel | What it guarantees | Failure mode / floor note |
| --- | --- | --- | --- |
| `pidfd_send_signal(2)` | 5.1 | signal delivered to the process the fd refers to, never a pid-number reuser | EBADF on a stale/closed fd; ESRCH if the process is reaped. [man pidfd_send_signal] |
| `pidfd_open(2)` | 5.3 | an fd that names one process for its lifetime; `poll`/`POLLIN` fires on its exit | ESRCH if pid already gone at open time. [man pidfd_open] |
| `PIDFD_GET_INFO` ioctl | ~6.13 | pid, ppid, and (with the right mask) process info read atomically off the fd, no `/proc` race | caller MUST check the returned mask has the requested bits; absent on 6.13.2 stable in one survey, so **probe, do not assume** on 6.13.x. [glibc pidfd.h commit] |
| cgroup v2 freezer (`cgroup.freeze`) | 5.2 | write `1` suspends the whole cgroup (TASK_FROZEN); write `0` resumes; survives SIGCONT; not undoable by the target | per-cgroup, not per-process (spec 5.2 "move then freeze"); gone on reboot; absent on a v1-only host (SIGSTOP fallback). [systemd cgroup-util] |
| `cgroup.kill` | 5.14 | write `1` SIGKILLs every task in the cgroup atomically, including would-be forks | not backported to older stable lines; fall back to per-pid pidfd kills over the frozen set (runc/libcontainer does exactly this). [containerd/cgroups#229] |
| `renameat2(2)` + `RENAME_NOREPLACE`/`RENAME_EXCHANGE` | 3.15 | atomic rename that keeps the inode (owner, mode, times, xattrs), fails rather than clobbering | EXDEV across filesystems (spec 5.4 neuter fallback); not all fs support the flags (ext4/xfs/btrfs/tmpfs do). |
| FS immutable flag on tmpfs (`FS_IMMUTABLE_FL`) | 6.0 | the neuter fallback's "cannot re-drop at this path" on tmpfs `/tmp`, `/dev/shm` | pre-6.0 tmpfs ignores it; ledger must record whether the bit took (spec 5.4 already does). |
| nftables `socket cgroupv2 level N` match | 5.13 | per-cgroup egress drop for the `isolate` action, resolved to a cgroup id at rule-load | the path is resolved at load, NOT matched as a string per packet: a rule for a not-yet-created cgroup fails with ENOENT, so create the quarantine cgroup before adding the rule. [netfilter list 2021] |
| Landlock (filesystem, ABI v1) | 5.13 | confine the responder itself: deny it everything but the paths it needs | ABI versions below; `landlock_restrict_self` is one-way (cannot be relaxed). [kernel landlock.rst] |
| Landlock network (TCP, ABI v4) | 6.7 | the responder can be denied all TCP except the SIEM/webhook allow-list | UDP is not covered; below 6.7 fall back to seccomp + a network namespace. [go-landlock] |
| seccomp-bpf | 3.5 | syscall allow-list for the responder (systemd `SystemCallFilter=`) | universally available; the primary confinement, Landlock is defence in depth. |

Landlock ABI ladder (for the responder's self-confinement, section 3):

- v1 filesystem (5.13)
- v2 `REFER`/cross-dir rename (5.19)
- v3 `TRUNCATE` (6.2)
- v4 TCP bind+connect (6.7)
- v5 IOCTL on device files (6.10+)

[kernel landlock.rst, go-landlock]. Query the ABI at runtime with
`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` and drop rights the kernel does
not know. The kernel docs mandate exactly this best-effort pattern.

**Takeaway for the spec.** No floor contradicts the design. Two additions the spec should fold in:

- the `isolate` cgroup must exist before its nft rule, which chains naturally after the freeze move
- `PIDFD_GET_INFO` is the right long-term way to read pid+identity atomically and retire the
  `/proc/<pid>/stat` read. But it must be probed on 6.13.x, so the `/proc` read stays as the portable
  path.

Both are small notes, not redesigns.

---

## 2. The pid-reuse problem: the correctness crux (validated)

This is the one place a mistake turns a security tool into a tool that kills innocent processes, so
it is worth stating the full argument and the verdict plainly.

**The problem.** banken reads a log after the fact. The pid in an alert is up to one scan interval
old (minutes). Three things can have happened to it by the time the responder runs:
1. the process exited and the pid is unused -> acting is a no-op at worst;
2. the process exited and the pid was **reused** by an unrelated process -> acting kills/freezes an
   innocent victim (the dangerous case);
3. the process is still alive -> acting is correct.

**Why `kill(pid)` is categorically wrong.** It cannot tell case 2 from case 3. The window is not
theoretical: on a busy host pids cycle through the whole `pid_max` range in seconds to minutes.

**Why pidfd ALONE is not enough -- the subtlety the spec gets right.** `pidfd_open(pid)` pins
*whatever process currently holds that pid*. If the original already exited and a reuser now holds
the pid, the pidfd faithfully pins the **reuser**. So a held pidfd defeats the race *between
verifying and acting* - a time-of-check-to-time-of-use (TOCTOU) race, where nobody can swap the
process out from under the fd once it is held. But it does **not** by itself establish that the
pinned process is the one the alert described. pidfd closes the micro-race. It does not close the
minutes-long latency gap.

**Why pid+starttime ALONE is not enough.** You can read `/proc/<pid>/stat` field 22 (starttime) and
compare it, but between that read and a subsequent `kill(pid)` the pid can still be reused (small
window, but the same class of bug you were trying to avoid).

**The sound construction is BOTH, in this order (spec 5.1, validated):**
1. `pidfd_open(pid)` -> fd. From here the fd names one process; ESRCH means already gone.
2. Read starttime and exe from `/proc/<pid>/...` (or `PIDFD_GET_INFO` where probed).
3. `poll(pidfd, POLLIN, 0)`: if it fires the process already exited and step 2 may have read a
   successor's `/proc` -- discard, treat as gone.
4. The fd's process is alive and unreaped, so its pid **cannot** have been reused; the step-2 read
   therefore describes that same process. Now check identity:
   - known starttime (eBPF/ESF/Sysmon sources): `|starttime - ref.starttime| <= 1 tick`;
   - unknown starttime (auditd/Laurel carry none): `starttime <= eventTime + skew`. This is a
     **proof, not a heuristic**: a pid is only reusable after its prior holder exits; the holder the
     alert described was alive at `eventTime`; any reuser was therefore forked after `eventTime` and
     fails the bound. The only thing that breaks it is a backwards wall-clock step, which is why
     there is a small skew tolerance and why the exe comparison is recorded.
5. Act through the fd: `pidfd_send_signal(fd, ...)`. Never `kill(2)`.

**Verdict: pidfd AND pid+starttime, not either/or.** pidfd is the pin that makes step 2's read and
step 5's signal race-free. The starttime bound is the identity proof that the pinned process is the
alert's process and not a reuser born in the latency gap. The spec's section 5.1 is correct as
written and must not be "simplified" to one or the other. The `PIDFD_GET_INFO` refinement (section
1) collapses steps 1-2 into one atomic read on new kernels, but changes nothing about the argument.

**The one honest gap, restated.** auditd and Laurel carry no starttime, so banken relies on the
`starttime <= eventTime` bound there. That is sound for process reuse, but it assumes a
monotone-enough wall clock between event and response. The mitigations are the skew tolerance and
the recorded (non-fatal) exe comparison, and refusal-on-doubt (`ErrStaleTarget`) is always preferred
to acting. A source that *does* carry starttime (mimi/eBPF) removes the assumption entirely. That is
a concrete argument for enriching process events from mimi over time (spec section 6).

---

## 3. Two-layer, two-process design: validated, with the testability argument sharpened

The spec splits a **pure `Decide(Input) Decision`** (in the scan, writes only JSON to a spool and
lines to a ledger, zero new privilege) from a **separate least-privilege `banken-respond` unit**
that re-decides from on-disk policy and executes. This is the right shape and the research only
strengthens the case for it:

- **"Should-kill is testable with nothing killed"** falls straight out of purity: `Decide` takes
  plain data (alert, policy, self-identity, kill-switch bool, budget, seen-set) and returns a
  verdict with no clock, no `/proc`, no fs. A fixture corpus (`tests/response/NAME.expect-ACTION.json`)
  proves the policy the same way the detection corpus proves rules, and a missing fixture fails the
  build. No process, no cgroup, no file is ever touched by the decision tests. This is banken's
  single biggest differentiator from every prior-art tool in section 6: **none of them can unit-test
  "would this alert kill?" without a live victim or a mock of the whole agent.**
- **The fake executor** (`exec.Fake`, not build-tagged, records ordered `Call`s, scriptable errors)
  makes the *protocol* testable on a Mac. The protocol it tests:
    - decided-before-requested
    - re-decide-downgrades-only
    - failed-line-on-every-error
    - idempotent-redrain
    - expired-not-executed
    - kill-switch-wins

  The real executor is exercised only in the root+cgroupv2 VM integration test on hokkaido.
- **The privilege split is the point, not overhead.** The scan parses untrusted bytes and holds
  `CAP_DAC_READ_SEARCH` and nothing that can signal/freeze/rename. Only `banken-respond` (path-unit
  triggered, `Type=oneshot`) holds `CAP_KILL`, `CAP_SYS_PTRACE`, `CAP_DAC_OVERRIDE/FOWNER`,
  `CAP_LINUX_IMMUTABLE`, cgroup write. A compromised scan can at most drop a forged work order, which
  the respond unit **re-decides from its own on-disk policy** and can only ever lower, never raise.
  This defence-in-depth against the parser is exactly what Wazuh's model lacks (section 6).

**One hardening the research adds: confine the responder itself.** The spec grants the respond unit
real capabilities; it should also wall it in so a bug in the 300-line executor cannot be turned into
general code execution. Concretely (section 1 floors permitting on the target, which 6.12 clears):
- seccomp `SystemCallFilter=` allow-list: `@system-service` plus exactly `pidfd_open`,
  `pidfd_send_signal`, `renameat2`, the cgroup/`ioctl` calls it needs, and nothing else (the spec
  already names this; make it a closed allow-list, not an extension of the default);
- Landlock filesystem rule restricting the responder to `/var/lib/banken/{spool,response,quarantine,
  evidence}`, `/sys/fs/cgroup/banken.quarantine`, and the policy's `allowPaths`, read-only on the
  policy file;
- Landlock TCP (6.7+) or a seccomp+netns fallback: the responder makes **no** network connections at
  all in v1 (it writes a ledger the scan/sinks ship), so deny all egress outright; revisit only if
  `isolate`/webhook-notify moves into the responder.

This is cheap. It is the same "confine the confiner" discipline the agent-containment flake already
applies to the claude user. And it closes the "what if the executor is the bug" question before it
is asked.

---

## 4. Reversibility, auditing, dry-run, interlocks (validated, nothing to add but emphasis)

The spec already has:

- reversible-first ordering (freeze is the recommended default, kill graduated per-rule after a week
  of observe)
- an append-only JSONL ledger (`decisions-*` from the scan, `actions-*` from the drain) with the
  undo handle on every executed line
- observe mode as the default, which records `Intended` plus which rail *would* have stopped an
  enforce action
- a `/run` kill-switch checked by both processes every time
- rate limits (per-run on the scan, per-hour on the drain, counted from the ledger)
- dedupe
- a built-in denylist (pid 1/2, init/sshd/auditd/dbus/banken itself, by name and by live re-check)
  that the policy can only add to, never subtract from

Research notes, in priority order:

- **Resolve open question 3 (uid-0): default-refuse, make it opt-in.** PLAN.md D7 already leans
  refuse-root-by-default; the research backs it. The built-in name denylist is necessary but not
  sufficient (names drift -- `sshd-session` arrived in OpenSSH 9.8, cited in the spec's own open
  question 8). A `response.allowRoot: false` default that refuses to act on uid 0 unless explicitly
  enabled per entry is a strictly stronger rail at a cost banken can afford, because the recommended
  first action is `freeze`, which is reversible: a frozen-by-mistake root daemon thaws. Pair with the
  name denylist (which still catches a root-owned sshd that `allowRoot` would otherwise expose).
- **Resolve open question 8 (name list vs cgroup): keep the name list, add a cgroup-unit rail.** On
  NixOS/systemd the sturdier identity is "is this pid in `sshd.service`'s cgroup / `init.scope`",
  which the executor can read from `/proc/<pid>/cgroup` at live re-check time. Do both: the portable
  name list (with a fixture per name, so a drift is loud) for the decision layer, and the
  cgroup-unit check as an additional executor-side refusal for the critical units. This is additive
  to the spec's existing "evaluated in Decide AND again in the executor" split.
- **Dry-run is already first-class** (`banken respond explain`, `banken check --policy`) and calls at
  most `Executor.Verify` (no action). Keep it; it is the operator's confidence-builder before the
  observe->enforce flip and the thing an incident writeup pastes from.
- **Boot-id on every ledger line** (already specced) is the right answer to "frozen state is gone
  after reboot": `list` marks dangling handles `not-applicable` rather than trying a thaw that would
  silently no-op.

---

## 5. Standards: OpenC2 as the command language, D3FEND as the control map

### 5.1 OpenC2 (OASIS)

OpenC2 Language Specification v2.0 defines 20 actions. A Command is
`{action, target, args?, profile?, command_id?}` and a Response is `{status, status_text?, results?}`.
[OASIS oc2ls v2.0]. The relevant actions and their normative meanings:

- `contain` -- "isolate a file, process, or entity so that it cannot modify or access assets or
  processes" (this is exactly freeze and process-level network isolation);
- `stop` -- halt a system or end an activity (kill, as the destructive stop);
- `delete` -- remove an entity such as data/files/flows;
- `restore` -- return to a known/earlier state (thaw, un-quarantine);
- `deny`/`allow` -- the packet-filter verbs (host/process network isolation);
- `investigate` / `copy` -- gather data (the reserved `collect`);
- `query` -- report state (observe-mode / `respond list`).

A dedicated **Endpoint Response (ER) actuator profile** is under development at
`oasis-tcs/openc2-ap-edr`, where OASIS separated the "endpoint response" part of EDR into its own
profile. Network isolation has a published **Stateless Packet Filter (SLPF)** profile
(`deny`/`allow`/`update`/`delete` over `ipv4_connection` five-tuples). [OASIS ap-edr repo; OASIS
oc2slpf v1.0]. The ER profile is still a working draft. So banken should map to the **language-spec
actions** (stable) and name the ER profile as the `profile` field, tracking it as it stabilises
rather than blocking on it.

**The call: adopt OpenC2 as a thin optional ingress shim, not banken's internal model.** banken's
internal `Action`/`Target`/`Decision` types stay as the spec defines them (they are what the fixtures
and ledger speak). Add, as a later phase, a small `internal/response/openc2` translator that accepts
an OpenC2 Command over the existing webhook/stdin seam and lowers it to a `Decision` (or rejects it),
and renders an OpenC2 Response from a ledger line. Mapping:

| banken action | OpenC2 action / target | OpenC2 profile |
| --- | --- | --- |
| `freeze` (process tree) | `contain` / `process` | ap-edr (ER) |
| `kill` | `stop` / `process` (or `delete`) | ap-edr (ER) |
| `quarantine` (file) | `contain` / `file` (restore = `restore`) | ap-edr (ER) |
| `isolate` (per-cgroup egress) | `deny` / `ipv4_connection`, or `contain` / `device` for host | slpf / ap-edr |
| `collect` | `investigate` or `copy` / `process`,`file` | ap-edr (ER) |
| observe / status | `query` / `features`,`process` | core |

Rationale: an orchestrator, or a SOAR (security orchestration, automation and response) platform,
drives banken with the standard verb set and no bespoke API. That is the entire point of OpenC2. But
banken's safety rails, policy and ledger remain the source of truth. An OpenC2 Command is just
another thing that proposes a `Decision` the rails still vet. The OpenC2 ingress must be subject to
the *same* `enforceSources`/mode/rails as any alert - a command is not a bypass. This keeps the
testable-decision core untouched.

### 5.2 MITRE D3FEND

D3FEND is the defensive counterpart to ATT&CK. banken's detections are ATT&CK-mapped, so mapping
each response to the D3FEND technique it realises is a cheap, recognisable docs win (standards.md
already lists it as "Docs, cheap"). Verified technique IDs (confirm each against d3fend.mitre.org at
write time -- third-party sources vary on a few):

| banken action | D3FEND technique | ID (verify) | Tactic |
| --- | --- | --- | --- |
| `kill` | Process Termination | D3-PT | Evict |
| `freeze` | Process Suspension | D3-PSUS | Evict |
| `quarantine` | File Eviction (file removal/isolation) | D3-FEV | Evict |
| `collect` (hash+manifest) | File Hashing / File Analysis | D3-FH / D3-FA | Analyze/Detect |
| `isolate` (per-cgroup / host egress) | Network Traffic Filtering / Broadcast Domain Isolation | D3-NTF / D3-BDI | Isolate |
| observe-mode ledger | Process/Network Analysis | D3-PA / D3-NTA | Analyze |

The honest framing for the docs: banken is an **Evict + Isolate** responder (post-event). It is
**not** a **Deceive** responder, nor an inline **Isolate-by-prevention** one (no exec-time block in
the timer model). That distinction is the same userspace-vs-eBPF point as section 6, stated in
D3FEND's own vocabulary.

---

## 6. Prior art: how real tools do Linux response, and where banken sits

| Tool | Linux response it does | How | What banken takes / rejects |
| --- | --- | --- | --- |
| **CrowdStrike Falcon** | network containment + process kill/file delete | "Contain Host" cuts all networking except the Falcon cloud and operator-listed internal IPs; kill/delete via Real Time Response (RTR), a logged remote shell | Validates **allow-list the management plane** (banken: allow-list the SIEM/webhook on `isolate`). banken has no cloud/RTR; its ledger is the "logged session". [CrowdStrike; ExtraHop/Netography] |
| **SentinelOne** | remediate + rollback; kill/quarantine | storyline-based remediate undoes an attack's changes; rollback is strongest on Windows (VSS); Linux is remediate/quarantine-centric | banken's **reversible-first + restorable quarantine** is the same instinct; banken does NOT claim filesystem rollback (honest: it quarantines and restores single files, not system state). |
| **Wazuh active-response** | stop process, delete file, firewall-drop | an `<active-response>` block binds a command + rule-id + timeout; agent runs a script; logs to `active-responses.log` | Closest architectural cousin. banken **improves on it** on exactly the two weak points: (1) Wazuh's script runs with the agent's privilege and has **no pid-reuse safety** -- banken splits privilege and uses pidfd+starttime; (2) Wazuh's "would this fire" is only testable by triggering it -- banken's `Decide` is pure-fixture-testable. [Wazuh docs] |
| **Falco Talon** | terminate pod, label, networkpolicy (calico/cilium), exec, drain | Kubernetes-native response engine on Falco alerts; `kubernetes:terminate` asks the orchestrator to stop a workload, not SIGKILL; netpol by label | Different niche (cluster orchestration, not host process identity). Validates "contain gracefully / reversibly" and label/policy-based isolation, but banken is **host-level** and must solve pid identity Talon delegates to k8s. [Falco Talon docs] |
| **osquery** | none (query only) | SQL over host state; response is bolted on by external tooling (Fleet, Kolide) | Confirms the clean split banken keeps: detection/telemetry is one concern, response another. banken keeps them in separate processes for the same reason. |
| **Tetragon / Cilium** | in-kernel enforcement: SIGKILL + return-value override at the syscall | BPF hooks that both decide and act in-kernel; docs state a bare SIGKILL "does not always stop the operation" (a kill during `write()` may still write) so Signal must be paired with Override to truly block | The reference point for the eBPF verdict (section 7). True *prevention* needs in-kernel; it is a different mechanism and a different product. [Tetragon enforcement docs] |

**Where banken sits.** It is a **userspace, post-event, host-level Evict/Isolate responder**. Its
differentiator is a **pure, fixture-testable decision** plus a **privilege-split executor** with
**correct pid identity**. No surveyed OSS tool has all three. Wazuh is the closest and lacks (1) and
(2). The eBPF tools do in-kernel prevention, which banken deliberately does not attempt (next).

---

## 7. Userspace vs eBPF enforcement: the honest verdict

**Verdict: banken response stays entirely userspace. In-kernel enforcement is a separate future
sibling, not bolted onto banken's scan.**

The argument:

1. **banken is cleanup, not prevention, by construction.** It reads a log on a timer after the fact.
   A response lands up to one interval after the event. In-kernel enforcement exists to stop an
   operation *as it happens* (Tetragon overrides the syscall return before the body runs). banken has
   already missed that window by design, so in-kernel machinery buys it **nothing** for the four
   response actions. kill/freeze/quarantine/isolate are all things you do to a process or file that
   already exists. Userspace pidfd/cgroup/renameat2/nft do them correctly and reversibly.

2. **In-kernel enforcement is a different, heavier mechanism with its own failure modes.** Tetragon's
   own docs show the subtlety: a SIGKILL from a BPF hook does not guarantee the in-flight operation
   is undone, so you must *pair* the signal with a return-value Override, and Override only works on
   functions annotated `ALLOW_ERROR_INJECTION` and (for security hooks) kernels 5.7+. That is a real,
   auditable-but-sharp mechanism that belongs to a resident, in-kernel product, not to a one-shot
   userspace scanner. [Tetragon docs]

3. **True prevention needs a resident daemon anyway, and that is already scoped elsewhere.** The spec
   (5.5) correctly rules out `fanotify` permission events in the timer model (nobody is resident to
   answer them) and reserves them for a future `--watch` mode. The memory note `mimi-listener-only`
   records the standing decision that in-kernel BPF-LSM *enforcement* is deferred as a someday
   separate sibling (task 1114), with mimi staying a pure listener. Those two facts line up exactly.
   If and when banken wants prevention, the path is a resident `--watch` mode. Even then the first
   choice is **fanotify permission events in userspace** (simpler, auditable, no `ALLOW_ERROR_INJECTION`
   dependency). BPF-LSM enforcement stays the "someday nuke" behind a hard design review, not a
   feature of the scan.

4. **The design tenets forbid it here.** "Simple is good", "no rough edges", and the containment
   tenet set (secure, auditable, comfortable, configurable) all point the same way: an in-kernel
   enforcer welded to a timer scanner would be the maximum of complexity for zero latency benefit.

So banken ships userspace for every response action. Prevention is a separate product shape
(resident `--watch`, fanotify-first). It is explicitly out of scope here and already has a home on
the task list. This is written into the phasing (section 8) as a non-goal, not an open question.

---

## 8. banken fit and phased rollout (confirming the spec, with the research folded in)

Flow (unchanged from spec section 2): `engine.Match -> Alert -> Dispatcher -> Responder.Respond`
(`Alert.Tags` is the selector) `-> Decide (pure) -> ledger "decided" -> if Action != none, write
work order to /var/lib/banken/spool -> ledger "requested"`. Then the `banken-respond.path` unit
fires `banken-respond.service`, which `re-Decide`s from on-disk policy and executes via the
`Executor`, writing `executed`/`failed`/`expired`. Two processes, one binary, scan sandbox
untouched.

NixOS module option shape (confirming PLAN and spec). The module derives the respond unit's
capability set from which actions the policy enables, so a policy with no `quarantine` entry gets no
`CAP_LINUX_IMMUTABLE`:

```nix
services.banken.response = {
  enable = false;                       # off by default; enabling renders banken-respond.{service,path}
  mode = "observe";                     # observe | enforce
  allowRoot = false;                    # research call: default-refuse uid 0 (section 4)
  killSwitchPath = "/run/banken/disable";
  minLevel = "high";
  enforceSources = [ "auditd" "laurel" ];
  rateLimit = { perRun = 3; perHour = 10; };
  confineResponder = true;              # research add: seccomp allow-list + Landlock on the respond unit (section 3)
  quarantine.dir = "/var/lib/banken/quarantine";
  quarantine.allowPaths = [ "/tmp" "/var/tmp" "/dev/shm" "/home" "/root" "/opt" ];
  policyFile = ...;                     # the response: YAML block, validated at build by `banken check --policy`
};
```

Phased rollout (spec section 12, with the research decisions attached):

0. **Prerequisites** -- `Event.PID/PPID/ProcessStart` + parser plumbing + goldens; `Rule.Tags` ->
   `Alert.Tags`. Pure additions, shippable alone.
1. **Decision layer in observe mode** -- `internal/response` (policy, pure `Decide`, ledger,
   responder), `tests/response/` corpus + harness, `banken check --policy`. Nothing acts; the ledger
   accumulates real would-have-done lines. Includes `allowRoot` default-refuse and the uid-0/cgroup
   rails.
2. **Executor: freeze/thaw/kill** -- `exec/` (pidfd+starttime identity, cgroup freezer, `cgroup.kill`
   with per-pid fallback), spool, `banken respond drain|list|thaw|explain`, `banken-respond.{service,
   path}` **with the seccomp+Landlock self-confinement**, the root+cgroupv2 VM integration test.
   `enforce` becomes real.
3. **Quarantine/restore** -- `renameat2` primary, EXDEV neuter fallback + immutable bit, restorable
   manifest sidecar. YARA scans the quarantined artifact after (PLAN's ordering).
4. **Later** -- `collect` (evidence snapshot), `isolate` (per-cgroup nft egress drop, cgroup-before-
   rule), the **OpenC2 ingress shim** (section 5.1) and **D3FEND docs table** (section 5.2), NixOS
   capability-set derivation. Prevention / `--watch` / fanotify is explicitly a **non-goal of this
   subsystem** (section 7), tracked separately.

---

## 9. Decisions made in this research (summary)

1. **pid identity: pidfd AND pid+starttime, never either alone.** pidfd closes the verify/act race.
   starttime closes the latency-gap reuse. The spec is correct; do not simplify. `PIDFD_GET_INFO` is
   a per-kernel-probed refinement, not a dependency. (Section 2.)
2. **userspace, not eBPF, for all response actions.** banken is post-event cleanup; in-kernel
   enforcement is a separate resident product (fanotify-first, BPF-LSM deferred per task 1114).
   (Section 7.)
3. **kernel floor: probe at runtime, do not version-gate.** banken's own target (6.12) clears every
   floor; the floors are for the portability story and graceful degradation (v1-host SIGSTOP
   fallback, missing `cgroup.kill` per-pid fallback, pre-6.0 tmpfs no-immutable). (Section 1.)
4. **confine the responder itself**: seccomp closed allow-list + Landlock fs rule + deny all egress
   on the respond unit. New, cheap, closes "what if the executor is the bug". (Section 3.)
5. **uid-0: default-refuse (`allowRoot: false`), opt-in per entry; keep the name denylist and add a
   cgroup-unit rail.** Resolves spec open questions 3 and 8. (Section 4.)
6. **OpenC2: adopt as a thin optional ingress/egress shim, not the internal model.** Map to stable
   language-spec actions (`contain`/`stop`/`delete`/`restore`/`deny`) and name the ER profile. Do
   not block on the draft. Commands are vetted by the same rails as alerts. (Section 5.1.)
7. **D3FEND: a docs table** mapping each action to its technique (D3-PT/PSUS/FEV/NTF). Cheap
   credibility; frames banken honestly as Evict+Isolate, not prevention. (Section 5.2.)
8. **Leave the rest of the spec as written.** The two-layer/two-process design, the ledger, observe
   default, kill-switch, rate limits, fixture corpus, and quarantine TOCTOU handling are all sound
   and need no change.

Spec open questions this research does **not** close (they are Conor's, not research calls):

- 1 (cgroup home: plain dir vs transient scope -- lean plain, touches hokkaido unit layout)
- 4 (two units vs one -- research strongly favours two)
- 5 (composite actions -- defer until `collect` exists)
- 6 (per-mount quarantine dir -- lean against, it is a rough edge)
- 7 (ledger location/retention)
- 10 (attack-range "expected response" column -- lean yes, same corpus idea)

---

## Sources

- OASIS OpenC2 Language Specification v2.0 -- https://docs.oasis-open.org/openc2/oc2ls/v2.0/oc2ls-v2.0.html
- OASIS OpenC2 Endpoint Response (EDR) actuator profile -- https://github.com/oasis-tcs/openc2-ap-edr
- OASIS OpenC2 Stateless Packet Filter (SLPF) profile v1.0 -- https://docs.oasis-open.org/openc2/oc2slpf/v1.0/
- man pidfd_open(2) (Linux 5.3) -- https://repo.or.cz/man-pages.git man2/pidfd_open.2
- man pidfd_send_signal(2) (Linux 5.1) -- https://sources.debian.org/src/manpages/ man2/pidfd_send_signal.2
- glibc PIDFD_* / PIDFD_GET_INFO header commit -- https://git.almalinux.org/.../include/uapi/linux/pidfd.h
- cgroup v2 freezer / cgroup.kill -- systemd cgroup-util (freezer file) and containerd/cgroups#229 (cgroup.kill 5.14) -- https://github.com/containerd/cgroups/issues/229
- nftables socket cgroupv2 level match (5.13) -- netfilter list, https://lore.kernel.org/all/20210818183857.GB3505@salvia/T/
- Landlock userspace API / ABI ladder -- kernel Documentation/userspace-api/landlock.rst; go-landlock https://pkg.go.dev/github.com/landlock-lsm/go-landlock/landlock
- Tetragon enforcement (signal + override, kernel floors) -- https://tetragon.io/docs/concepts/enforcement/
- Wazuh active response -- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/
- Falco Talon response engine -- https://falco.org/blog/falco-talon-v0-1-0/
- CrowdStrike Falcon network containment (Linux) -- https://www.crowdstrike.com/ ; ExtraHop/Netography integration notes
- MITRE D3FEND -- https://d3fend.mitre.org (verify D3-PT, D3-PSUS, D3-FEV, D3-NTF, D3-BDI, D3-FA/FH)
