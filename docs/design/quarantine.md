# Quarantine - the file response action

Status: **design, partially implemented.** Written 2026-11-02 against `5febddb` (branch
`distro-matrix-mimi`). The executor already has a `Quarantine`/`Restore` pair
(`internal/response/exec/exec_linux.go:285-391`): `renameat2(RENAME_NOREPLACE)` into a store,
EXDEV neuter fallback with the immutable bit, a sidecar manifest, and a restore with an inode check.
**It is gated behind `Config.Enforce`, which is false everywhere** (`exec.go:6-20`). This doc is the
design the built code is measured against: what quarantine is for, what it must never touch, how it
stays reversible, and why it is designed together with YARA. Where the code at `5febddb` falls
short of the design, the gap is listed in section 10 with a line number and a seeded task; no code
is changed here.

Read `response-actions.md` section 5.4 first (the primitive) and `yara-integration.md` section 4.2b
(the quarantine-time scan contract). The YARA engine itself has since been redirected to a sidecar
process in the mimi mould (tasks `8be69247`, `4c59d403`: separate binary, own sandbox, first cut a
`yr` subprocess behind the same banken-side interface); nothing here depends on which engine shape
lands, only on the interface in section 6.

The one-sentence shape: **quarantine takes the *file* an alert pointed at out of the attacker's
reach without destroying it - moved or neutered, hashed, manifested, scanned - and can put it back
exactly, so the worst a wrong quarantine does is a `restore`.**

---

## 1. What quarantine is, and is not

**It acts on a file, never a process.** `kill`/`freeze` take a `ProcessRef`; `quarantine` takes a
`FileRef` (`internal/response/types.go:82-84`). The policy loader refuses a quarantine entry with
`scope:` and a process action with `target:` (`policy.go:219-232`).

**It is the action that survives fire-and-exit.** Most droppers finish before a post-event
responder can reach them (`enforcement-testing.md` section 4.2); the *dropped file* does not. A
payload fetched into `/tmp`, a `.so` written for `LD_PRELOAD`, a user unit written for persistence,
a loot archive staged for exfil: each outlives its writer, and each is what the next stage needs.
Taking the file away is the one response that lands *before* the next stage even when the process
response lands after the first.

**It is reversible by construction.** Rename keeps the inode: owner, mode, timestamps, xattrs,
ACLs and the security label move with it and nothing is copied. Neuter changes two things (mode,
immutable flag) and records both. Restore reverses exactly what was done and refuses to clobber
whatever now sits at the path (`RENAME_NOREPLACE` again).

**It is evidence preservation, not deletion.** banken never unlinks. A quarantined file is kept,
root-only, immutable, hashed, with a manifest, until an operator purges it. "Delete the malware" is
what the operator does *after* reading the manifest and the YARA verdict, with `purge`.

**What it is not:**

- Not prevention. The file was written minutes ago; whatever read it in the meantime has read it.
- Not removal. `nlink > 1` means other names still reach the inode; a reflink or an earlier `cp` is
  a different inode banken cannot find. The manifest records `nlink`; the ledger says so.
- Not a process stop. Renaming a running executable does not stop it (Linux has no `ETXTBSY` on
  rename). Pair with `freeze`/`kill` (section 2.3) and record who had it open (section 4.4).
- Not a scanner. banken does not crawl. The only file it ever quarantines is one an audited event
  named (`TargetFilename` or `Image`), under paths the operator allowed.

---

## 2. When: which alerts map to quarantine, and how it relates to kill/freeze

### 2.1 Selection is operator policy, by rule or by tag

Same contract as every response action (README security model item 4): a rule emits a tag, the
local policy maps tag or rule name to the action. `quarantine` is a *reversible* action, so a
**tag-only selector may map to it** (`policy.go:96-100`), unlike `kill`. A rogue remote rule can at
worst earn a quarantine, which restores.

The file-dropping detections in the baseline and their natural artifact:

| Rule (banken baseline / SigmaHQ) | Tag | `target:` | Artifact |
| --- | --- | --- | --- |
| `download_ip_to_tmp` | `attack.t1105` (ingress tool transfer) | `targetFilename` | the fetched payload in `/tmp` |
| `masquerading` (the `cp /bin/sh .../crond` branch) | `attack.t1036.005` | `targetFilename` | the copied binary under a daemon name |
| `persistence` (user unit / rc edit) | `attack.persistence`, `attack.t1543.002`, `attack.t1546.004` | `targetFilename` | the unit file or rc fragment in `~/.config` |
| `ldpreload` | `attack.t1574.006` | `targetFilename` | the `.so` in a scratch dir |
| `tmpexec` (exec from `/tmp`, `/dev/shm`) | `attack.t1059` | `image` | the executable that ran |
| `stage` (loot archive) | `attack.t1560.001` | `targetFilename` | the archive before exfil |
| `gitpersist` | `attack.t1546` | `targetFilename` | the hook script |
| SigmaHQ `proc_creation_lnx_wget_download_suspicious_directory` | `attack.t1105` | `targetFilename` | as above |

Recommended default policy posture: **tag `attack.t1105` -> quarantine `targetFilename`** (the
dropper tag, the clearest artifact, the lowest false-positive risk under the safety rails of
section 4), everything else pinned by rule name as the operator gains confidence from the
observe-mode ledger. `image` targets are more dangerous (section 4.2: the image is often an
interpreter, which the never-touch list blocks, or a legitimate tool the user ran from `/opt`) and
should start rule-pinned.

### 2.2 The decision layer already has what it needs, with one addition

`Decide` builds the `FileRef` from `TargetFilename` or `Image` per the entry's `target:`
(`decide.go:209-214`), checks never-touch prefixes and `allowPaths` (`decide.go:142-153`), and
dedupes on path (`decide.go:220-228`). Rails 2-3 and 6-9 apply unchanged. One addition: the
executor's owner rail (section 4.2) needs the alert's user, so `FileRef` gains it:

```go
type FileRef struct {
    Path string `json:"path"`
    User string `json:"user,omitempty"` // the alert's User, for the owner rail (section 4.2)
    UID  int    `json:"uid,omitempty"`  // when the source carried a numeric uid; 0 = unknown, not root
}
```

Pure data, no new rail in `Decide` (it cannot stat; the owner check is executor-side by nature).

### 2.3 Relationship to kill and freeze: the composite problem

The incident shape for a dropper is *stop the process, then take the file, then ask what it is*:

```
collect (snapshot /proc of the dropper, if alive)
  -> freeze (so nothing rewrites or re-drops)
    -> quarantine (the file can no longer change; hash is final)
      -> yara (what is it)
        -> operator: thaw+restore (false positive) | kill+purge (confirmed)
```

Today a rule maps to **one** action: `matchEntry` returns the first matching entry
(`decide.go:184-195`). Two entries on the same rule cannot both fire. The spec left this open
(spec 13.5); this doc resolves it for quarantine's sake: **an entry may carry `actions: [..]` as
well as `action:`, executed in the fixed canonical order above**, never in the order written.
Canonical order is a load-time normalisation (`[quarantine, freeze]` becomes `[freeze, quarantine]`),
`kill` is only valid last and never together with `freeze` (a frozen tree is what you kill if you
decide to; freezing then killing in one entry is a kill with extra steps), and every member is
subject to its own rails (`kill` still needs `rules:`; a tag-only `[freeze, quarantine]` is fine).
The ledger gets one `decided` line per member with the same alert id. This keeps `Decide` pure (it
returns `[]Decision` or a `Decision` with `Steps`) and keeps the fixtures readable:
`dropper.expect-freeze+quarantine.json`.

Until composites land, the guidance is honest: an operator chooses **quarantine** for dropper rules
(the file outlives the process; `gone` is the common process outcome anyway) and **freeze** for
process-centric rules (reverse shells), and accepts that one rule gets one.

---

## 3. Mechanism

### 3.1 Store layout

```
/var/lib/banken/quarantine/              0700 root  (StateDirectory of banken-respond)
  <id>/                                  0700 root  id = 8 bytes unix-nanos + 4 random, hex (exec_linux.go:732)
    manifest.json                        0400 root  written FIRST, immutable after finalisation (3.4)
    file                                 0000 root  the inode, moved here (rename method only)
    yara.json                            0400 root  the scan verdict, written by the YARA step (section 6)
    restored.json                        0400 root  tombstone: when, by whom, to where (section 5)
```

Same filesystem as the target or the neuter path is taken (3.3). The store is never under a path
the policy may quarantine from (`allowPaths` must not contain or be contained by `quarantine.dir`;
load error), so quarantine cannot recurse into itself.

### 3.2 Primary: rename, same filesystem (as built, with two changes)

Steps, as `exec_linux.go:285-352` does them, with the design's deltas marked **(new)**:

1. Path rails: never-touch prefixes, `allowPaths` (`:287-292`). Re-checked here even though `Decide`
   checked them: the executor trusts nothing in the work order.
2. `open(path, O_PATH|O_NOFOLLOW|O_CLOEXEC)`, `fstat`, require `S_IFREG` (`:296-307`). A symlink,
   directory, device, FIFO or socket is `ErrStaleTarget`, never acted on. Record
   `(dev, ino, mode, uid, gid, size, mtime, nlink)`.
3. **(new)** Safety rails on the inode (section 4): owner, root-owned, in-use, size. Any refusal is
   `ErrDenied` with the rail named, before anything is written.
4. `sha256` through `/proc/self/fd/<fd>` (`:308`, `:686-699`) - **(new)** bounded by
   `quarantine.maxFileBytes` (default 256 MiB); over the cap the file is still quarantined (rename
   costs nothing) but `sha256` is recorded as `"unhashed: size"` and YARA is skipped. The hash is
   for the record and for YARA, not a precondition of taking the file away.
5. **(new)** Write `manifest.json` *first*, with `method: pending` (3.4). If this write fails, stop:
   no manifest, no quarantine.
6. `renameat2(AT_FDCWD, path, AT_FDCWD, <id>/file, RENAME_NOREPLACE)` (`:324`).
7. Post-rename `(dev, ino)` recheck against step 2; on mismatch rename straight back and refuse
   (`:330-335`). This is the microsecond TOCTOU the spec describes and the code closes.
8. **(new)** Neuter the stored inode: `fchmod(fd, 0)` and set `FS_IMMUTABLE_FL` on it. The store is
   already root-only, but a stored `0755` dropper that root can `./file` by accident is a rough
   edge; `0000` + immutable makes the stored artifact inert to everyone including a careless root
   shell, and `restore` re-applies the recorded mode. `ctime` changes; the pre-neuter stat is in
   the manifest.
9. Finalise the manifest (`method: rename`, the post-rename stat, `immutable: true`), `fsync`,
   `fchmod(0400)`, set immutable on the manifest too.
10. Ledger `executed` with the handle (`Undo = <id>` dir), `method`, `sha256`, `inUse`, `nlink`.

### 3.3 Fallback: EXDEV, neuter in place (as built, acting on the fd)

`/tmp` is tmpfs on most hosts and `/var/lib` is not, so for the single most common artifact the
rename fails with `EXDEV` and the file stays where it is. The design: never copy (not atomic, and
the copy doubles the evidence surface - spec 5.4), neuter in place.

- `fchmod(fd, 0)` and `ioctl(fd, FS_IOC_SETFLAGS, flags|FS_IMMUTABLE_FL)` **on the fd from step 2**,
  never by path. The code at `exec_linux.go:340-341` re-resolves `path` for both (`os.Chmod(path,
  0)`, `setImmutable(path)` -> `chattr` opens by path at `:568`); an attacker who swaps the
  directory entry between the `fstat` and the `chmod` gets an innocent file neutered. The fd
  already exists; use it. `chattr` needs an `O_RDONLY` fd for the ioctl (an `O_PATH` fd cannot
  ioctl) - open `/proc/self/fd/<opathfd>` `O_RDONLY` as `sha256OfFd` already does (`:689`), same
  inode by construction.
- After the neuter, `fstat` again and confirm `(dev, ino)` and `mode == 0`; record
  `immutable: <bool>` honestly (tmpfs before 6.0 ignores the flag - research section 1).
- Manifest `method: neuter`, with the same manifest-first ordering; `file` is absent in the store
  dir. The quarantined inode is still at its original path, unreadable, unexecutable, undeletable
  without `CAP_LINUX_IMMUTABLE`, and - the point - **the attacker cannot re-drop at the same path**
  because the name is taken by an immutable file.
- Honest limit: a `0000` file still owned by the attacker can be `chmod`ded back by its owner. So
  when the immutable bit does not take (tmpfs before 6.0, or a filesystem without flags support)
  and the file is not root-owned, neuter is **not** a quarantine; the ledger records `neuter-weak` and the
  journal line says so. The operator's fix is a quarantine dir on the same filesystem
  (`quarantine.dirs: {"/tmp": "/tmp/.banken-quarantine"}` - spec 13.6 counted a per-mount dir a
  rough edge; it remains opt-in, never default).

### 3.4 Manifest-first ordering

As built, the manifest is written *after* the rename and a failure is a logged warning
(`exec_linux.go:347-349`). A full disk, a permission typo or a crash in that window leaves a moved
file with no record of where it came from: evidence with no chain and no way back. Design: the
manifest is written and fsynced **before** the rename with `method: pending`; the rename happens;
the manifest is finalised. A crash leaves either (pending manifest, file still at origin: nothing
happened, the drain's retry sees `pending` and starts over) or (pending manifest, file in store: the
retry sees `pending` + a `file` entry, verifies `(dev, ino)` against the manifest, and finalises).
Both are recoverable from the store alone, without the ledger.

### 3.5 The manifest

```json
{
  "id": "0189f3b2c9d1e4a7b8c0d1e2",
  "version": 1,
  "method": "rename",                         // rename | neuter | pending
  "origPath": "/tmp/.x/payload",
  "stat": { "dev": 64769, "ino": 1310772, "mode": 33261, "uid": 1000, "gid": 100,
            "size": 48212, "mtime": "...", "ctime": "...", "nlink": 1 },
  "owner": { "user": "alice", "group": "users" },          // names resolved at quarantine time
  "xattrs": { "security.selinux": "...", "user.foo": "..." }, // for the record; rename preserves them
  "capabilities": "",                                      // security.capability if set (a setcap binary!)
  "sha256": "9f2c...",                                     // or "unhashed: size"
  "immutable": true,                                       // whether FS_IMMUTABLE_FL took (store or in place)
  "inUse": [ { "pid": 4242, "exe": true, "mapped": false, "fd": true } ],  // section 4.4
  "alert": { "ledgerId": "...", "rule": "download_ip_to_tmp", "level": "high", "source": "auditd",
             "user": "alice", "time": "...", "policy": "sha256:..." },
  "time": "2026-11-02T06:12:03Z",
  "bootId": "...",
  "banken": "0.5.0"
}
```

Written once. State that changes later (restored, purged, scanned) lives in its own file beside it
(`yara.json`, `restored.json`) and in the ledger, so the original record is never rewritten and can
be made immutable. `version` lets a future manifest shape be read by an older `restore`.

---

## 4. Safety: what quarantine must never touch

The rails run in the executor against the **live inode**, after the decision layer's path rails.
Each is a refusal with a named reason, never a silent skip, and each is a policy knob with a
conservative default - a request to relax one is a config change the operator deploys.

### 4.1 Paths (exists)

Never-touch prefixes (`/nix/store`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/etc`, `/boot`, `/proc`,
`/sys`, `/run`; `exec_linux.go:52-55`, `policy.go:105-108`) are built in and cannot be allowed
through; `allowPaths` must be absolute and outside them (load error otherwise). Default
`allowPaths`: `/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/root`, `/opt`. The store itself and the
spool/ledger dirs are refused (recursion guard, 3.1).

**Gap:** `/dev` is not on the never-touch list but `/dev/shm` is allowed; a device node under
`/dev` is caught by the `S_IFREG` check, not the prefix. Fine, but add `/dev` to never-touch with
`/dev/shm` carved out so the intent is in the list, not in a side effect of `fstat`.

### 4.2 Ownership: the file must be the alert's user's, or scratch

The single strongest rail, and the one that defuses the threat model in section 9. **A file is
quarantinable only if its owner uid equals the alert's uid, or the file lies under a scratch prefix
(`/tmp`, `/var/tmp`, `/dev/shm`).** Otherwise `ErrDenied: owner mismatch`. Policy:
`quarantine.allowForeignOwner: false`.

Why: an unprivileged attacker can make banken *see* an innocent file by reading it (an auditd watch
on `/opt/app` records the open, a `file_event` rule fires with `TargetFilename: /opt/app/config.yml`).
If that rule maps to quarantine, the attacker has quarantined the app's config with a `cat`. With
the owner rail, they can only quarantine files they own - which they could already delete.

**Root-owned files are refused outright** unless `quarantine.allowRootOwned: true`, a separate knob
from the process `allowRoot` because the semantics differ (a root-owned file under `/opt` is almost
always a package or an admin's install; a uid-0 *process* is often malware). Default false.

### 4.3 Package-owned and system-critical files

On NixOS everything installed is under `/nix/store` (never-touch) and reached through symlinks
(`O_NOFOLLOW` refuses the link; the target is never-touch). On FHS distros `dpkg -S`/`rpm -qf` are
too slow and too distro-specific for a 300-line executor; the never-touch prefixes cover the package
trees and the owner + root rails cover `/opt`. What remains is honest: a root-installed app under
`/opt` or `/home/svc` with `allowRootOwned: true` set by an operator is on the operator. The lint
(section 7) warns when a policy enables both `allowRootOwned` and an `image` target.

### 4.4 Files in use: executing, mapped, open

Before acting, walk `/proc/[0-9]*/` once and compare `(dev, ino)` against each process's `exe`
readlink target, its `map_files/` entries (or `maps` device:inode columns) and its `fd/` targets.
The result is the `inUse` list in the manifest, with the pid and *how*.

Policy `quarantine.inUse: refuse | proceed`, default **`refuse`**:

- `refuse`: a file that is executing or mapped is not quarantined; the ledger says `in use by pids
  [...]` and names the pairing (`freeze` first). Rationale: quarantining a running binary is a
  half-measure that *looks* like a response (the ledger says `executed`) while the process runs on,
  and the rename changes `/proc/<pid>/exe` to point into the store, confusing every other tool.
  Open-for-write only (`fd`, not exe/mapped) is allowed under `refuse` too but recorded, because
  the dropper writing the file is the normal case and the file still needs taking; the hash is
  marked `provisional` and re-computed at `list` time (section 5).
- `proceed`: quarantine regardless, record the pids. For operators who run `[freeze, quarantine]`
  composites and want the file even when the freeze failed.

The walk needs `CAP_SYS_PTRACE` for other users' `exe`/`map_files` (the responder has it for the
process rails already - spec 8). It costs one `/proc` pass per quarantine, which the rate limit
bounds.

### 4.5 Size and kind

`S_IFREG` only (exists). `maxFileBytes` bounds the hash and the YARA scan, not the rename (3.2 step
4). A sparse file reports `size` from `fstat`, so a 1 TiB sparse dropper is "unhashed", moved, and
scanned by nobody - recorded as such. An `nlink > 1` file is quarantined (one name removed) and
flagged `otherLinks: n-1`; banken does not search for the other names.

### 4.6 The executor's own hygiene

The store dir is created `0700` and the manifest `0400`; the responder unit's `ReadWritePaths` is
exactly the store + `allowPaths`; `CAP_LINUX_IMMUTABLE` is granted only when a quarantine entry
exists (spec 8). A quarantine never follows a symlink (`O_NOFOLLOW` on the final component; the
intermediate-symlink residual is the same as YARA's, `yara-integration.md` 5.1 item 3, closed by
`openat2(RESOLVE_NO_SYMLINKS)` when `x/sys` is accepted, and partially mitigated here by the
never-touch + owner rails: a symlinked parent can only redirect into a file the attacker owns or a
scratch file).

---

## 5. Restore, list, purge: the operator surface

```
banken respond list [--since 24h] [--kind quarantine]
  0189f3b2  quarantine  rename   /tmp/.x/payload  alice  48 KiB  sha256 9f2c..  yara: 2 hits (MAL_XMRig_Jan24, ..)  in-use: -   state: held
  0189f3c0  quarantine  neuter   /dev/shm/x.so    alice  12 KiB  sha256 1a..    yara: clean (forge-core 2026-10)   in-use: 4242(exe) state: held (neuter-weak)
banken respond show <id>            # the manifest, yara.json, ledger lines, verbatim
banken respond restore <id> [--to PATH] [--force]
banken respond purge <id> | --older-than 90d [--yara-clean-only]
```

**Restore** (`exec_linux.go:354-391` as built, with deltas):

1. Read the manifest. `method: pending` -> finish or roll back (3.4), then re-evaluate.
2. `rename`: `fstat` the stored `file`; require `(dev, ino)` **both** equal the manifest (the code
   checks `ino` only, `:371`); clear the store immutable bit; `fchmod` the recorded mode;
   `renameat2(store, origPath, RENAME_NOREPLACE)`. If something now sits at `origPath`, fail
   cleanly and say so; `--to PATH` restores elsewhere (under `allowPaths` only); `--force` is not
   offered (replace-by-rename of an unknown file is exactly the mistake quarantine exists to avoid;
   the operator moves the squatter themselves).
3. `neuter`: open `origPath` `O_PATH|O_NOFOLLOW`, `fstat`, require `(dev, ino)` equal the manifest
   (the code does none of this, `:379-387`: with a weak neuter the path could be a different file by
   now), then clear immutable and `fchmod` the recorded mode on the fd.
4. Write `restored.json` (time, operator uid from `SUDO_UID`/the journal, destination) and **keep
   the manifest**. The code `RemoveAll`s the entry dir (`:377`, `:386`), destroying the record of
   what was done to whom; the tombstone is what makes "restoring a restored handle is a no-op with
   a ledger note" implementable at all.
5. Ledger `restored` referencing the handle and the alert's ledger id.

**Integrity at `list` time.** Re-hash the stored file and compare with the manifest. A mismatch
means a writer still had the inode open after the rename (4.4, `provisional`) and the artifact is
not what was hashed; show `sha256: CHANGED (was 9f2c.., now 7e..)`. For `neuter`, re-stat the path
and show `mode`/`immutable` as they are now (a root attacker clearing the bit shows up here).

**Purge.** Clears the immutable bits and removes the entry dir. Never automatic by default
(`quarantine.retention: 0` = keep, like the ledger). `--older-than` with an optional
`--yara-clean-only` for the operator who trusts their rule set. Purge writes a `purged` ledger line
carrying the manifest verbatim, so the chain survives the artifact.

**Reboot.** Rename-quarantined files persist. Neutered files persist (immutable survives). Nothing
to do, unlike freeze; `bootId` in the manifest is for correlation only.

---

## 6. The "what IS this file" question: the YARA tie-in

Quarantine and YARA are designed together because each is the other's missing half:

- A Sigma alert says *behaviour*: "something fetched a file from a bare IP into `/tmp` and ran it".
  It does not say what the file is. The operator's first question on seeing a `quarantine` ledger
  line is "was that malware or my colleague's build script?" - and the file is now in a store where
  banken can answer.
- A YARA scan on a live path is best-effort by construction (`yara-integration.md` 4.2a): the
  dropper may be gone, truncated, or swapped by scan time. On a quarantined file it is **reliable**:
  the inode is root-only, immutable, hashed, and cannot change under the scanner. The quarantine
  store is the one place a content verdict is worth recording as fact.

### 6.1 Flow

```
Executor.Quarantine -> handle                (the file is held; this never waits on YARA)
  -> responder: yara.ScanStored(id)          (section 6.2; a deadline, never-die)
       -> <id>/yara.json                     (verdict, engine, rule-set version, scanned sha256)
       -> ledger "scanned" line on the handle
       -> derived Alert{Kind: yara, Trigger: "sigma/<rule>", File: origPath, SHA256} per match
          -> Dispatcher (journal/jsonl/webhook) as any alert
```

**Quarantine never depends on YARA.** The file is taken on the Sigma alert; the scan is a
follow-up that can fail (no engine, timeout, too big) without un-taking anything. `yara.json` then
records `verdict: unscanned, reason: ...`, and `list` shows it. A quarantine with no verdict is
still a quarantine; a verdict with no quarantine is the best-effort live scan, which is a different
feature.

### 6.2 Interface (banken side; engine-agnostic)

```go
// internal/yara (interface only; the engine is the sidecar / yr subprocess per tasks 8be69247, 4c59d403)
type StoredVerdict struct {
    Verdict   string    `json:"verdict"`   // malicious | clean | unscanned
    Reason    string    `json:"reason,omitempty"` // for unscanned: no-engine | timeout | too-large | unhashed | error
    Matches   []Match   `json:"matches,omitempty"` // rule, namespace, tags; never strings or offsets
    SHA256    string    `json:"sha256"`    // of the bytes scanned; must equal the manifest's
    Engine    string    `json:"engine"`    // "yr 1.3.0" | "yara 4.5.4" | "yarad 0.1"
    RuleSet   string    `json:"ruleSet"`   // "forge-core 2026-10" etc.
    Time      time.Time `json:"time"`
}

func (s *Scanner) ScanStored(ctx context.Context, storeDir string) StoredVerdict
```

`ScanStored` opens `<id>/file` read-only (`O_NOFOLLOW`), hands the **fd** to the engine (the
sidecar gets `/proc/self/fd/N` or an `SCM_RIGHTS`-passed fd over the mimi-style socket), bounds the
scan with `yara.timeout`, writes `yara.json` `0400`, and never returns an error to the caller: an
`unscanned` verdict *is* the error channel, like `Result.Skipped`/`Err` in the YARA design. The
`neuter` method scans the in-place file through the same fd discipline (it is `0000` but the
responder is root).

### 6.3 What the verdict is allowed to cause

- **Record and alert.** Always: `yara.json`, a `scanned` ledger line, a derived `Kind: yara` alert
  per match (one level of derivation; a YARA alert is never itself a trigger).
- **Inform `list`.** The verdict column is how an operator triages a day of quarantines in one
  screen.
- **Not auto-restore.** A `clean` verdict must never restore the file by itself: YARA-clean means
  "no signature matched", not "benign", and an attacker who can predict the rule set gets banken to
  put their file back. Restore is an operator action.
- **Not auto-kill (yet).** `malicious` + a non-empty `inUse` list is the one case where a follow-up
  kill of exactly those pids (pinned by the `exe` `(dev, ino)` match, which is a stronger identity
  than a pid) is *tempting*. It is deferred to the composite-actions work (2.3) as an explicit
  policy step (`onMalicious: kill-inUse`), default off, `rules:`-pinned like any kill. Not in v1.
- **Not escalation of the Sigma alert.** Independent alerts, correlated by `Trigger` and the
  ledger id (`yara-integration.md` 11.9 left this open; stays out of v1).

### 6.4 Why not scan before quarantining?

Because the scan takes tens of ms to seconds and the attacker's writer may still hold the file; a
pre-scan hash and a post-move hash would differ and the verdict would describe bytes that no longer
exist. Take the file first (microseconds, atomic, reversible), *then* ask. The one thing lost is
"do not quarantine if clean", which 6.3 argues banken should not offer anyway.

---

## 7. Test strategy

The standard is the detection corpus's: a decision is a fixture, a primitive is an integration test
on a self-created file, and a missing fixture fails the build. Everything below runs on a plain
Linux box as an unprivileged user unless marked **root/VM**.

**Decision layer (fast, Mac-safe).**
- `tests/response/dropper_tmp.expect-quarantine.json`, `dropper_nixstore.expect-none.json`
  (never-touch), `dropper_outside_allow.expect-none.json`, `dropper_no_path.expect-none.json`
  (untargetable), `dropper_tagonly.expect-quarantine.json` (tag-only is allowed for quarantine),
  `dropper_image_interpreter.expect-none.json` (`image: /usr/bin/python3` -> never-touch).
- `TestQuarantineNeverRecursesIntoStore`: a policy whose `allowPaths` contains `quarantine.dir`
  fails to load.
- Property: for any alert and any policy that validates, a `quarantine` decision's path is under
  `allowPaths` and outside never-touch (`FuzzDecideNeverCrossesRails` gains the file arm).

**Executor (Linux, unprivileged, own files under `t.TempDir()` and `/tmp`).**
- **Round-trip property** (`rapid`): random content, random mode (including setuid/setgid/sticky
  bits), random mtime, random `user.*` xattrs, a hard link or not; `Quarantine` then `Restore`;
  assert content, mode, uid/gid, mtime, xattrs identical and `nlink` unchanged. Then the same with
  `QuarantineDir` on a tmpfs and the file on disk (or vice versa) to force EXDEV: assert
  `method: neuter`, mode `0`, `immutable` as the fs allows, restore clears both and the recorded
  mode is back. Extends `TestQuarantineRestore` (`exec_linux_test.go:231`).
- **Swap race.** Between `fstat` and `rename` (inject a hook between steps 2 and 6), replace the
  directory entry with another file. Assert `ErrStaleTarget`, the swapped-in file is back at the
  path, and the store has no entry. Then the same on the EXDEV path: assert the fd-based `fchmod`
  hits the original inode, not the swapped-in one (today, by path, it hits the wrong one - F-Q1).
- **Manifest-first.** Make the store dir unwritable; assert `Quarantine` refuses before any rename
  and the file is untouched. Crash injection after the rename (exit before finalise); assert the
  retry finalises from `pending` and `Restore` works.
- **Idempotency.** `Quarantine` twice (second: same handle or `ErrAlreadyQuarantined`, file moved
  once); `Restore` twice (second: no-op, ledger note, `restored.json` unchanged).
- **Restore to an occupied path.** Put a new file at `origPath`; assert `restore` fails cleanly,
  the squatter is untouched, `--to` works.
- **Rails.** Owner mismatch (file owned by another test-created uid - needs root; or chown fails ->
  skip), root-owned refused by default, `inUse` refused by default (the test execs the file it
  then quarantines; `/proc/self/exe` is the in-use pid) and recorded under `proceed`, `S_IFREG`
  only (a FIFO, a directory, a symlink), size cap marks `unhashed` and still moves.
- **Store neutering.** After quarantine the stored `file` is `0000` + immutable; `restore` reapplies
  the recorded `0755`.
- **Integrity at list.** Hold the file open for write, quarantine, write more, `list`: assert
  `sha256: CHANGED`.
- **Dry-run is inert**: under the syscall filter of `enforcement-testing.md` 5.3, with a sparse 1 TiB
  file (hash cap) and under a `ReadOnlyPaths=/tmp` unit.

**YARA tie-in (fast with a fake engine; real engine opt-in).**
- `TestScanStoredWritesVerdict`: fake engine returns one match -> `yara.json` present, `0400`,
  `sha256` equals the manifest's, one derived alert with `Trigger`, one `scanned` ledger line.
- `TestScanStoredNeverFailsQuarantine`: engine returns error / times out / is absent -> verdict
  `unscanned` with the reason, quarantine handle unchanged, no derived alert.
- `TestCleanVerdictDoesNotRestore`, `TestYaraAlertNeverTriggersScan`.
- Real engine: the embedded canary rule against a quarantined canary file -> `malicious` with
  `banken_canary`; `BANKEN_YARA` gated, as in `yara-integration.md` section 6.

**VM, root, the real units** - the quarantine scorecard (section 8), the responder unit's
`ReadWritePaths`/`CAP_LINUX_IMMUTABLE` actually allow the rename/neuter (and `/etc` is refused by
the unit as well as by the code), and the weaponisation tests of section 9.

---

## 8. The quarantine scorecard

The enforcement scorecard counts kills per rule. The same harness, one column over: for every
emulation whose header names a dropped artifact, run it under a quarantine policy and assert the
artifact is in the store with a manifest and (with the engine present) a verdict. Report
`quarantined artifact on X/Y file-dropping emulations`, and the `missing` count honestly: every
emulation deletes its scratch dir on exit (`trap 'rm -rf "$work"' EXIT`), so by default the artifact
is gone before banken runs. The harness needs the scripts' `EMUL_KEEP=1` mode (seeded alongside the
enforcement harness work) which disables the trap and prints the artifact path on stdout for the
assertion. Where the emulation's artifact lands on tmpfs the column records `neuter`, which is
also the proof that the EXDEV path works end to end under the real unit.

---

## 9. Threat model: quarantine as a weapon

The attacker's goal flips: not to evade quarantine but to *cause* one against a file the host
needs. Each vector, and the rail that stops it:

| Vector | How the attacker tries | Rail |
| --- | --- | --- |
| quarantine a system file | make an audited event name `/etc/ld.so.preload` or `/usr/bin/sshd` (read it, stat it) with a rule mapped to quarantine | never-touch prefixes, in `Decide` **and** the executor; not configurable off |
| quarantine an app's data under `/opt` or `/home/svc` | `cat /opt/app/config.yml` under a file_event rule mapped to quarantine | owner rail (4.2): not theirs, not scratch -> refused; root-owned refused by default |
| quarantine a running service's binary | trigger on `image:` of a legit tool under `/opt` | `inUse: refuse` (4.4) + owner/root rails |
| quarantine a user's real file | drop a payload *named* like the victim's file in a scratch dir, hope for confusion | the alert names the path the attacker touched; the owner rail means only the attacker's own files qualify outside scratch, and inside scratch the file is theirs |
| symlink redirection | `/tmp/x -> /home/alice/.ssh/authorized_keys`, trip a rule on `/tmp/x` | `O_NOFOLLOW` on the final component; the intermediate case is closed by the owner rail (the target is not theirs, not scratch) |
| hardlink to a protected file | `ln /home/alice/important /tmp/x` (same fs, attacker has read access) | the inode's owner is alice, not the attacker -> owner rail refuses; if the attacker *is* alice, they could already delete it; `nlink > 1` recorded |
| fill the store | drop and trigger thousands of files | `rateLimit.perRun/perHour` bound the count; rename costs no space; neuter costs none |
| make restore clobber | after a quarantine, place a file at `origPath` so `restore` replaces it | `RENAME_NOREPLACE` on restore; no `--force` |
| make restore target elsewhere | tamper with the manifest to change `origPath` | manifest is `0400` root + immutable; `(dev, ino)` check on the stored file; `--to` is operator-typed and `allowPaths`-bounded |
| get a file *back* via YARA | craft a file that is YARA-clean | clean never restores (6.3) |
| exhaust the drain | a file on a hung mount / 1 TiB sparse | hash cap; `O_PATH` open does not block; the YARA scan has a deadline |
| root attacker | clears immutable, edits manifest, restores | not preventable from userspace; `list`'s re-hash and re-stat show it; `tamper_banken` fires on writes under `/var/lib/banken` |

The design property these add up to: **an unprivileged attacker can only ever cause banken to
quarantine a file the attacker could already have deleted**, and every quarantine is undone with
one command. The owner rail is doing most of the work, which is why it defaults on and why relaxing
it is a named, logged policy change.

---

## 10. Gaps between the design and the code at `5febddb`

| # | Line | Gap | Task |
| --- | --- | --- | --- |
| Q1 | `exec_linux.go:340-341`, `:568` | EXDEV neuter acts by path, not on the fstat'd fd; no post-neuter inode recheck | roughedge |
| Q2 | `:347-349` | manifest written after the rename; failure is a warning -> orphaned, unrestorable file | roughedge |
| Q3 | `:377`, `:386` | `Restore` deletes the entry dir (evidence record gone; idempotent restore impossible) | roughedge |
| Q4 | `:371`, `:379-387` | rename-restore checks `ino` only, not `dev`; neuter-restore checks nothing against the manifest | roughedge |
| Q5 | `:285-352` | no owner / root-owned / in-use rails; `FileRef` carries no user | design |
| Q6 | `:308`, `:686` | hash has no size cap; dry-run reads the whole file | roughedge |
| Q7 | `:321-324` | the stored file keeps its original mode; not neutered in the store | design |
| Q8 | `:275-283` | manifest lacks owner names, xattrs, capabilities, ctime, alert/ledger id, policy hash, boot id, inUse, version | design |
| Q9 | - | no `yara.json` step, no `ScanStored`, no derived alert from the store | design (with 8be69247) |
| Q10 | `decide.go:184` | one rule, one action: no `[freeze, quarantine]` composite | design |
| Q11 | - | no `banken respond list/show/restore/purge` for quarantine; no integrity re-hash at list | design |
| Q12 | `tests/emulations/*.sh` | artifacts deleted on exit; no `EMUL_KEEP` for the scorecard | test |
| Q13 | `exec_linux.go:52` | `/dev` not never-touch (relies on `S_IFREG`); `/dev/shm` carve-out needed | roughedge |

---

## 11. Open questions for Conor

1. **Owner rail default.** `allowForeignOwner: false` and `allowRootOwned: false` make quarantine
   nearly useless against a *root* dropper (root malware writes root-owned files outside scratch).
   The counter-argument: a root dropper is already past every userspace defence, and the file it
   dropped is almost certainly in scratch anyway (where the rail allows it). Keep both defaults
   strict, or allow root-owned under scratch prefixes only (a middle setting)?
2. **`inUse: refuse` as default** means the most *interesting* quarantine (the running miner's
   binary) is refused until composites exist. Accept the gap for v1, or ship `proceed` as default
   with the loud ledger line?
3. **Composites now or later.** Section 2.3 resolves spec 13.5 in favour of `actions: [..]` with a
   canonical order. It touches `Decide`'s return shape and every fixture. Land it with quarantine,
   or ship quarantine single-action first?
4. **Per-mount store** (`quarantine.dirs`). Spec 13.6 called it a rough edge; 3.3 makes it the only
   real fix for tmpfs without immutable support, opt-in. Offer it, or document `neuter-weak` and
   leave it?
5. **Store neutering changes `ctime`** of the evidence inode. Forensic purists dislike it; the
   pre-neuter stat is in the manifest. Neuter the stored copy (recommended) or leave it as moved?
6. **YARA follow-ups.** 6.3 defers `onMalicious: kill-inUse`. Is that the right line, given it is
   the one place banken would have a *content*-grounded reason to kill?
