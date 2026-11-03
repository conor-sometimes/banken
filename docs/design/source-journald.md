# journald as a banken telemetry source

Status: design + scouting, 2026-11-02.

Today journald is a stubbed parser placeholder. The stub lives at internal/parser/stub.go:9-31. It
is registered in parser.Registry() at internal/parser/parser.go:108 under the source name
"journald". docs/log-sources.md:38 lists it as "native parser (stub today), planned". Conor wants
real support.

This doc is the scouting behind that work. It gives the honest verdict on what the systemd journal
can and cannot give a detection, and the recommended read mechanism. The PR-sized pieces are:

- a config source type
- a journalctl JSON bridge
- a native parser
- the sandbox
- logsource routing
- VM tests

The headline is plain. The journal is not a complete record of every process that ran. It records
the identity of whatever process emitted a log line. It does not see a program that executed but
logged nothing.

So journald is a first-class source for three things:

- auth, login and sudo telemetry
- service and kernel telemetry
- a portable baseline on a stock systemd host

For process_creation it is a deliberately secondary, caveated signal. Real process coverage stays
the job of auditd / Laurel / mimi / Sysmon. Section 5 has the honest limits. Read it before wiring
anything to a process_creation rule.

## 1. Current state in the code

- Parser stub at internal/parser/stub.go:9-31. `Journald` implements the `Parser` interface
  (internal/parser/parser.go:24-35). It drains its reader to advance the caller's cursor and emits
  no events. Its TODO names the intended fields: `_COMM / _EXE / _CMDLINE / _UID`, "one entry per
  double-newline" (the systemd export format). The sibling `Syslog` stub sits beside it
  (internal/parser/stub.go:39-48) for RFC 3164/5424 auth.log. Section 8 argues journald largely
  subsumes it on journald-only hosts.
- Registered. internal/parser/parser.go:108 wires `journaldName: Journald{}` into the registry. So
  a `-source journald:PATH` flag or a `{type: journald, path: ...}` config entry already resolves to
  this stub and silently produces nothing.
- Config half-admits it. internal/config/config.go:45 documents `Type` as
  `laurel | auditd | journald | syslog`, so the config layer already admits journald. The NixOS
  module's option enum does not. module.nix:88 lists `[ "laurel" "auditd" "generic" "mimi" "sysmon" ]`
  with journald and syslog absent. config.go admits journald and module.nix rejects it. That is a
  wiring gap to close (section 7).
- Streaming. journald is a continuous stream, so it must be followed, not scanned. `isStreamSource`
  (main.go:351) currently returns true only for `mimi` and `sysmon`. journald must join it, so
  banken follows it via `StreamFollow` (internal/engine/stream.go:26) rather than the one-shot
  timer leg.
- Not the output journal sink. internal/alert/journal.go is banken writing alerts to the journal
  (an alert sink, module.nix:52 / module.nix:243). This doc is about reading the journal as a
  telemetry input. Different direction, same word.

The `Event` contract every parser fills is internal/event/event.go:25-88. `Event.Field`
(internal/event/event.go:93) resolves the named Sigma fields then `Raw`. So anything a parser drops
in `Raw` is still matchable by name. That is the whole target of the mapping in section 4.

## 2. What the journal actually is (and is not)

systemd-journald is a log aggregator, not a syscall sensor. It collects several streams into one
indexed store:

- stdout/stderr of every service it supervises (the dominant volume)
- syslog traffic (sshd, sudo, PAM, cron, rsyslog clients) via /dev/log
- kernel messages (/dev/kmsg)
- structured native entries from `sd_journal_send` clients
- optionally the kernel audit multicast, when systemd-journald-audit.socket is enabled

For each entry, journald attaches trusted fields describing the process that sent the entry. These
are the underscore-prefixed fields. journald reads them from /proc at receive time, so the sender
cannot forge them:

    `_PID`, `_UID`, `_GID`, `_COMM`, `_EXE`, `_CMDLINE`, `_CAP_EFFECTIVE`, `_AUDIT_SESSION`,
    `_AUDIT_LOGINUID`, `_SYSTEMD_UNIT`, `_SYSTEMD_CGROUP`, `_SYSTEMD_SLICE`, `_SELINUX_CONTEXT`,
    `_BOOT_ID`, `_MACHINE_ID`, `_HOSTNAME`, `_TRANSPORT`, `_SOURCE_REALTIME_TIMESTAMP`.

The non-trusted fields carry the content: `MESSAGE`, `PRIORITY`, `SYSLOG_IDENTIFIER`,
`SYSLOG_FACILITY`, and any app-supplied keys.

Two facts drive the whole design:

1. There is no trusted parent field. journald attaches `_PID` but not a `_PPID`. It has no parent
   exe and no parent cmdline. So an event sourced from the journal cannot fill `ParentImage` or
   `ParentProcessId` (internal/event/event.go:45, event.go:65). Those are the fields a lot of
   behavioural rules want. This is intrinsic, not a parser shortcut.

2. `_EXE` / `_CMDLINE` describe the sender of a log line. A process shows up in the journal only if
   it (or systemd on its behalf) emitted an entry. Most execs emit nothing. So the journal's view of
   "processes that ran" is a biased, incomplete subset. The journal is exec-incomplete by
   construction.

## 3. Recommended read mechanism: a journalctl JSON bridge + a native parser

Start with the constraint. banken is CGO-free and statically linked. That is the whole point of the
"single portable binary" story. It rules out the obvious mechanism, libsystemd's sd-journal via cgo.
The reading options, with verdicts:

| Option | How | Verdict |
| --- | --- | --- |
| sd-journal (cgo) | link libsystemd, read the journal API directly | OUT. cgo breaks the static CGO-free binary. Non-starter. |
| Pure-Go journal binary reader | reimplement the on-disk journal file format (/var/log/journal/*/*.journal) in Go | OUT for v1. The format is complex (windowed hash tables, compression, FSS sealing), under-specified, and there is no vendor-supported Go reader. A lot of fragile code to own, for a format that changes. Reject. |
| `journalctl -o export` subprocess | double-newline-delimited, binary-safe export format (what the stub TODO names) | Workable but loses to JSON: export needs field-by-field reassembly across the blank-line framing, and binary values are length-prefixed. JSON is one object per line - a direct fit for the parser's line scanner. |
| `journalctl -o json` subprocess, bridged to a file | journalctl follows the journal and emits one JSON object per entry; a tiny service appends it to a file banken tails | RECOMMENDED. See below. |

The recommendation is a bridge. A `journalctl -o json --follow` service appends newline-delimited
JSON to a file. banken tails that file with a native `Journald` JSON parser. This is not a new
pattern. It is exactly the shape banken already ships for Sysmon on journald-only hosts
(module.nix:445-484, `banken-sysmon-journal`: `journalctl -f -n0 -o cat` appending to a bridge file
that banken tails as a normal file source). docs/design/sysmon-linux.md already blesses this as "the
whole of reading the journal there: a thin, supported journalctl pipe rather than a journal client
or cgo in banken itself, so banken keeps its single file+cursor+inotify reading path."

This is the right call for banken for five reasons:

- It reuses the one reading path banken is built around. The bridge file is just another file
  source. `StreamFollow` (internal/engine/stream.go:26) already handles the cursor, partial trailing
  writes, rotation on reopen, and the 1s safety tick for a sink that appears late or moves. Nothing
  new in the engine.
- It reuses the parser contract verbatim. One JSON object per line means `scanLines`
  (internal/parser/parser.go:52) frames it. The parser mirrors `Mimi`
  (internal/parser/mimi.go:41-56): unmarshal per line, skip a line that is not valid JSON, never
  fail the batch. The mimi parser is the template. journald JSON is just a different object shape.
- It keeps banken CGO-free and static. All the journal knowledge lives in the `journalctl` the host
  already ships. banken parses plain JSON.
- It reuses the exact sandbox. The bridge is a DynamicUser service in the `systemd-journal` group
  with no other power, a copy of module.nix:445-484 (section 6).
- It is portable. Every systemd host has journalctl. This is the source that works on a stock distro
  with nothing else installed (section 9).

The tradeoffs, stated honestly:

- Bridge downtime loses sub-second events. On a bridge restart, `journalctl -f` resumes at the tail.
  Entries written during the (2s) restart window are not bridged. The same caveat is already
  documented and accepted for the Sysmon bridge (module.nix:443). For auth events this is a real,
  small gap. A failed login during a bridge restart is missed. If that gap matters, resume from the
  last journal cursor (next bullet).
- The cursor tracks the file, not the journal. banken's cursor is a byte offset in the bridge file,
  not journald's native `__CURSOR`. That is fine for the file. But resume-after-restart means "tail
  of the file now", not "exactly after the last journal entry banken saw". A v2 could have the
  bridge pass `--after-cursor=<saved>`, using the `__CURSOR` the parser keeps in `Raw`, for exact
  resume. v1 accepts the sub-second gap, as Sysmon does.
- Bridge file growth. `StandardOutput=append:` grows unbounded if banken falls behind or the file is
  never rotated. This is an unsolved edge shared with the Sysmon bridge. Section 10 lists it as an
  open question to solve once for both.

One alternative is not recommended for v1 but is worth a mention. banken could spawn `journalctl`
itself with no bridge file, read its stdout as the `io.Reader`, and persist journald's `__CURSOR`
for exact resume. That is journal-native and loses no events across restart. But it makes banken
manage a child process and a second cursor type (an opaque journal cursor string, not a byte
offset). That diverges from the single file+cursor model module.nix:441 celebrates. It also adds
process-exec and journal-read power to banken's own hardened unit (section 6). Defer it. Revisit
only if the sub-second gap proves to matter.

## 4. Field mapping: journald JSON -> event.Event

A representative `journalctl -o json` entry (one line; abbreviated), for an sshd failed login:

    {"__REALTIME_TIMESTAMP":"1730520000123456","__CURSOR":"s=ab..;i=12f;b=..","_BOOT_ID":"..",
     "_HOSTNAME":"host","_TRANSPORT":"syslog","PRIORITY":"5","SYSLOG_FACILITY":"10",
     "SYSLOG_IDENTIFIER":"sshd","_COMM":"sshd","_EXE":"/usr/sbin/sshd","_CMDLINE":"sshd: alice [priv]",
     "_PID":"1041","_UID":"0","_GID":"0","_SYSTEMD_UNIT":"sshd.service","_AUDIT_LOGINUID":"1000",
     "MESSAGE":"Failed password for alice from 192.0.2.7 port 51514 ssh2"}

The parser (mirroring internal/parser/mimi.go:58-108) fills:

| event.Event field | journald source | Notes |
| --- | --- | --- |
| Source | (stamped "journald") | Never read from the line - the enforceSources trust rail, same as mimi (internal/parser/mimi.go:59-61). |
| Time | `_SOURCE_REALTIME_TIMESTAMP` else `__REALTIME_TIMESTAMP` | Microseconds since epoch; prefer the sender's source timestamp for accurate exec->alert latency in StreamFollow (internal/engine/stream.go:39). |
| Image | `_EXE` | The LOGGING process's exe. Best-effort; empty for kernel/non-process entries. See section 5. |
| CommandLine | `_CMDLINE` | The logging process's argv. journald stores it NUL-separated; render NULs as spaces, reusing the proctitle approach in decodeHexField (internal/parser/parser.go:134-139). Can be truncated by journald's field cap. |
| User | `_UID` | Numeric uid; banken's cross-source User normalisation resolves it to a login name where it can, as for mimi (internal/parser/mimi.go:76-78). |
| PID | `_PID` | The logging process. |
| PPID | - | NOT available. No trusted parent field. Stays zero. |
| ParentImage | - | NOT available. Stays empty. |
| CurrentDirectory | - | NOT available. The journal carries no cwd. Stays empty. |
| ProcessStart | - | NOT available. Stays zero (pid-reuse-safe response targeting is weaker here than off mimi/Sysmon). |
| Raw["MESSAGE"] | `MESSAGE` | The log text. This is the PRIMARY matchable datum for journald (auth strings, "Failed password", "session opened for user root"). Field/AllText reach it by name (internal/event/event.go:118, event.go:164). |
| Raw["SyslogIdentifier"] | `SYSLOG_IDENTIFIER` | sshd / sudo / cron / ... - the cheapest unit/program selector for a rule. |
| Raw["Unit"] | `_SYSTEMD_UNIT` | Which service emitted it. |
| Raw["Priority"] | `PRIORITY` | 0-7 syslog severity. |
| Raw["Comm"] | `_COMM` | 15-byte process name (like mimi's ParentName). |
| Raw["Gid"] | `_GID` | As mimi (internal/parser/mimi.go:103-105). |
| Raw["AuditLoginUid"] | `_AUDIT_LOGINUID` | The login uid behind a privileged action - useful for sudo/su attribution. |
| Raw["Transport"] | `_TRANSPORT` | syslog / kernel / stdout / journal / audit - lets a rule scope to a transport. |
| Raw["Cursor"] | `__CURSOR` | Provenance, and the hook for exact resume in a v2 (section 3). |

Everything else a parser chooses to keep can go in `Raw` too (SELinux context, cgroup, boot id,
app-supplied keys). `Event.Field`/`AllText` reach it with no schema change, exactly as mimi keeps
its ancestry chain (internal/parser/mimi.go:91-98). No field renames are needed. banken's event
model already uses Sigma's own names, so the pipeline.yml `rename` maps stay identity by design (the
pipeline file's own header says so; section 7).

## 5. The process_creation shape: journald is not execve-complete

This is the honest core. Say it to operators plainly and keep saying it:

- The journal records the process that logged a line, not every process that executed. `_EXE` and
  `_CMDLINE` are real and trusted, but they are a biased sample. Daemons that log heavily are
  over-represented. A quiet `curl | bash` that writes nothing to the journal is invisible to this
  source. The exec sources see the exec itself; journald sees it only if it logged.
- No parent, no cwd (section 4). Rules keyed on ParentImage / ParentProcessId / CurrentDirectory
  cannot fire off a journald event.
- So do not route journald into the process_creation lane. A `category: process_creation` rule
  evaluated against journald events would match "the shell that happened to log something". That
  produces misleading, incomplete hits that look like exec coverage but are not. v1 gives journald
  its own logsource lane (auth, application, or a journald service lane; section 7) and leaves
  process_creation to the sources that actually see execs.

journald complements the exec sources rather than overlapping them:

- auditd / Laurel give syscall-complete exec and file records, plus the folded multi-record audit
  event (internal/event/event.go:80-87 Multi). This is the complete exec ground truth. journald does
  not replace it. Where both are present they corroborate the "who" metadata (uid, loginuid), but
  journald adds nothing to exec coverage.
- mimi gives eBPF exec with the full ancestry chain and reliable pid/ppid (internal/parser/mimi.go).
  mimi has the parent and ancestry journald cannot give. journald is the fallback when no eBPF
  sensor is deployed.
- Sysmon-for-Linux gives a real absolute ParentImage and network/file events
  (docs/design/sysmon-linux.md). journald does not overlap this either. It is the dependency-light
  baseline for hosts that run none of the above.

journald earns its place for three things of real detection value:

1. Auth, login and privilege events. sshd accepted/failed logins, `sudo`/`su` sessions, and PAM
   "session opened for user root", all matched on `MESSAGE` + `SYSLOG_IDENTIFIER`. This is precisely
   the target the stubbed `syslog` parser (internal/parser/stub.go:39-48) was written for. On a
   journald-only host the journal is where auth.log lives. One source covers both (section 8).
2. Service and kernel telemetry. systemd unit state, OOM kills, segfaults, and kernel log lines
   (PRIORITY, _SYSTEMD_UNIT, _TRANSPORT=kernel). No other banken source carries this.
3. The portable baseline. Every systemd host has a journal with zero extra install. On a stock
   distro with no auditd rules loaded, no Laurel, and no eBPF sensor, journald is the source that
   still gives banken auth and service visibility. That is the "banken runs on stock distros"
   promise (section 9).

A note on reading audit through the journal. If systemd-journald-audit.socket is enabled, the
journal also carries the kernel audit multicast (`_TRANSPORT=audit`, SYSCALL/EXECVE as journal
entries). banken already reads those same records, better, via the `auditd` source off
/var/log/audit/audit.log (internal/parser/auditd.go). Reading audit through the journal would
duplicate that source in a worse format. v1 does not do it. A journald rule can simply ignore
`_TRANSPORT=audit` entries.

## 6. Sandbox and permissions

Reading the journal needs membership in the `systemd-journal` group (or root). The design keeps that
power in the bridge, not in banken:

- The bridge service, `banken-journald`, is a near-verbatim copy of `banken-sysmon-journal`
  (module.nix:445-484): `Type=exec`, `ExecStart=journalctl -f -n0 -o json <filters>`,
  `StandardOutput=append:<bridgePath>`, `Restart=on-failure`, `RestartSec=2`. Its only privilege is
  `DynamicUser = true` with `SupplementaryGroups = [ "systemd-journal" ]` and a `LogsDirectory` for
  its own output file. The full hardening block carries over unchanged (NoNewPrivileges,
  ProtectSystem=strict, PrivateDevices, PrivateNetwork, SystemCallFilter=@system-service,
  MemoryDenyWriteExecute, ProtectProc=invisible, UMask=0077). It is a dynamic user that can only read
  the journal and write one file.
- banken itself does not change. It reads the bridge file as root with the CAP_DAC_READ_SEARCH it
  already holds (module.nix:396). No journal group, no exec, no new syscalls, no new capability. The
  hardened main unit (module.nix:375-422) is untouched. This is the decisive reason to prefer the
  bridge over banken spawning journalctl itself (section 3). The bridge isolates the journal-read
  privilege in a throwaway dynamic user instead of widening banken's own sandbox.
- No new egress. The bridge is `PrivateNetwork=true`. banken's network posture is unchanged
  (module.nix:404-405).

The design holds to the four containment tenets (secure, auditable, comfortable, configurable). The
bridge is one more small, auditable, least-privilege unit. The source is one config switch. Every
knob is an option Conor sets, including which identifiers, units and priorities to bridge
(section 7).

## 7. Config, wiring, and logsource routing

The config and wiring, as PRs:

- module.nix:88 enum. Add `"journald"` (and, with section 8, `"syslog"`) to
  `[ "laurel" "auditd" "generic" "mimi" "sysmon" ]`. config.go already admits the type
  (internal/config/config.go:45). The module must too, or `services.banken.sources` with a journald
  entry fails evaluation.
- main.go:351 `isStreamSource`. Add `|| typ == "journald"` so banken follows the bridge file
  continuously (StreamFollow) and gives it its own cursor file (streamStatePath, main.go:355),
  rather than scanning it on the timer leg.
- A `services.banken.journald.enable` switch, mirroring `services.banken.sysmon`
  (module.nix:163-216). It brings up the `banken-journald` bridge, points banken at the bridge file
  as a `{type: journald, path: <bridgePath>}` source (the sources-merge at module.nix:44-50 already
  has the shape), and makes banken a `--watch` daemon (streamEnabled, module.nix:23). Expose two
  options: the journalctl filter (identifiers, units, min priority; section 10) and the bridge path.
- AutoDetectSources (internal/config/config.go:117-134) could learn journald as a last-resort
  candidate, since a journal always exists on a systemd host. But keep it behind the switch first.
  Auto-adding journald everywhere would double-count against auditd/mimi and flood low-value service
  logs. Candidate order stays laurel, auditd (config.go:118-119). journald is opt-in for v1.

Now the logsource routing. It depends on PR #24, swarm/sigma-engine, not yet merged to the
distro-matrix-mimi base (see section 11). The routing pipeline lives at internal/sigma/pipeline.yml
on that branch. It maps a rule's `logsource` (category/product/service) to the set of event `Source`
tags a rule is evaluated against. Today its lanes are:

    windows-sysmon       -> [sysmon]
    macos                -> []            (loads, nothing live feeds it)
    linux-auditd-service -> [auditd, laurel, mimi, generic]
    linux                -> [auditd, laurel, mimi, sysmon, generic]
    process-creation-any -> [auditd, laurel, mimi, sysmon, generic]

Add journald carefully, consistent with section 5:

- Add a journald lane for the logsource categories journald can actually satisfy. That means an
  auth/authentication lane and a journald/service lane, with `sources: [journald]` (plus the generic
  JSONL escape hatch where relevant). Example shape:

      - name: linux-auth
        when: { product: linux, service: auth }   # sshd/sudo/pam auth rules
        sources: [journald, auditd, laurel, generic]
      - name: linux-journald-service
        when: { product: linux, service: systemd } # or a journald service lane
        sources: [journald]

- Do not add `journald` to `process-creation-any` or the broad `linux` lane. That is the whole point
  of section 5. Routing journald into process_creation would let exec rules match the logging
  process and mislead. Keep journald on the lanes it can honestly serve.
- No `rename` map needed. journald fills Sigma-named fields and keeps the rest in `Raw` under
  Sigma-ish names, so the maps stay identity, exactly as the pipeline header intends.

## 8. Relationship to the stubbed syslog source

The `Syslog` stub (internal/parser/stub.go:39-48) targets sshd/sudo/PAM auth from RFC 3164/5424
auth.log. Many hosts have no /var/log/auth.log, so that telemetry lives in the journal instead.
These are the journald-only hosts: the NixOS default, and RHEL/Rocky/Alma/Fedora/Amazon (the same
split docs/design/sysmon-linux.md:76-80 documents for Sysmon). So a working journald source covers
most of what the syslog stub promised, on exactly the hosts where a syslog file does not exist.

Build journald first. Treat the syslog file parser as the narrower case for the
rsyslog-with-a-file distros (Debian/Ubuntu/openSUSE) only. The auth rules are source-agnostic and
are written once. These are the MESSAGE patterns for "Failed password", "session opened" and
"sudo: ... COMMAND=". journald and syslog are two transports feeding the same rules. This is a
design question to settle, not a v1 commitment (noted in section 10).

## 9. Testing and distro-matrix applicability

Mirror the mimi/Sysmon switch tests (tests/switch.nix, tests/switch-restart.nix, tests/sysmon-switch.nix):

- tests/journald-switch.nix. A NixOS VM with `services.banken.journald.enable = true` and audit,
  mimi and sysmon off, so journald is banken's only source. Generate an auth event that does not
  depend on a syscall sensor: a failed ssh login, or a `sudo` run as the unprivileged `alice` (the
  switch.nix harness already has an `alice` normal user, switch.nix node def). Assert banken emits
  the matching OCSF Detection Finding tagged `data_sources:["journald"]` within the latency budget.
  This is the same assertion shape as tests/switch.nix. It proves the bytes travelled
  journal -> journalctl bridge -> banken.
- tests/journald-switch-restart.nix. Restart `banken-journald.service` mid-run. Assert banken
  re-attaches to the regrown bridge file and keeps alerting (the StreamFollow 1s safety tick and
  reopen-on-rotation path, internal/engine/stream.go:78-97). Document the known sub-second gap during
  the restart (section 3).
- Golden fixture. Capture a real `journalctl -o json` line (sshd, sudo, a service) from the VM into
  internal/parser/testdata/journald_sample.jsonl + journald.golden. Add it to the parser's
  golden/table tests (the pattern of internal/parser/golden_test.go and
  testdata/mimi_event.golden.jsonl). This pins the exact live framing (NUL-joined _CMDLINE,
  microsecond timestamps, field presence), not just the reconstructed sample in this doc.
- FuzzJournald. Add the parser-contract no-panic fuzz target alongside the others
  (internal/parser/fuzz_test.go), per the cardinal rule at internal/parser/parser.go:5-12. A log is
  untrusted bytes, and a crash on one crafted journal line is a way to switch detection off.

journald is the most broadly applicable source banken can have. Every systemd distro ships it. It
needs no EULA binary (unlike Sysmon, docs/design/sysmon-linux.md:276-278) and no loaded audit
ruleset (unlike auditd). It slots into tests/distros as a row that applies to every systemd target.
It is the natural "baseline source present on a stock box" entry in that matrix. Non-systemd distros
have no journal, and none are in banken's matrix today. There the syslog file parser (section 8) or
auditd is the floor.

## 10. Performance and backpressure

- Filter at the source. The journal is a firehose of every service's stdout. The bridge should
  filter in `journalctl` before the bytes reach banken. Use `-p <priority>` (min severity),
  `-t <identifier>` (sshd, sudo, ...), `-u <unit>`, or field matches. journalctl does this
  server-side cheaply. A default that bridges everything makes banken parse the entire host log
  volume for little gain. Default to an auth + notable-service filter and let the operator widen it
  (section 7 option).
- Project only needed fields. `journalctl -o json --output-fields=MESSAGE,PRIORITY,SYSLOG_IDENTIFIER,_EXE,_CMDLINE,_UID,_PID,_COMM,_SYSTEMD_UNIT,_TRANSPORT,_AUDIT_LOGINUID,_SOURCE_REALTIME_TIMESTAMP`
  cuts each line from dozens of fields to the dozen banken maps (journalctl always keeps
  `__CURSOR`/`__REALTIME_TIMESTAMP`). That is a large byte reduction on a high-volume stream.
- The line cap already protects the parser. A pathological journal MESSAGE above maxLineBytes (1 MiB,
  internal/parser/parser.go:41) is skipped, not buffered unbounded. The parser contract holds for
  journald as for every source.
- Bridge file growth. `StandardOutput=append:` grows without bound if banken lags or the file is
  never rotated. This is the one genuinely unsolved edge, shared with the Sysmon bridge (section 3).
  Solve it once for both. Either a size-capped bridge file with rotation banken follows across reopen
  (it already handles rotation, internal/engine/stream.go:20), or the v2 cursor-resume model that
  needs no growing file at all. Open question (section 11).

## 11. Non-goals (v1), open questions, risks

Non-goals for v1 (keep the scope honest and small):

- NOT an execve-complete process_creation source. journald is not routed into process_creation; it
  does not replace auditd/mimi/Sysmon (section 5).
- NO sd-journal cgo and NO pure-Go journal binary-format reader - the bridge + JSON parser only
  (section 3).
- NOT banken spawning journalctl directly - the bridge isolates the journal-read privilege; revisit
  only if the restart gap matters (section 3, section 6).
- NO synthesised ParentImage/PPID/cwd (would need /proc walking at read time; the data is not in the
  journal). Those fields stay empty off journald.
- NOT reading audit-via-journald - the `auditd` source already does it better (section 5).
- NO field renames - identity maps, by pipeline design (section 7).

Open questions:

- Bridge file rotation / unbounded growth - solve once for the Sysmon and journald bridges
  (section 10). The single biggest open item.
- Default journalctl filter - auth-only, auth + notable services, or everything? Volume vs coverage
  (section 7).
- Resume semantics - accept the sub-second restart gap (as Sysmon does), or build the
  cursor-resume v2 now for auth events where a missed failed-login matters (section 3)?
- Clock choice - `_SOURCE_REALTIME_TIMESTAMP` (sender) vs `__REALTIME_TIMESTAMP` (journald receive)
  for `Event.Time`; prefer source-time for honest latency, fall back to receive-time (section 4).
- Fold the syslog stub into journald on journald-only hosts, keeping the syslog FILE parser only for
  rsyslog-with-a-file distros? (section 8).

Risks:

- An operator deploys journald expecting exec coverage and gets a quiet, incomplete process view.
  That is the exact over-sell to avoid. Docs and the logsource lanes must make "journald is
  auth/service/baseline, not an exec feed" unmissable (section 5).
- Volume. An unfiltered journald source is a lot of low-value lines. Without the source-side filter
  it can dominate banken's match budget (section 10).
- Bridge downtime gap on restart for auth events (section 3).
- The module enum and config disagree (module.nix:88 vs internal/config/config.go:45). A journald
  source silently fails module evaluation today until the enum is fixed (section 7). Fix it in the
  same PR that adds the switch, so there is never a half-wired state.

## Verdict

Worth building, at low-to-moderate effort, as banken's portable baseline and auth source. Not as a
process_creation source. The parser is a direct sibling of the mimi JSON parser. The bridge is a
near-copy of the Sysmon journal bridge. The engine, cursor, sandbox and rule model all already
exist.

Keep repeating the honest line. journald gives banken auth/login/sudo, service and kernel visibility
on every systemd host with zero extra install, plus a best-effort "who logged this" process
identity. But it is not a complete exec record. It has no parent or cwd. Real exec coverage stays
the job of auditd / Laurel / mimi / Sysmon. Scope it that way and it is a high-value, high-reach,
low-code addition.

## Sources (code)

- internal/parser/stub.go:9-48 (Journald + Syslog stubs), internal/parser/parser.go:24-35,52,108
  (Parser interface, scanLines, registry), internal/parser/mimi.go (the JSON-parser template)
- internal/event/event.go:25-131 (Event contract, Field/Values/AllText)
- internal/engine/stream.go:26-97 (StreamFollow cursor/rotation/safety-tick)
- main.go:343-373 (isStreamSource, streamStatePath, follow), internal/config/config.go:44-134
  (Source type, AutoDetectSources, candidateSources)
- module.nix:44-50,88,163-216,375-422,445-484 (sources merge, source enum, sysmon switch, banken's
  hardened unit, the banken-sysmon-journal bridge this design copies)
- internal/sigma/pipeline.yml (logsource routing; on branch swarm/sigma-engine / PR #24, not yet on
  the distro-matrix-mimi base)
- docs/log-sources.md:38 (journald roadmap row), docs/design/sysmon-linux.md (the sibling
  source-scouting doc and the journald-only-distro split)

## Sources (external, journald field semantics)

- systemd.journal-fields(7): the trusted `_`-prefixed fields journald attaches, and the absence of a
  trusted parent field.
- journalctl(1): `-o json` / `-o export` output formats, `--follow`, `--output-fields`,
  `--after-cursor`, `-p`/`-t`/`-u` filtering.
- systemd-journald.service(8) and systemd-journald-audit.socket(8): transports (syslog, kernel,
  stdout, native, audit) feeding the journal.
