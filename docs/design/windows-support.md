# Windows support for banken: feasibility and staged design

Status: feasibility + design, 2026-11-02. Design only.

This doc answers one question Conor asked ("can we do a cloud-init Windows host, for support?") and
the larger one behind it (what would it take for banken to run on Windows at all). It is honest about
magnitude. A Windows test host is cheap and real, but a Windows EDR is a major expansion. Nothing
here is implemented, and the tasks it seeds are not started.

banken today is Linux-only by design:

- it reads Linux audit telemetry (auditd, Laurel), the eBPF sensor (mimi) and Sysmon-for-Linux
- its security model is the systemd unit's sandbox
- its live test matrix (tests/distros) is a grid of real Linux distros on their own kernels

Windows is a different operating system, telemetry stack, service model and provisioning story. Do
not read the "cheap" parts below as "Windows is easy". They are cheap because banken was built
source-agnostic, not because the platform gap is small.

## 1. The honest scope verdict

Windows support is a major, multi-stage expansion. It is not a source stub and must not be sold as
one. The weight is in three places:

- telemetry acquisition, meaning getting Windows events into banken
- the service and deploy model, since there is no systemd
- standing up a Windows node in the test matrix, since there is no vendor cloud qcow2 to pin and boot
  in one line

Those are each real pieces of work.

Three structural facts, all verified in the code, make the smallest valuable slice unusually cheap
for banken specifically. They do not shrink the whole. They move the first useful milestone close.

1. **The product already cross-compiles to windows/amd64, CGO-free, clean.** Verified on hokkaido
   (go 1.26.8, `nix develop ~/wbdev#banken`) against origin/distro-matrix-mimi:

   - `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build .` -> exit 0 (the banken binary builds).
   - `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./internal/...` -> exit 0 (engine, parser,
     sigma, event, alert, config, ioc all build).
   - `go build ./...` fails on exactly one package, and it is not the product:
     `tests/distros/distrocheck/main.go:238-239` uses `syscall.SysProcAttr.Setpgid` and
     `syscall.Kill`, which do not exist on Windows. distrocheck is the in-guest Linux test harness,
     not banken. The product is clean.

   This is not luck. The engine already carries a platform boundary. inotify-vs-poll lives in
   `internal/engine/stream_linux.go` / `stream_other.go` (build-tagged `linux` / `!linux`), and the
   inode rotation check in `stat_unix.go` / `stat_other.go` (`unix` / `!unix`). The non-Linux side
   already exists and compiles. It was written so the package builds and tests off Linux.

2. **The event schema and one parser are already Windows-shaped.** `internal/event/event.go` is the
   single normalised Event every parser fills and every rule matches. It names its fields after the
   Sigma Windows field names on purpose: Image, CommandLine, ParentImage, TargetFilename, User,
   CurrentDirectory, ProcessId, ParentProcessId (event.go:25-131). And `internal/parser/sysmon.go`
   already parses the Windows Sysmon XML event shape (`<Event><System><EventID>.../<EventData><Data
   Name=..>`), because Sysmon-for-Linux emits the exact same schema Windows Sysmon does. The parser
   header says it plainly: it "makes banken's Windows Sysmon source half-written". A Windows source
   is a new `parser.Parser` registered in `parser.Registry()` (parser.go:101) and nothing else
   downstream changes.

3. **Sigma is Windows-first, so the rule side is a strength, not a cost.** The public SigmaHQ corpus
   is overwhelmingly Windows (Security 4688 process creation, PowerShell 4104 script blocks, Sysmon
   1/3/11/...). banken already keys on those field names. PR #24 (branch swarm/sigma-engine, open
   against distro-matrix-mimi) adds logsource routing that models `product: windows`, so the rule
   engine is ready to route Windows logsources the day a Windows source feeds it. That routing is not
   yet merged into this base. Today's loader matches on fields regardless of logsource.

**Verdict.** Worth doing, staged, and worth starting with the host Conor asked for. The honest shape,
stage by stage:

- Stage 0 (a bootable, reachable Windows node in the matrix) is a few days of provisioning spike with
  real unknowns but no banken code.
- Stage 1 (banken runs on a real Windows host and fires Windows Sigma rules off one source) is
  reachable mostly by wiring plus a platform boundary, because the brain already ports and the schema
  already fits. This is the smallest slice that is a genuine Windows EDR capability rather than a
  demo.
- Stage 2+ (ETW, more channels, a Windows service, a Windows alert sink) is the large, open-ended
  part. Scope it only after Stage 1 proves the shape on real telemetry. Do not commit to Stage 2+ as
  a deliverable up front.

The smallest valuable slice, stated once: a cross-compiled banken.exe on a real Windows host, reading
one Windows event source, firing the Windows Sigma rules it already carries, alerting to a file or
webhook. Everything before that is plumbing banken mostly already has. Everything after it is the
genuinely large Windows surface.

## 2. Staged plan

### Stage 0: a cloud-init Windows host in the matrix that boots and is reachable

This is the thing Conor asked for, and the honest first step for everything after. You cannot test
Windows support without a Windows host. Standing one up on hokkaido's KVM is itself the first unknown
to retire. The goal is one Windows node, provisioned the matrix's way, that comes up and is
reachable, running no banken. Provisioned the matrix's way means the image is pinned by checksum,
booted under QEMU/KVM, and seeded by the Windows cloud-init.

The definition of done has four parts, all on a pinned image with a recorded checksum:

- the node boots unattended under KVM as the claude user
- cloudbase-init runs the seed
- the checker can reach it (a command runs in-guest and its output comes back)
- no banken on it yet

This is deliberately a boot-and-reach milestone, not a detection milestone. It retires the
provisioning unknowns (image, drivers, licensing clock, egress) in isolation. That is the same way
the Linux matrix's value is a boot path that is proven and reusable.

### Stage 1: banken cross-compiles and runs on Windows, reading ONE source

banken.exe on the Stage 0 host, reading one Windows event source, firing Windows Sigma rules.

The recommended first source is Windows Security 4688 (process creation) via the Windows Event Log,
read as exported evtx/XML. The reasoning:

- 4688 is built into Windows (Audit Process Creation + "include command line", both group-policy
  toggles), so Stage 1 needs no third-party agent installed in the guest. Sysmon would need a second
  install and config step. 4688 is the OS's own telemetry, which is the better analog to "auditd from
  the distro's own repos".
- The Event Log renders 4688 to XML whose fields (NewProcessName, CommandLine, ParentProcessName,
  SubjectUserName) map cleanly to banken's Event fields. A `parser.Windows4688` is a small, pure
  parser in the exact mould of `sysmon.go` (read XML lines, fill event.Event, register in
  Registry()).
- Acquisition at Stage 1 can be the simplest thing that works and stays CGO-free. Write `wevtutil qe
  Security /f:xml` (or a periodic evtx export) to a file, which banken tails through the one
  battle-tested file path it already has (cursor, rotation, inotify-or-poll follow). No live
  subscription, no ETW, no new runtime dependency.

Sysmon-for-Windows is the strong second source, and the one where banken is "half-written" because
the parser exists. It is Stage 1b, not Stage 1a, only because it adds an install/config step the OS's
own 4688 does not. Either way the parser work is small. The cost is acquisition and the platform
boundary (section 3).

The definition of done: a cross-compiled banken.exe runs on the Stage 0 Windows host, reads the
chosen source, and fires at least one Windows Sigma rule on a real process-creation event, alerting
to a file or webhook. This is the smallest valuable slice.

### Stage 2+: ETW, more channels, a service, a Windows sink

The large, open-ended surface. Scope it only after Stage 1. In rough order of value:

- **More channels.** PowerShell 4104 (script block logging) and Sysmon 1/3/11, each a parser plus
  acquisition. This is where Sigma's Windows depth starts paying off.
- **Live acquisition via ETW** instead of periodic evtx export, for real-time detection. ETW can be
  consumed CGO-free through `golang.org/x/sys/windows` (pure Go, an allowed dependency). But it is a
  large API surface (sessions, providers, manifests) and is the single biggest piece of Stage 2+.
- **A Windows service + scheduled-task deploy model**, the analog to the systemd unit + timer. This
  is also where banken's security model has to be re-grounded. On Linux the model is the unit's
  sandbox. Windows has no equivalent, so "what is banken's containment on Windows" is an open design
  question, not a port.
- **A Windows Event Log alert sink**, the analog to the journald sink. The current journald sink
  (`internal/alert/journal.go`) writes sd-daemon-prefixed lines to stderr. On Windows that is
  harmless (just stderr) but meaningless, so a real deployment wants events written to the Windows
  Event Log. The file/jsonl/webhook/OCSF sinks already work unchanged.
- **A Windows row (or node) in the live matrix running the detection objectives**, once there is a
  Windows objective set to run. The A-E objectives are auditd/systemd-shaped and do not map 1:1.

## 3. What is Linux-coupled in banken, and the platform boundary to add

The product cross-compiles, but "compiles" is not "runs cleanly as a Windows program". These are the
Linux assumptions that must sit behind a platform boundary so they neither fire nor mislead on
Windows. The pattern already in the engine is the right one to extend: a `_linux.go` / `_other.go` or
`_windows.go` pair behind a build tag. Prefer that over `runtime.GOOS` branches in shared code.

Already abstracted, and the template to keep:

- `internal/engine/stream_linux.go` (inotify) / `stream_other.go` (poll fallback) is the follow
  watcher. Windows gets the poll fallback today. A `stream_windows.go` using ReadDirectoryChangesW
  is a later nicety, not required.
- `internal/engine/stat_unix.go` / `stat_other.go` is inode-based rotation detection, with a size
  heuristic fallback off Unix.

Needs a boundary at Stage 1:

- **`internal/config/config.go:117` `candidateSources` and `AutoDetectSources`** hardcode Linux paths
  (`/var/log/laurel/audit.log`, `/var/log/audit/audit.log`). On Windows these never exist, so
  auto-detect silently finds nothing. Split the candidate list by platform (a `candidates_linux.go` /
  `candidates_windows.go`) so `banken` with no config auto-detects the Windows source.
- **`auditcheck.go`** reads `/etc/audit/rules.d` and `/etc/audit/audit.rules`, and in main.go prints
  augenrules advice. On Windows the glob is empty, so it is harmless, but the advice is Linux-only UX.
  Put the audit-blindspot check behind a build tag (no-op on Windows), or gate it on the source type.
- **The source set itself.** auditd, laurel, journald, syslog and mimi are Linux-origin parsers.
  They stay registered and are harmless, since they just never match a Windows file. But AutoDetect
  and the docs must not offer them on Windows. The sysmon parser is cross-platform at the parse
  layer. Only the acquisition differs.
- **Deployment.** `module.nix`, the systemd unit and timer, and the whole "security model is the
  unit sandbox" story are Linux. Windows deployment (service + scheduled task) is new, not a port,
  and is Stage 2+.

Harmless on Windows. Note these, but do not block Stage 1:

- `internal/alert/journal.go` sd-daemon `<N>` prefixes are meaningless off systemd but do no harm.
  The outside-systemd path already drops the prefix when `JOURNAL_STREAM` is unset. A real Windows
  Event Log sink is Stage 2+.
- `syscall.SIGTERM` in main.go (signal handling) is defined on Windows in Go's syscall package, so
  it compiles. Ctrl-C / service-stop semantics differ, but the build is fine.

## 4. Provisioning specifics (Stage 0 detail)

The Linux matrix (tests/distros) works because every vendor publishes a cloud image (a qcow2) with
three properties. It boots unattended. It is seeded by cloud-init from a one-line NoCloud ISO. And it
can be pinned by the vendor's own checksum (tests/distros/distros.json: url + sha256/sha512 + package
manager + the package providing each needed command). A Windows guest is the analog, and every one of
those properties is harder on Windows. The honest unknowns, each to retire in Stage 0:

- **Image.** There is no official Windows "cloud qcow2". The realistic source is the Windows Server
  **evaluation** media from Microsoft (a 180-day eval ISO or a prebuilt eval VHD). Stage 0 either
  builds a bootable qcow2/VHD from the eval ISO (unattend.xml for the install, virtio drivers
  injected) or converts a prebuilt eval VHD. This build step has no Linux equivalent in the current
  matrix and is the bulk of Stage 0.
- **cloud-init analog: cloudbase-init.** This is the Windows port of cloud-init. It reads a
  NoCloud-style config drive (the same ISO shape the Linux matrix already builds) and runs a
  first-boot script. This is the mechanism that makes "boot and run the checker from the seed" work
  on Windows. Its maturity and its NoCloud datasource behaviour under QEMU are an unknown to verify,
  not assume.
- **virtio drivers.** Windows has no in-box virtio, so the image must carry the Fedora virtio-win
  drivers (storage + net), or the guest will not see its disk or network under KVM. These are
  injected at image-build time.
- **Licensing / eval limits.** The eval media is time-bombed (180 days, with rearm). That is fine for
  a test node but means the image is not "pin once forever". The pinned image ages out, and the clock
  is a recorded property, as the Linux matrix records kernel and systemd version. No product key and
  no activation. The eval terms must permit this use (verify before shipping anything public).
- **Egress.** The walled host already allows `packages.microsoft.com` (used by the Sysmon-for-Linux
  stage). The Windows eval media and virtio drivers come from other Microsoft/Red Hat hosts
  (`software-static.download.prss.microsoft.com` / `go.microsoft.com` for the eval ISO,
  `fedorapeople.org` for virtio-win). Those hosts are not on the allow-list today and would need
  adding, the same way `acc.umu.se` was added for Debian's redirect. This is a Conor config change,
  since the allow-list is deployed, not worked around. Flag it as a blocker the moment Stage 0 needs
  it.
- **KVM as the claude user.** The Linux matrix already proves claude can run QEMU/KVM on hokkaido.
  A Windows guest is heavier (more RAM, a real disk, minutes to boot vs seconds), so the
  `-test.parallel` budgets and the 4h matrix timeout will need headroom. Not a blocker, a sizing
  note.
- **Reachability / the checker.** The Linux checker writes its JSON report to the serial console and
  powers off. A Windows guest can write to a virtio serial port too (cloudbase-init can run a script
  that does), so the same report-over-serial shape is plausible. Confirm it in Stage 0 rather than
  design a WinRM/SSH path first.

## 5. The payoff

If Stage 1 lands, Windows coverage can grow faster than Linux did, because the detection content is
already there. Linux detection content had to be built or adapted. Linux Sigma is a minority of
SigmaHQ, and auditd's record shape needed the folding and multi-value handling in event.go. Windows
is the opposite. The SigmaHQ corpus is Windows-first, banken's Event fields already match the Windows
Sigma field names, and PR #24's logsource routing is built to route `product: windows`. Each new
Windows channel (4688, 4104, Sysmon) unlocks a large block of existing rules the moment its parser
exists. The marginal cost per channel is a small parser plus acquisition, not rule authoring. So the
honest upside is real. The hard part is the first source and the platform boundary. After that,
breadth is cheap.

## 6. Risks and unknowns

- **ETW scope (Stage 2).** Pure-Go ETW consumption (via `golang.org/x/sys/windows`) is possible and
  CGO-free, but it is a large API and the biggest single unknown past Stage 1. Stage 1 deliberately
  avoids it (periodic evtx export).
- **Staying CGO-free.** `golang.org/x/sys/windows` is pure Go and an acceptable dependency; the
  CGO-free, static-binary property holds on Windows. Verify no transitive dependency pulls cgo in
  when the first Windows acquisition code lands.
- **Eval clock.** The 180-day eval and rearm mean the Windows node is not a set-and-forget pin; the
  image refresh is recurring maintenance.
- **cloudbase-init under QEMU.** NoCloud datasource behaviour, first-boot timing, and serial-console
  output are the Stage 0 unknowns most likely to bite.
- **Security model.** banken's Linux security story is the systemd sandbox. Windows has no equivalent;
  "what contains banken on Windows" is an open design question for Stage 2+, not a port.
- **Objective set.** The matrix's A-E objectives are auditd/systemd-shaped. A Windows node needs its
  own objective set before it can run detection objectives; Stage 0 is boot-and-reach only.
- **Matrix cost.** A Windows guest is heavy; running it in the same `nix run .#distro-matrix` grid
  may want it gated behind its own flake output (as the mimi and Sysmon stages are), not on by
  default.

## 7. Non-goals

- Not porting auditd, the eBPF sensor (mimi) or Sysmon-for-Linux's acquisition to Windows. Windows
  has its own telemetry; the Linux sources stay Linux.
- Not writing a kernel driver or an ETW kernel provider. banken is a user-mode reader on Windows too.
- Not authoring Windows-specific detection rules beyond wiring the existing SigmaHQ Windows corpus
  through banken; new rule content is the rule lane's work, not this one.
- Not an MSI installer, a GUI, or deployment polish in Stage 0/1. Service packaging is Stage 2+.
- Not making Windows a first-class peer of Linux up front. Windows is additive; Linux stays the
  primary, proven platform, and nothing here changes the Linux product.
- Not committing to Stage 2+ as a deliverable before Stage 1 proves the shape on real telemetry.

## 8. Project note for the task tracker

These seed under `project:banken.sources +windows` to sit beside the other source work (Sysmon,
journald, syslog). That is the pragmatic choice while the work is "one more source". A dedicated
`project:banken.windows` is cleaner once Windows grows past Stage 1 into acquisition, a service model
and its own matrix node. At that point it is a platform, not a source. It will accumulate
provisioning, packaging and security-model tasks that are not "a parser". So start under
`banken.sources +windows` and split to `banken.windows` at Stage 2.
