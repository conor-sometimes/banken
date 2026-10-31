# Windows support (scaffold)

banken reads the Linux audit log; this is the scaffold for reading **Windows** telemetry too, so the
same engine, OCSF output and SigmaHQ rules work on Windows hosts. It is a foundation, not finished
support — enough to prove the shape and to run a real Sysmon log end to end.

## Why it fits with almost no new machinery

banken's whole design is "a parser normalises a source into one `event.Event`, and everything
downstream is source-agnostic" (see `internal/parser`). A Windows process-creation event carries the
same facts as a Linux exec — which program, its command line, its parent, the user, the pids — so it
maps onto the very same `event.Event` fields, and a SigmaHQ **Windows** `process_creation` rule
matches it with no translation. Windows-specific fields that have no typed home (`Hashes`,
`IntegrityLevel`, `TargetObject`, ...) go into `Event.Raw` under their own name, and `Event.Field`
falls back to `Raw`, so a rule keying on them works with **zero code change**.

## What the scaffold has

- **A native Sysmon parser** (`internal/parser/sysmon.go`, source name `sysmon`). It reads Windows
  Event Log **XML** — the native render of `wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml`,
  of PowerShell `Get-WinEvent ... | % { $_.ToXml() }`, and of what shippers (Vector's
  `windows_event_log`, winlogbeat) forward. EventID 1 (Process Create) fills Image / CommandLine /
  ParentImage / CurrentDirectory / User / ProcessId / ParentProcessId; EventID 11 (FileCreate) fills
  TargetFilename; every other `EventData` field, and the EventID itself, goes to `Raw`. It holds the
  parser contract: never panics, skips a record it can't read, errors only on an I/O failure
  (`FuzzParseSysmon`, 1M+ execs clean).
- **One example rule** (`rules/windows/powershell_encoded_command.yml`) with a fixture and OCSF
  golden, proving the path end to end: raw Sysmon XML → `sysmon` parser → engine → an OCSF 1.3.0
  Detection Finding.
- **Both-separator basenames** in the OCSF mapper, so a Windows finding reads `powershell.exe`, not
  the whole `C:\...` path. (Unchanged for Linux: identical to `path.Base` on a forward-slash path.)

## How to run it (on a real Windows host)

Install Sysmon with a config (SwiftOnSecurity's is the usual baseline), then export its log and point
banken at it:

```powershell
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /e:Events > sysmon.xml
```

```sh
banken -source sysmon:sysmon.xml -jsonl-dir ./alerts -jsonl-format ocsf
```

A shipper that forwards the Event Log as XML (or that renders it to banken's own JSON and uses the
`generic` source) is the continuous path; the one-shot export above is the quickest live test.

## What is NOT done yet (the roadmap, tracked as tasks)

- **Logsource-aware routing.** banken matches every rule against every event. Field shape keeps a
  Windows rule from matching a Linux event and vice versa, so it is not *wrong*, but it is not
  intentional and won't scale to SigmaHQ's thousands of Windows rules. Honouring Sigma
  `logsource.product`/`category` (map `sysmon`→windows, auditd/laurel→linux) is the next piece, and
  the enabler for loading the Windows ruleset.
- **More event types as first-class.** Registry (13), network (3) and image-load (7) events are
  ingested (into `Raw`) but have no typed fields, so their OCSF findings are thinner (they assume a
  process). First-class `TargetObject` etc. would enrich them.
- **Windows 4688 / Security log** (process creation without Sysmon) uses different field names
  (`NewProcessName`, `ParentProcessName`); a second mapping or a small alias table would cover hosts
  without Sysmon.
- **SigmaHQ Windows rule coverage**, measured by `sigmacov` once routing exists.
