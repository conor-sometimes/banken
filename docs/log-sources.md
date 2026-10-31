# Log sources: how banken stays extensible across OSes

The short version: **adding a log source — on any OS — is adding a parser behind one interface, never an architecture change.** The seam already exists; this page is the plan for growing into it.

## The seam

Everything downstream of ingestion — the matcher, the rules, the cursor, the alert sinks — speaks exactly one language: the normalised [`event.Event`](../internal/event/event.go). A source is the *only* thing that knows its own format. The contract is two small pieces:

```go
// internal/parser
type Parser interface {
    Name() string                          // the Source tag it stamps on events
    Parse(r io.Reader) ([]event.Event, error) // normalise a source's bytes to events
}
```

plus a registry mapping a source name to its parser. To add a source you implement `Parse`, register it, and **nothing else changes** — the rules you already wrote match the new source's events because they match `Event` fields, not raw log lines.

Two consequences that make this cheap:

- **The `Event` is the cross-OS contract.** Its fields (`Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `User`, `CurrentDirectory`, …) are deliberately source- and OS-agnostic. A rule for "a shell spawned by a web server" is the same rule whether the exec came from Linux auditd, macOS ESF, or Windows Sysmon — each parser fills the same fields. New dimensions (pid/ppid/start-time, network tuples, hashes) are *added* to `Event`, never reshaped, so existing parsers and rules keep working.
- **`logsource` routing** (roadmap) lets a rule declare the platform/category it applies to, so a Windows-only rule is skipped on Linux events instead of running pointlessly. That's the one small addition that makes a mixed, cross-OS ruleset clean — not a rewrite, a filter.

## Two ways to add a source (pick the cheap one)

1. **A native Go parser** — for a format banken can read directly (journald, syslog/auth, Windows EVTX). Implement `Parser`, done. Best when the format is a stable text/structured log.

2. **The generic-JSONL adapter** — the *no-new-Go* path. A tiny external collector emits the common `Event` as one JSON object per line, and banken's generic-JSONL parser ingests it verbatim. This is the universal escape hatch: anything that can be shimmed to emit the normalised event plugs in **without a bespoke parser in banken**. It is the first thing to build, because it unblocks every exotic source at once.

Most OS-specific telemetry arrives best through (2): the OS-native collector (which needs platform APIs/entitlements banken shouldn't carry) runs as its own small helper and feeds banken JSONL.

## Per-OS roadmap

| OS | Source | Mechanism | How it plugs in | Status |
| --- | --- | --- | --- | --- |
| Linux | auditd | raw audit log | native parser | ✅ |
| Linux | Laurel | auditd→JSON | native parser | ✅ |
| Linux | journald | `sd-journal` / `journalctl -o json` | native parser (stub today) | 🔜 |
| Linux | syslog / auth | RFC 3164/5424 | native parser (stub today) | 🔜 |
| Linux | eBPF | Falco/Tetragon-style kernel probes | helper → generic JSONL (gains network + reliable pid/ppid + hashes) | 🔜 |
| macOS | Endpoint Security (ESF) | `EndpointSecurity.framework` (exec/file/network) | signed Swift/C helper (needs entitlement) → generic JSONL | 🔜 |
| macOS | Unified Log | `log stream --style ndjson` | helper → generic JSONL | 🔜 |
| Windows | Sysmon | Sysmon → Windows Event Log | collector → generic JSONL (SigmaHQ's Windows rules target Sysmon fields) | 🔜 |
| Windows | ETW | Event Tracing for Windows | collector → generic JSONL | 🔜 |
| any | generic JSONL | one normalised `Event` per line | **the adapter the rest build on** | 🔜 (build first) |

## Why this needs no rewrite

The engine holds no I/O of its own beyond an `io.Reader` through a `Parser`; the matcher is pure over `Event`; the sinks are pure over `Alert`. Growing to a new OS touches exactly one new file (a parser) — plus, once, the generic-JSONL adapter and `logsource` routing. The hard, platform-specific, privileged work (ESF entitlements, ETW sessions, eBPF programs) lives in *external helpers* that emit JSONL, so banken's core binary stays small, portable, and dependency-light on every OS.
