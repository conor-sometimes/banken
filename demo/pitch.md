# banken: an early, honest look

A host EDR for Linux, written from scratch in Go. It reads the Linux audit log (and its own eBPF
sensor, mimi), matches Sigma-style rules, and emits OCSF findings a SIEM can read. It is PRE-ALPHA:
early, rough, and missing a lot. But the parts that exist are real, and you can run them yourself.

The project is a "can I build the honest middle between a free firehose like auditd and a
hundred-megabyte commercial agent" experiment. Built solo (with AI agents, under direction).

## What it already does, and you can re-run it

- Catches a reverse shell end to end in **under 300 ms** off the eBPF sensor (299 ms measured
  2026-11-02; demo/banken-demo-mimi.txt), and the alert is a standard **OCSF 1.3.0 Detection
  Finding** with the MITRE ATT&CK technique attached, not a log line.
- Ships **38 attacker-behaviour detections enabled by default** (9 of them for AI-agent accounts):
  reverse shells, credential theft, privilege escalation, persistence, log and audit tampering,
  defence evasion, and more, each mapped to ATT&CK (rules/). It can also load SigmaHQ's ~210 Linux
  rules on top.
- Coverage is **measured, not claimed**: a live Atomic Red Team range scores it per technique --
  **24 of 115 ATT&CK techniques on merit** as of 2026-11-01, an honest number that is rising.
- Stays **quiet on a normal day**: an ordinary admin workload raises zero alerts (proven on a normal
  day's work, not a promise of zero false positives forever).
- Runs green on **8 real distros** (Rocky, Alma, Fedora, Amazon Linux, Debian, Ubuntu, openSUSE,
  Arch) on each one's own kernel, plus NixOS, in a live VM matrix.
- Is **one static 7.0 MiB binary**, ~14 MiB RAM, **no kernel module** (a bug is a missed detection,
  never a kernel panic), under a hardened systemd sandbox.

Run the exact proof yourself:

```sh
nix run github:conor-sometimes/banken#demo        # catch a reverse shell on the auditd floor
nix run github:conor-sometimes/banken#demo-mimi   # the sub-second catch off the eBPF sensor
```

Each boots a throwaway VM, runs a benign reverse-shell-shaped command, and shows the finding land
with the measured latency. Re-runnable is the whole point: nothing here is a recording to trust.

## What it is NOT, yet

- **No response.** It detects; it does not kill, quarantine, or isolate. (Designed, not built.)
- **Linux only.** No Windows, no macOS.
- **Pre-alpha.** Rough edges, breaking changes, not deployed anywhere real, not hardened for
  production. Do not run it expecting a product.
- Coverage is partial (24/115), the default rule set is small (38), and plenty is half-built or on a
  roadmap.

That is the honest state: early, but the foundations are real and everything above is reproducible.
