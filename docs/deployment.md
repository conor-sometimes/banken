# Deployment

The goal is no fiddling: install the binary, point it at the audit log, enable the timer. banken
ships an embedded baseline ruleset and auto-detects the log source, so there is little to configure.

## Quickstart (any systemd Linux)

1. Put the `banken` binary on `PATH` (a static `CGO_ENABLED=0` build runs on any Linux).
2. Make sure the host is auditing process execution (see [Log source](#log-source)).
3. Install the unit and timer and enable it:

   ```sh
   install -m0755 banken /usr/bin/banken
   install -m0644 packaging/systemd/banken.service /etc/systemd/system/
   # a banken.timer (e.g. OnUnitActiveSec=2min) drives it; see below
   systemctl enable --now banken.timer
   ```

With no config file, `banken` loads its embedded rules, auto-detects the source
(`/var/log/laurel/audit.log`, then `/var/log/audit/audit.log`), and alerts to the journal. A config
file is only needed to add rule trees, change the source, or enable the jsonl/webhook sinks.

A matching `banken.timer` (ship alongside the unit):

```ini
[Unit]
Description=Run banken on a schedule
[Timer]
OnBootSec=1min
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
```

The interval is the main detection-latency knob: a threat is flagged within one interval of being
logged (plus ~microseconds of matching — see [Performance](../README.md#performance)). Shorten it,
or run `banken --watch` as a daemon, for lower latency.

## Log source

banken reads the audit log; it does not hook syscalls itself. The host needs auditd capturing
execve (and the file accesses you care about). A minimal rule set:

```
# /etc/audit/rules.d/banken.rules
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
```

Then `augenrules --load` (or `auditctl -R`). [Laurel](https://github.com/threathunters-io/laurel) is
supported and recommended as an enricher (it turns the multi-line audit records into clean JSON),
but not required — the raw auditd parser reads `/var/log/audit/audit.log` directly.

## Configuration

Config is YAML; flags override it. A fuller example:

```yaml
rules: [/etc/banken/rules]          # extra trees, loaded on top of the embedded baseline
statePath: /var/lib/banken/cursor.json
sources:                            # omit to auto-detect
  - type: laurel
    path: /var/log/laurel/audit.log
alerts:
  journal: { enable: true }
  jsonl:   { enable: true, dir: /var/log/banken, retentionDays: 30 }   # format: ocsf for OCSF
  webhook: { enable: true, urlFile: /run/secrets/banken-webhook, style: slack }  # or style: ocsf
```

The webhook URL is **always** read from a file (`urlFile`) — a secret never belongs inline in a
config that may live in a store or a repo. See the CLI flags with `banken -h` for one-off overrides
(`-source type:path`, `-jsonl-dir`, `-webhook-url-file`, `--watch`, …).

## Sandbox

`packaging/systemd/banken.service` runs the scan locked down: `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `MemoryDenyWriteExecute`,
`SystemCallFilter=@system-service`, writing only `/var/lib/banken` and reading only the audit logs,
with just `CAP_DAC_READ_SEARCH` to read the root-owned log. banken parses untrusted bytes as root,
so the sandbox shrinks the blast radius of a parser bug to almost nothing. See the
[README's Security model](../README.md#security-model) for why the rules themselves can't become a
code-execution vector.

## NixOS

A first-class NixOS module (`services.banken`) that generates the hardened unit, timer, webhook
secret wiring and a VM test is on the roadmap (the containment flake will consume banken as an
input). Until it lands, use the portable unit above on NixOS too.
