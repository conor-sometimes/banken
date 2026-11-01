# Deployment

The goal is no fiddling: install the binary, point it at the audit log, enable the timer. banken
ships an embedded baseline ruleset and auto-detects the log source, so there is little to configure.

**One line, if you run NixOS:** add the module and set `services.banken.enable = true;` - that pulls
in auditd with the rules banken reads, the hardened unit and the timer, alerting to the journal (see
[NixOS](#nixos)). On any other systemd Linux it is the three-command [Quickstart](#quickstart-any-systemd-linux)
below. Either way the defaults are a working deployment; the rest of this page is the optional knobs.

## Supported platforms

**Linux with systemd** on x86_64 (aarch64 builds but is not yet tested). The live distro matrix
([tests/distros](../tests/distros/README.md)) runs banken against each distro's own kernel and
auditd: Rocky 9, AlmaLinux 10, Fedora 44, Amazon Linux 2023, Debian 13, Ubuntu 24.04, openSUSE
Leap 16 and Arch; NixOS is tested through its own module (`tests/vm.nix`).

systemd is a requirement, not a preference. banken runs as root and parses untrusted log bytes,
so its security model *is* the unit's sandbox ([Sandbox](#sandbox)): `ProtectSystem=strict`,
one capability, a syscall filter, no writable or executable memory. OpenRC and SysV init have no
equivalent, so a banken under them would be an unconfined root parser. The static binary runs
anywhere, but outside systemd it is unsupported.

## Quickstart (any systemd Linux)

1. Put the `banken` binary on `PATH` (a static `CGO_ENABLED=0` build runs on any Linux).
2. Make sure the host is auditing process execution (see [Log source](#log-source)).
3. Install the unit and timer and enable it:

   ```sh
   install -m0755 banken /usr/bin/banken
   install -m0644 packaging/systemd/banken.service packaging/systemd/banken.timer /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now banken.timer
   ```

With no config file, `banken` loads its embedded rules, auto-detects the source
(`/var/log/laurel/audit.log`, then `/var/log/audit/audit.log`), and alerts to the journal. When
`/etc/banken/banken.yml` exists it is read; it is only needed to add rule trees, change the source,
or enable the jsonl/webhook sinks. The unit runs `banken` with no flags either way.

The timer is `packaging/systemd/banken.timer`: first scan two minutes after boot, then every two
minutes, catching up a run missed while the machine was off.

Under systemd banken logs at the right priorities: alerts at `crit`/`err`, its own problems at
`warning`/`err`, progress at `info`. So `journalctl -u banken -p err` is the alert feed, and
anything else it shows at `warning` or above is banken telling you something is wrong.

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

Then `augenrules --load` (or `auditctl -R`). Two distro quirks to check first (both found by the
live distro matrix, [tests/distros](../tests/distros/README.md)):

- **`-a task,never` turns syscall auditing off entirely.** Fedora and openSUSE ship it in
  `/etc/audit/rules.d/audit.rules`. With it loaded the kernel emits no exec events, and banken runs
  cleanly while seeing nothing. Comment the line out before `augenrules --load`. banken checks for
  it on every run and logs a warning naming the file and line.
- **On RHEL 10 and its rebuilds, `auditctl` and `augenrules` are in a separate `audit-rules`
  package** that a cloud image may lack (seen on AlmaLinux 10): `dnf install audit-rules`.

[Laurel](https://github.com/threathunters-io/laurel) is
supported and recommended as an enricher (it turns the multi-line audit records into clean JSON),
but not required — the raw auditd parser reads `/var/log/audit/audit.log` directly.

## Configuration

Config is YAML; flags override it. The smallest useful config is **no config at all** - the
zero-config default above (embedded rules, auto-detected source, journal alerts) is a complete
deployment. A config file is only for adding to it.

A minimal config that turns on a second sink - copy, paste, edit one line:

```yaml
# /etc/banken/banken.yml
alerts:
  journal: { enable: true }                          # keep the default journal feed
  jsonl:   { enable: true, dir: /var/log/banken }    # plus one file of alerts per day
```

A fuller example with every common knob:

```yaml
rules: [/etc/banken/rules]          # extra trees, loaded on top of the embedded baseline
statePath: /var/lib/banken/cursor.json
sources:                            # omit to auto-detect
  - type: laurel
    path: /var/log/laurel/audit.log
alerts:
  journal: { enable: true }
  jsonl:   { enable: true, dir: /var/log/banken, retentionDays: 30 }   # format: ocsf | ecs to re-shape
  webhook: { enable: true, urlFile: /run/secrets/banken-webhook, style: slack }  # or style: ocsf
```

The jsonl sink's `format` picks the on-disk shape: `banken` (native, the default), `ocsf` (OCSF
1.3.0 Detection Findings for an OCSF-aware SIEM) or `ecs` (Elastic Common Schema for
Elasticsearch/Kibana). One finding per line in every case.

The webhook URL should come from a file (`urlFile`) - most webhook URLs embed a secret token
(Slack, Discord), and a secret never belongs inline in a config that may live in a Nix store or a
repo. Set the URL inline (`url:` / NixOS `alerts.webhook.url`) only for a genuinely non-secret
receiver. See the CLI flags with `banken -h` for one-off overrides (`-source type:path`,
`-jsonl-dir`, `-jsonl-format`, `-webhook-url-file`, `--watch`, …).

## Sandbox

`packaging/systemd/banken.service` runs the scan locked down: `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `MemoryDenyWriteExecute`,
`SystemCallFilter=@system-service`, writing only `/var/lib/banken` and reading only the audit logs,
with just `CAP_DAC_READ_SEARCH` to read the root-owned log. banken parses untrusted bytes as root,
so the sandbox shrinks the blast radius of a parser bug to almost nothing. See the
[README's Security model](../README.md#security-model) for why the rules themselves can't become a
code-execution vector.

## NixOS

First-class: `services.banken` (`module.nix`, exported as `nixosModules.default`) generates the
config at `/etc/banken/banken.yml`, the unit (this section's hardening, plus no network unless the
webhook is on), the timer, and by default auditd with banken's audit rules (`audit.enable`,
`audit.watchPaths`). `services.banken.enable = true` is the whole setup; see the README's
[Use (NixOS)](../README.md#use-nixos) for options. `tests/vm.nix` proves the module end to end.
