# Emulations - benign malware look-alikes that must trip the rules

Each script here does the *harmless analogue* of something a real, named piece of malware is known
to do on a compromised host: read a credential, stage a "loot" archive, phone a C2, arrange to run
again. They exist to make the `rules/agent/` Sigma rules **fire**. A unit test can then confirm the
detection works end to end (script runs as the agent -> auditd -> Laurel -> matcher -> alert), not
just in theory.

## Safety contract (every script holds to this)

- **No real secrets.** Any "credential" is dummy data the script creates in its own `mktemp -d`
  scratch and deletes on exit. It never reads a real `~/.ssh`, keyring, token or wallet.
- **No real exfil.** Any "C2" is an unroutable address (`192.0.2.0/24`, TEST-NET-1, RFC 5737) with
  a short timeout. Nothing leaves the host. The egress wall would block it anyway. The point is the
  *attempt* in the audit log.
- **No real persistence or damage.** Anything "installed" goes to a scratch path and is removed.
  Nothing survives the run, touches a real unit/rc file, or needs privilege.
- **Reversible and quiet.** Each script is idempotent, cleans up after itself, and exits 0 whether
  or not the host "has" the thing it looks for.

The behaviour is real enough to generate the same audit events the malware would. The consequences
are not. If a script can't stay inside this contract, it doesn't belong here.

## Layout

- `<family>.sh` imitates a named family's observed behaviour. It may trip several rules, like the
  real thing. The header lists the family, the TTPs, and the rules it should fire.
- The unit test (`../run.sh` / the VM test) runs each script, then asserts exactly the expected
  rules fired (and the benign baseline fires nothing). The events a run produces are also saved as
  fixtures, so the fast, no-VM test can replay them.

| Script | Imitates | Expected rules |
| --- | --- | --- |
| `amos.sh` | AMOS / Atomic Stealer - harvest creds + wallets, stage, curl to C2 | credential_file_read, download_ip_to_tmp |
| `xmrig.sh` | XMRig / coin-miner dropper - fetch miner by IP into scratch, curl \| sh install | download_ip_to_tmp, pipe_to_shell |
| `revshell.sh` | Generic reverse-shell one-liners - bash /dev/tcp, python socket, nc -e | reverse_shell |
| `persist.sh` | Generic persistence - systemd user unit, shell rc edit (all in scratch) | persistence |
| `sudo_probe.sh` | Privilege-escalation probing - non-interactive sudo/doas | privilege_escalation_attempt |
| `tamper.sh` | T1562 Impair Defenses - stop/kill/remove banken, flush auditd (all harmless) | tamper_banken |

A few TTPs are unsafe to run live even in analogue: installing a real crontab, flushing audit rules
as root, stopping the real banken unit. The scripts avoid them, and the corresponding selections
are exercised by the checked-in `tests/fixtures/*.json` events instead. `tamper.sh` runs
`auditctl -D` only when unprivileged, where it cannot actually flush anything.

There is no `benign.sh` script for the benign baseline. It would just be ordinary activity. The
`*.expect-none.json` fixtures stand in for it, asserting everyday commands fire nothing.
