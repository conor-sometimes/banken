# ATT&CK range — Atomic Red Team → banken coverage scorecard

The attack-side counterpart to the Sigma conformance harness. It runs
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)'s Linux
atomics (benign, self-cleaning technique tests) and scores how many ATT&CK
techniques banken detects. Two fidelities:

## Dry run (`attackrange.py`, runs anywhere, no sandbox)
Parses each Linux `bash`/`sh` atomic's command, synthesises a process event
from it, and asks `banken check` whether a rule fires. Tests banken's
command-line / Image matching — a **lower bound**, since it can't reproduce the
real file (PATH) and network syscalls an atomic makes (rules keying on
`TargetFilename` or a live connection score higher against real telemetry).

```sh
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team /tmp/art
go build -o /tmp/banken ..          # from attackrange/, builds the repo root
uv run attackrange.py /tmp/art/atomics /tmp/banken
```

Baseline (this build): **22/116 Linux techniques detected in the dry run** — a
floor, not a ceiling. Many "missed" are recon/discovery (T1082/T1057/T1083…) a
behavioural EDR intentionally doesn't alert on, or file/network behaviours the
dry run can't synthesise; the live run and ongoing rule work raise it.

## Live (`tests/attackrange.nix`, a throwaway VM)
Actually executes every Linux bash/sh atomic of a pinned Atomic Red Team commit, as root, inside
a NixOS test VM with banken deployed by its own module, so auditd captures the real behaviour;
banken scans around each atomic and the rules that fired are recorded. Atomics run nowhere else:
the runner (`range.py`) refuses to start without the VM's sandbox marker, and the 13 atomics that
would end the range itself (shutdown/reboot, `rm -rf /`, sysrq) are skipped and reported as such.

```sh
nix-build tests/attackrange.nix      # needs KVM; ~30 min; $out holds scorecard.md/.json, results.ndjson
```

Scoring is honest by construction: `privilege_escalation_attempt` fires on any sudo, and many
atomics run their command through sudo, so a technique counts as detected "on merit" only if a
rule about it fired (any rule, for the T1548 privilege-escalation techniques themselves). The
scorecard reports both numbers.

Live runs (ART `e8cfc41`):
- 2026-10-31: **23/115 techniques on merit** (50/409 atomics); 40/115 with sudo-only hits.
- 2026-11-01, after adding `credential_search` and `history_tamper`: **24/115 on merit (71/409
  atomics)** -- credentials-in-files (T1552.001) went 0/21 -> 18/21, history clearing (T1070.003)
  0/10 -> 3/10 (the rest are shell builtins no exec-based EDR can see). +21 atomics from two rules.

Largest remaining misses, i.e. the rule roadmap: shell variants (T1059.004), permission changes
(T1222.002), private keys (T1552.004), timestomp/clear (T1070.006), the agentic set (scoped to
agent accounts, so they do not fire on the range's generic user).

Run it nightly/in CI (on the sandbox) as a **regression that fails if coverage
drops**, and as the scored range for the purple-team CTF.
