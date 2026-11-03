# ATT&CK range - Atomic Red Team -> banken coverage scorecard

The attack-side counterpart to the Sigma conformance harness. It runs
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)'s Linux atomics and
scores how many ATT&CK techniques banken detects. Atomics are benign, self-cleaning
technique tests.

It runs at two fidelities.

## Dry run (`attackrange.py`, runs anywhere, no sandbox)

For each Linux `bash`/`sh` atomic, it parses the command, synthesises a process event,
and asks `banken check` whether a rule fires. This tests banken's command-line and
Image matching.

The result is a **lower bound**. The dry run can't reproduce the real file (PATH) and
network syscalls an atomic makes. Rules keying on `TargetFilename` or a live connection
score higher against real telemetry.

```sh
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team /tmp/art
go build -o /tmp/banken ..          # from attackrange/, builds the repo root
uv run attackrange.py /tmp/art/atomics /tmp/banken
```

Baseline for this build: **22/116 Linux techniques detected in the dry run**. That is a
floor, not a ceiling. Many "missed" techniques are one of two kinds:

- recon/discovery (T1082/T1057/T1083...) that a behavioural EDR intentionally doesn't
  alert on
- file/network behaviours the dry run can't synthesise

The live run and ongoing rule work raise the number.

## Live (`tests/attackrange.nix`, a throwaway VM)

This actually executes every Linux bash/sh atomic of a pinned Atomic Red Team commit.
It runs them as root inside a NixOS test VM, with banken deployed by its own module, so
auditd captures the real behaviour. banken scans around each atomic and records the
rules that fired.

Atomics run nowhere else. The runner (`range.py`) refuses to start without the VM's
sandbox marker. 13 atomics would end the range itself (shutdown/reboot, `rm -rf /`,
sysrq); these are skipped and reported as such.

```sh
nix-build tests/attackrange.nix      # needs KVM; ~30 min; $out holds scorecard.md/.json, results.ndjson
```

Scoring is honest by construction. `privilege_escalation_attempt` fires on any sudo,
and many atomics run their command through sudo. So a technique counts as detected "on
merit" only if a rule about it fired. For the T1548 privilege-escalation techniques
themselves, any rule counts. The scorecard reports both numbers.

Live runs (ART `e8cfc41`):

- 2026-10-31: **23/115 techniques on merit** (50/409 atomics); 40/115 with sudo-only hits.
- 2026-11-01, after adding `credential_search` and `history_tamper`: **24/115 on merit
  (71/409 atomics)**. Credentials-in-files (T1552.001) went 0/21 -> 18/21. History
  clearing (T1070.003) went 0/10 -> 3/10; the rest are shell builtins no exec-based EDR
  can see. That is +21 atomics from two rules.

The largest remaining misses are the rule roadmap:

- shell variants (T1059.004)
- permission changes (T1222.002)
- private keys (T1552.004)
- timestomp/clear (T1070.006)
- the agentic set, scoped to agent accounts, so they do not fire on the range's generic user

Run it nightly or in CI, on the sandbox. It serves two purposes:

- a **regression that fails if coverage drops**
- the scored range for the purple-team CTF
