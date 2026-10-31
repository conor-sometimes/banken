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

## Live (`run-live.sh`, SANDBOX host with auditd — hokkaido)
Actually executes the atomics so auditd captures the real behaviour, then runs
`banken` over the log and scores — the faithful scorecard. It **refuses to run
unless `/run/banken-range-sandbox` exists** (never a real host). `attackrange.py
--emit` feeds it the atomics as NDJSON. Finalised/tested on hokkaido (this Mac
has no auditd).

Run it nightly/in CI (on the sandbox) as a **regression that fails if coverage
drops**, and as the scored range for the purple-team CTF.
