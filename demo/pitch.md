# banken: the one-page case for a two-week pilot

*A free, open, host-wide threat detector that catches the obvious attacks, maps them to MITRE
ATT&CK, and feeds the SIEM we already run -- with no per-endpoint licence and nothing that can take
a host down.*

This page is the leave-behind. Every figure is cited to its source in the banken repo, or clearly
labelled illustrative. Anyone can re-run the proof themselves (see "Reproducible", below).

## 1. It saves real money

Commercial host EDR is licensed per endpoint per year, on top of a sales cycle and annual renewals.
Industry list pricing is broadly in the **$50-$150 per endpoint per year** range (illustrative, not
a banken figure; tiers and discounts vary widely). banken is **MIT-licensed and free**, running on
hardware we already own and feeding the SIEM we already pay for.

| Fleet size | Commercial EDR licences / yr (illustrative) | banken licences / yr |
| --- | --- | --- |
| 500 endpoints | ~$25k - $75k | $0 |
| 2,000 endpoints | ~$100k - $300k | $0 |

The ranges are illustrative industry list pricing to show the shape of the saving, not a quote. The
point that does not move: banken's licence cost is zero and there is no vendor to negotiate with.

## 2. We won't get breached -- here is the proof, live

The centrepiece is a live catch anyone can reproduce. An attacker lands a reverse shell on a host;
banken catches it **in under a second**, and the alert is **already in the SIEM the SOC watches**,
as a standard finding with the **MITRE ATT&CK technique attached** (T1059.004, Command and Control).
No log-scraping glue, no waiting. Measured in a real run on 2026-11-02: exec-to-alert **299 ms** off
the eBPF sensor. (demo/banken-demo-mimi.txt; tests/switch.nix.)

Then breadth. banken ships its own curated roster of **38 attacker-behaviour detections enabled by
default** (9 of them specific to AI-agent accounts), each mapped to ATT&CK: reverse shells,
credential theft, privilege escalation, persistence, data destruction, log and audit tampering,
defence evasion and more. (rules/.) Coverage is **measured, not self-reported**: a live Atomic Red
Team range scores detection per technique, and as of 2026-11-01 banken detects **24 of 115 ATT&CK
techniques on merit** -- framed honestly as a real, measured number that is rising, with a published
roadmap for the gaps. (README.md line 163; attackrange/README.md.)

## 3. It cannot take the business down

Remember the July 2024 CrowdStrike outage: a bad update to a kernel component blue-screened machines
worldwide and grounded flights. banken **cannot** do that. It is **one static binary of 7.0 MiB**
with **no kernel module and no driver** -- a banken bug is a missed detection in userspace, never a
kernel panic. It is written in pure Go with whole classes of memory bug structurally impossible, and
runs under a hardened sandbox that scores a clean exposure rating. On a host it is tiny: **about
14 MiB of memory** with the baseline ruleset. (README.md Performance lines 342-345, Security model
lines 314-389; tests/distros objective D1; demo shows the static binary and the sandbox score live.)

## 4. No alert fatigue

A detector that cries wolf gets muted, and then it is useless. On a **normal day's work** banken
says **nothing**: the demo runs an ordinary admin workload and banken raises **zero** alerts, so the
SOC only hears from it when something is actually wrong. (This proves no false positives on normal
activity -- not a promise of zero false positives forever; the two-week pilot measures the real rate
on our own traffic.) (demo/demo.nix "quiet" step.)

## 5. The ask is small

Let us run banken on **one representative fleet segment for two weeks, observe-only**, feeding our
existing SIEM. Zero licence cost, no kernel driver to risk, no rip-and-replace -- it rides alongside
what we already have. We will bring back the real false-positive rate on our traffic and the ATT&CK
techniques it caught. The decision is a two-week pilot, not a procurement.

## Reproducible -- so you do not have to take our word for it

Burned by vendor demos before? This one is not a recording to trust. Our security lead can run the
**exact** demo on our own hardware and get the same result:

```sh
nix run github:conor-sometimes/banken#demo        # catch a reverse shell on the auditd floor
nix run github:conor-sometimes/banken#demo-mimi    # the sub-second catch off the eBPF sensor
```

Each boots a throwaway VM, runs a benign reverse-shell-shaped command, and shows the OCSF finding
land with the measured latency. That re-runnability is the honesty guarantee a slide deck can never
give.

## Honesty note

banken is early, and past the floor. It is free and open (MIT), but there is no prebuilt installer
yet (on non-NixOS Linux you build the one static binary yourself), a validated per-fleet memory/CPU
footprint across our distro mix is not yet measured (a single-host bench reports ~14 MiB resident),
and ATT&CK coverage (24/115 on merit) is deliberately reported as a measured, rising number rather
than a finished one. The two-week pilot is exactly how we turn these into numbers on our own fleet.

## Backup detail (for the security lead's questions)

- **Latency, precisely.** Sub-second is the eBPF-sensor push path (267 ms VM / 83 ms deployed /
  28-33 ms live hardware). On the auditd-only floor the match itself is ~10 us; end-to-end there is
  that compute plus at most one scan interval (tunable), so the interval is the knob, not the match.
  (tests/switch.nix; README.md Performance.)
- **SIEM integration.** Findings emit as OCSF 1.3.0 Detection Findings (validated in CI against the
  compiled schema), plus ECS 8.11.0 and OTLP/HTTP, so Security Lake, Splunk, Datadog or Elastic
  ingest them with no per-product mapping. OCSF is the schema, OTLP the pipe. (README.md Standards
  lines 156-166.)
- **Portability.** Proven green on 8 Linux distros plus NixOS on their own kernels, installed exactly
  as the docs say. (README.md lines 123-144; tests/distros/README.md.)
- **Rules you can read.** Detections are plain Sigma you can audit and extend; banken also loads the
  full SigmaHQ Linux rule set (210 rules at pinned release r2026-07-01) for compatibility.
  (README.md lines 81, 158, 242; conformance/.)
