# Optional rules (opt-in policy detections)

These rules ship in the binary like every other, but they are **held back by default**. Each carries

```yaml
optional: true
```

in its YAML, and banken does not run it unless the operator activates it by name.

## Why a rule is optional, not baseline

The shipped-on baseline is tuned for signal: a rule earns its place there only if a hit is suspicious
on almost any host. Some genuinely useful detections do not clear that bar because whether a hit
*means* anything depends entirely on the environment:

- `netcat` - nc/socat is a reverse-shell tool on a locked-down server and an everyday convenience on
  a developer box. Same bytes, opposite verdict.
- `password_cracker` - john/hashcat/hydra *are the job* on a security team's workstation and fire all
  day; anywhere else they are a credential attack.

Shipping these on by default would bury real alerts in noise on the hosts where the tool is normal.
Dropping them entirely would lose a detection the *other* hosts want. Optional is the resolution:
ship them, off, and let each host turn on the ones that fit its policy.

This is the home for a detection that is really a **policy choice** - "we don't run X here" - rather
than an unambiguous threat. (A tool that is suspicious everywhere stays in the baseline: ngrok,
cloudflared and tailscaled, for instance, ship *on* in `command-and-control/tunnel_tool`.)

## Activating them

An optional rule has three states. By rule name (the file basename), or `"*"` for all:

| State | How | Behaviour |
| --- | --- | --- |
| **off** | not named (default) | not evaluated - zero cost, zero noise |
| **observe** | `observeRules` / `-observe` | evaluated; hits **recorded** (jsonl, run summary) but marked `observed` so the paging sinks (journal, webhook) **skip** them - measure a rule's noise before it pages |
| **on** | `optionalRules` / `-optional` | a normal rule: pages per its level |

```nix
services.banken = {
  observeRules  = [ "netcat" ];           # watch quietly: recorded, never pages
  optionalRules = [ "password_cracker" ]; # page normally
};
```

```sh
banken -observe netcat                     # recorded, never pages
banken -optional netcat,password_cracker   # page; flag overrides the config
banken -optional '*'                       # every optional rule, paging
```

A rule named in **both** lists pages - the explicit enable wins over observe. A name that matches no
optional rule is **warned about at startup**: a mis-typed enable is a detection that silently is not
running, and banken never fails a detection silently.

The typical path: start a rule in `observeRules`, watch the jsonl record for a week (`observed: true`
entries), and if the hits are all real, move it to `optionalRules` so it pages - or if they are all
noise, drop it back to off. This is the audit-then-enforce loop, per rule, per host.

`banken check` evaluates optional rules too (it is a testing tool: you want to see everything that
could fire) and marks each optional hit `[optional: off unless activated]`, so a check hit is never
mistaken for a shipped-on detection.

## Rules here

- `netcat` - netcat (nc/ncat/netcat) or socat ran (MITRE T1095). The blanket policy alert on the
  tool; `reverse_shell` and `tunnel_tool` catch the specific malicious shapes host-wide.
- `password_cracker` - an offline cracker (john, hashcat) or online brute-force tool (hydra, medusa,
  ncrack, patator) ran (MITRE T1110).

## Writing your own

Add `optional: true` to any Sigma rule and drop it here (or anywhere in the tree - the flag is what
makes it opt-in, the directory is only where the shipped pack lives). Like every banken rule it needs
a fixture (`tests/fixtures/NAME.expect-<rule>.json`) and an OCSF golden; the test suite enforces both
for optional rules exactly as for baseline ones.
