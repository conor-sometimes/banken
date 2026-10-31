# Red-team account — purple-teaming banken on a live host

A standing invitation to find where banken is blind, on a real system rather than a VM. An AI
operator logs in as the contained `redteam` user on hokkaido, plays an attacker who has just
landed an unprivileged shell, runs **benign stand-ins** of attacker behaviour, and we score
banken's alerts against a ground-truth log the operator keeps. The misses are the product: each
one is a rule to write or tune (the same loop the [ATT&CK range](../../attackrange/README.md)
runs, but interactive and on a live host).

This is defensive work: banken is Conor's own EDR, the host is his own test box, the account is
contained with no egress, and nothing here touches a real secret, a real remote host, or anything
outside the account's own scratch space. The goal is a better detector, measured honestly.

## Rules of engagement

Every action holds to the emulations' [safety contract](../emulations/README.md#safety-contract),
and to these:

- **Benign stand-ins only.** Imitate the *shape* of a behaviour so it produces the same audit
  events — exec a harmless placeholder under a tool's name, read dummy data from a scratch dir,
  connect to an unroutable TEST-NET address (`192.0.2.0/24`) with a short timeout. Never run real
  malware, a real exploit, or a real attack tool against anything.
- **This account only.** Stay inside `redteam`'s own home and `mktemp` scratch. No touching other
  users' files, no attempts against other hosts (there is no egress anyway), no shared-system
  resources. The containment wall enforces this; the rules of engagement mean not even trying.
- **No privilege escalation for real.** A `sudo`/`su` *attempt* is a valid thing to test (banken
  should alert on it), but do not attempt to actually gain root, exploit the kernel, or break
  containment. The attempt is the signal; the breakout is out of scope.
- **Nothing destructive, nothing persistent.** No deleting or encrypting real data, no real
  cron/unit/rc changes that outlive the session, no fork bombs or resource exhaustion. Clean up
  after each run.
- **Keep ground truth.** Append every action to `~/redteam-log.ndjson` as
  `{"t": "<iso8601>", "technique": "<id or name>", "command": "<what ran>", "expect": "<rule or 'none'>"}`
  before running it, so banken's alerts can be scored against what was actually done — including
  the actions that *should* stay quiet (a false-positive check).

If an action cannot be done within this contract, it does not belong here. The point is never to
harm the host; it is to learn what banken does and does not see, and to write that down.

## How a session goes

1. Read this file and the [emulations](../emulations/README.md) for the house style.
2. Pick a behaviour to test — start from ATT&CK tactics banken claims to cover, then the gaps the
   range flagged (credentials-in-files, history clearing, shell variants; see the project tasks).
3. Log it to `~/redteam-log.ndjson`, run the benign stand-in, note the time.
4. After a scan interval, read banken's alerts (`journalctl -u banken -p err`, or
   `/var/log/banken/alerts-*.jsonl`) and record whether the expected rule fired.
5. At the end, score: detections, misses, and any false positive on an action that should have
   stayed quiet. Each miss becomes a rule task in the banken repo.

## The two accounts

- **`redteam`** (uid 1102): the scored harness above — tight limits, no egress, no Nix builds.
- **`lab`** (uid 1103): a freer-range version of the same idea — still no egress, but roomier
  limits and fewer restrictions, so a session can move around a realistic multi-step scenario
  (land, look around, stage, "exfil" to a dead address) rather than one probe at a time. Same
  rules of engagement; same ground-truth log.

Both are contained by [nixos-agent-containment](https://github.com/conor-sometimes/nixos-agent-containment):
per-user audit trail, egress wall, resource limits. banken watches both through the host's Laurel
log, exactly as it watches everything else.
