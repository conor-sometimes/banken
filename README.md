# banken

番犬 — "watchdog". A small, host-wide EDR: it watches the machine's logs on a timer, matches them
against Sigma rules and IOC lists, and alerts. One Go binary, no agent runtime, no Python — a
poor-man's SentinelOne you can actually read.

Not an agent thing: banken watches the *whole host*. A contained AI agent, a cron job, a logged-in
user — if it does something a rule flags, banken alerts. (The
[agent containment](https://github.com/conor-sometimes/nixos-agent-containment) is one consumer: it
adds its own tighter agent-specific rules on top.)

## How it works

    logs (auditd / journald / Laurel JSON / auth)  ->  banken [ parse -> normalise -> match ]  ->  alerts

One self-contained tool: banken **parses the logs itself**. A parser per source — raw auditd (the
multi-line execve/path/cwd records joined into one event), Laurel's JSON, journald, syslog/auth —
normalises to one common event that the rules match. A new log type is a new parser behind the same
interface; nothing else changes.

A systemd timer runs `banken` every interval; each run reads the events since the last cursor,
matches, and emits hits. One-shot by design — systemd owns the schedule, no daemon to babysit
(`banken --watch` for a self-timing daemon is a later add). Laurel stays supported as an input, but
banken no longer *needs* it: with the auditd parser the end state is `auditd + banken + a timer`.

## Rules

Portable [Sigma](https://github.com/SigmaHQ/sigma) YAML, organised so a rule's *home* says what it
is, plus plain IOC lists for bulk feeds:

    rules/
      credential-access/    persistence/    execution/
      command-and-control/  privilege-escalation/   ...   # behavioural rules, by ATT&CK tactic
      malware/<family>/                                    # family-specific signatures (IOCs unique to a family)
      ioc/*.txt                                            # bulk IOC lists (filenames, IPs, domains), one per line

- **Behavioural rules** detect a *behaviour*, not a family, so they live by tactic (reading a
  credential is `credential-access/` whether AMOS, RedLine or a human did it). The SigmaHQ Linux
  set drops in by the same scheme as a noisy baseline.
- **Family signatures** are Sigma too (an IOC is just a matched value), kept under `malware/<family>/`.
- **Bulk IOC feeds** (thousands of values) go in `ioc/*.txt` with a fast set lookup, not one Sigma
  file each.

banken evaluates the Sigma subset these use — `Image|endswith` / `CommandLine|contains` /
`TargetFilename|contains` value lists and `and`/`or`/parens conditions — with clear errors on a bad
rule. Fuller Sigma is added as rules need it.

## Alerts

Pluggable sinks, any combination:

- **journal** — high/critical to the system journal (syslog), a one-line login summary for admins.
- **jsonl** — one file per day of alerts, kept `retentionDays`, so retention is a file delete.
- **webhook** — POST the alert JSON to a URL (generic, or Slack/Discord/ntfy shaping). The URL is a
  secret: it comes from `alerts.webhook.urlFile` (sops/agenix or a systemd credential), never inline
  in the Nix store. The service runs as root, so the webhook host just needs to be reachable.

Matched alerts flow through one dispatch point, so **response actions** (kill a process, revoke a
key, isolate) slot in later without a redesign. For now: alert only.

## Use (NixOS)

    services.banken = {
      enable = true;
      interval = "2min";
      rules = [ ./rules ];                       # plus any extra rule trees
      alerts.webhook.urlFile = "/run/secrets/banken-webhook";
    };

## Testing

Heavily tested — the parsers especially, since they eat untrusted log bytes:

- `go test ./...` — table-driven cases for every parser and the matcher, plus the
  `tests/fixtures/*.json` events (`NAME.expect-<rule>.json` must fire that rule; `*.expect-none.json`
  must fire nothing).
- **Go fuzzing** (`go test -fuzz`) — `FuzzParseAuditd`, `FuzzParseLaurel`, `FuzzMatch`, …: random and
  malformed input must never panic or mis-normalise. A parser that crashes on a bad line is a denial
  of the detection itself.
- `tests/emulations/<family>.sh` — benign look-alikes of real malware (dummy data, unroutable "C2",
  cleaned up; see `tests/emulations/README.md`). The VM test runs each end to end and asserts the
  expected rules fire; their recorded events also seed the fixtures.
- **CI** (`.github/workflows`) runs `go test -race`, `go vet`, `golangci-lint`, a short fuzz smoke,
  and `nix flake check` (the module's VM test) on every push.

## Status

Early. v1 is Laurel-first input, the Sigma subset above, journal/jsonl/webhook alerts, one-shot
timer. Roadmap: `--watch` daemon mode, direct auditd ingestion (drop Laurel), journald and other
log sources, response actions, a tuned baseline over a week of real activity.

## Licence

GPL-3.0-or-later. Rules are plain Sigma — copy them out with `git subtree split rules/` if you want
them without the binary.
