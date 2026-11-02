# Syslog / auth as a banken telemetry source

Status: design + scouting, 2026-11-02. Today this source is a stub: `internal/parser/stub.go`
defines `Syslog{}` (lines 33-48), it drains its reader and emits nothing, and it is registered in
`parser.Registry()` under the name "syslog" (`internal/parser/parser.go:108`). `docs/log-sources.md`
(line 39) lists it as a native parser, status planned. This doc is the scouting behind filling that
stub in, and the honest verdict that it is NOT just a parser: auth/login telemetry is a different
signal class from process execution, so it also needs event-model work and a routing dependency
before a single auth rule can fire cleanly.

This source is about AUTH/login telemetry: failed and successful ssh logins, sudo, su, and PAM
session events. That is a different signal class from the process_creation events every working
source (auditd, Laurel, mimi, Sysmon) produces today, and it is the signal the honeypot and fleet
stories want most: who tried to get in, from where, with what account, and did they succeed.

## 1. Current state, in the code

- **The source seam.** Every source implements one interface, `parser.Parser`
  (`internal/parser/parser.go:24-35`): `Name() string` and `Parse(io.Reader) ([]event.Event, error)`.
  `scanLines` (`parser.go:52-80`) is the shared, fuzz-tested line reader every parser builds on: it
  never fails on content, caps a line at 1 MiB, and drops what it cannot read. The registry
  (`parser.go:101-111`) maps a source name to its parser; "syslog" already has a slot pointing at the
  stub.
- **The stub.** `Syslog{}` (`internal/parser/stub.go:39-48`): `Name()` returns "syslog", `Parse`
  copies the reader to `io.Discard` and returns no events. Wiring it up later is filling `Parse` in;
  nothing else in the seam changes. The TODO already names the target lines: "sshd accepted/failed
  logins, sudo sessions".
- **The event model is exec-shaped.** `event.Event` (`internal/event/event.go:25-88`) carries
  `Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `User`, `CurrentDirectory`, `PID`, `PPID`,
  `ProcessStart`, plus `Raw`/`Multi` maps. Of these, only `User` fits an auth event. There is no
  first-class field for a source IP, an outcome (success/fail), an auth service (sshd/sudo/su), an
  auth method (password/publickey), or a source port. `Event.Field` (`event.go:93-131`) resolves a
  fixed set of named exec fields and then `Raw`/`Multi`. So an auth event today can only be carried
  as loose `Raw` keys plus the raw message text, which AllText (`event.go:157-177`) exposes to
  keyword matching. That is enough to fire a keyword rule, but not enough to model "N failed logins
  from one IP in M seconds" as structured fields.
- **No logsource routing.** The matcher runs EVERY rule against EVERY event: `Engine.Match`
  (`internal/engine/engine.go:37-39`) calls `matcher.Match(ev)` (`internal/sigma/matcher.go:134`),
  and the `Rule` struct (`internal/sigma/rule.go:21-56`) does not parse or carry a `logsource:` block
  at all - `load.go` ignores it. `docs/writing-rules.md:57` and `docs/log-sources.md:22` both flag
  logsource routing as roadmap, not built. This matters directly here: with no routing, auth events
  would be fed to all 59 process_creation rules (noise and wasted work), and any new auth rules would
  be fed every process exec. Routing is a hard precondition for a clean auth source, not a nicety.
- **Every shipped rule is process_creation.** All 59 rules under `rules/` declare
  `product: linux`, `category: process_creation` (a `grep` over `rules/` shows 59 of each and no
  other category). There are zero auth/login rules today, so this source ships with no detections
  until we add them (section 6).
- **OCSF output is a finding, not raw telemetry.** `internal/alert/ocsf.go` emits an OCSF Detection
  Finding, class_uid 2004 (`ocsf.go:94`), when a rule matches. Its evidence is process-shaped:
  `ocsfEvidences` (`ocsf.go:398-428`) builds an `ocsfProcess` from `Image`/`CommandLine`/`User`/
  parent. There is no actor/src_endpoint shape, and OCSF Authentication (class 3002) appears nowhere
  in the tree. banken does not emit raw telemetry as OCSF; it emits findings. So "OCSF 3002" here is
  not a new emitted class - it is a vocabulary to borrow for an auth-shaped evidence block on the
  2004 finding (section 4).
- **The sandbox already reads /var/log as root.** The NixOS unit (`module.nix:393-396`) runs banken
  as root with `CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH" ]`, `ProtectSystem = "strict"`,
  `NoNewPrivileges`. It reads root-owned logs under /var/log today. Reading /var/log/auth.log or
  /var/log/secure needs no new privilege. The journald-only case has a precedent already in the tree
  (section 5).
- **Auto-detection and config.** `candidateSources` (`internal/config/config.go:117-120`) lists only
  laurel and auditd; an auth source adds auth.log/secure candidates there. A source is configured as
  `{ type = "syslog"; path = "..."; }` and dispatched by `parser.Registry()` in
  `scanSources`/`watch` (`main.go:222-253`, `main.go:285-351`).

## 2. What the bytes actually look like

RFC 3164 (BSD syslog) and RFC 5424 (modern syslog) describe the syslog FRAME: a priority, a
timestamp, a hostname, and a tag. That framing is the easy part and is well specified. The real work
is NOT the RFC frame.

The content of an auth.log / secure line is a free-text application message written by sshd, sudo,
su, or a PAM module. It is not a structured RFC field set; it is a human sentence with a per-program
grammar. A representative RFC 3164 line:

    Nov  2 11:03:21 host sshd[2111]: Failed password for invalid user admin from 203.0.113.9 port 54122 ssh2

The frame is `Nov  2 11:03:21 host sshd[2111]:`; everything after the colon is sshd's own text. So
parsing splits in two:

1. **Frame parse.** Strip the RFC 3164 or RFC 5424 frame to get timestamp, hostname, program tag
   (`sshd`, `sudo`, `su`, `CRON`), and pid. RFC 3164 timestamps carry no year and no timezone (a
   known weakness; infer the year from file mtime / current time, keep it best-effort as every banken
   field is). RFC 5424 lines (`<PRI>1 2026-11-02T11:03:21.000Z host sshd 2111 - - ...`) carry a real
   ISO timestamp and are simpler. The `Sysmon` parser already shows banken's house approach to a
   syslog-wrapped payload: find the payload inside the line and parse that
   (`internal/parser/sysmon.go:52-56`); the auth parser does the frame equivalent.
2. **Message grammar.** Match the program's message against a small, enumerated set of line
   patterns. This is the actual engineering, and it must be a curated, tested table, not open-ended
   regex soup (house rule: no unexplained magic constants). The key lines to cover in v1:

   sshd (the honeypot's bread and butter):
   - `Accepted password for USER from IP port PORT ssh2` (successful login, password)
   - `Accepted publickey for USER from IP port PORT ssh2: RSA SHA256:...` (successful, key)
   - `Failed password for USER from IP port PORT ssh2` (failed login)
   - `Failed password for invalid user USER from IP port PORT ssh2` (failed, nonexistent account)
   - `Invalid user USER from IP port PORT`
   - `Connection closed by authenticating user USER IP port PORT [preauth]`
   - `Disconnected from authenticating user USER IP port PORT [preauth]`
   - `message repeated N times: [ Failed password ... ]` (rsyslog dedup; one line is N events)

   sudo:
   - `USER : TTY=... ; PWD=... ; USER=root ; COMMAND=/path/to/cmd` (sudo invocation, the command run)
   - `USER : command not allowed ; ...` and `USER : N incorrect password attempts ; ...` (sudo abuse)

   su:
   - `(to root) USER on pts/0` / `pam_unix(su:session): session opened for user root(uid=0) by USER`
   - `FAILED su for root by USER`

   PAM (shared across services):
   - `pam_unix(sshd:auth): authentication failure; logname= uid=0 ... rhost=IP user=USER`
   - `pam_unix(sshd:session): session opened for user USER(uid=1000) by (uid=0)`
   - `pam_unix(...:session): session closed for user USER`
   - `pam_unix(cron:session): session opened ...` (noise to classify, often filtered)

   The parser extracts USER, IP, PORT, service, method, and outcome from each matched pattern into
   the structured fields (section 3); an unmatched line is still emitted carrying its raw message in
   `Raw` so keyword rules and provenance survive, never dropped. Unmatched is the common case for the
   long tail of programs, and that is fine.

Non-RFC reality to design around: rsyslog "message repeated N times" collapsing, multi-line messages
(rare in auth), locale-dependent month names in RFC 3164, and the fact that distros mix facilities
into one file. The parser must treat the whole thing as untrusted bytes, per the parser contract.

## 3. The event-model decision (recommendation)

**banken needs new auth fields on `event.Event`, plus an event-kind discriminator. This is
event-model work, not only a parser.** The reasoning:

- An auth login is not an exec. The matcher's whole contract is `Event.Field` / `Values` / `AllText`
  over named fields (`internal/event/event.go`). SigmaHQ's Linux auth corpus (the `linux/builtin`
  sshd/sudo/auth rules) keys on fields like `User`, a source address, and an outcome - none of which
  exist as named fields today. Shoving them only into `Raw` works for crude keyword matching but
  cannot express the structured, correlated detections that are the entire point (brute force = count
  failures per source IP per window).
- The design tenet is explicit: new dimensions are ADDED to `Event`, never reshaped
  (`docs/log-sources.md:21`). So the house-correct move is to add named fields, not fork a second
  struct. Proposed additions, mapped to the Sigma field names auth rules use:
  - `SourceIp` (the `rhost` / `from IP`) - new named field, exposed to rules and as an OCSF
    observable (pivotable).
  - `SourcePort` - new named field.
  - `AuthService` (sshd / sudo / su / login / cron) - lets logsource routing and rules discriminate.
  - `AuthMethod` (password / publickey / none) - new named field.
  - `Outcome` / `Status` (success / failure) - the single most load-bearing auth field.
  - `User` already exists and is reused as the target/acting account.
  - A `Category` / `Kind` discriminator on the event (e.g. "auth" vs "process_creation") so logsource
    routing (section 6) can gate which rules run. This is the one field that is structural rather
    than cosmetic, and it is the explicit event-model task to call out.
  - Everything else (TTY, the sudo COMMAND, the uid tuple, the `[preauth]` marker) rides in `Raw`
    keyed by Sigma field name, as mimi and Sysmon already do.

  `Event.Field`, `Values`, and `AllText` must be extended to resolve the new named fields, and the
  OCSF mapping (below) extended to render them. Add, do not reshape, so every existing parser and
  rule keeps working untouched.

- **OCSF: borrow 3002's vocabulary, do not emit class 3002.** banken emits a 2004 Detection Finding
  when a rule fires, not raw telemetry, so it will never emit an Authentication (3002) activity event
  as its own object. What it SHOULD do is give the 2004 finding an auth-shaped evidence block when
  the triggering event is an auth event: an `actor.user` plus a `src_endpoint` (ip/port) drawn from
  the OCSF 3002 / Authentication field vocabulary, instead of forcing a login into the process-shaped
  `ocsfProcess` evidence (`internal/alert/ocsf.go:398-428`). The source IP should also appear as a
  flat OCSF observable so a SOC can pivot on it. This is the OCSF half of the event-model task.

Verdict: a reuse-only "stuff it in Raw" parser is possible and would fire keyword rules, but it
leaves the valuable correlated detections unbuildable and the OCSF output misshapen. Do the
event-model work. It is the honest definition of "first-class".

## 4. Field mapping

| auth.log datum        | Event field              | OCSF finding (2004) placement            |
| --------------------- | ------------------------ | ---------------------------------------- |
| acting/target account | `User` (existing)        | evidence actor.user / observable User    |
| source address        | `SourceIp` (new)         | evidence src_endpoint.ip + observable    |
| source port           | `SourcePort` (new)       | evidence src_endpoint.port               |
| service (sshd/sudo/su)| `AuthService` (new)      | finding metadata / routing               |
| method (password/key) | `AuthMethod` (new)       | evidence auth_protocol-style field       |
| success/failure       | `Outcome` (new)          | finding status / activity                |
| sudo COMMAND          | `Raw["Command"]`         | unmapped / evidence                      |
| TTY, uid tuple        | `Raw[...]`               | unmapped                                 |
| raw message (always)  | `Raw["Message"]`         | AllText keyword surface                  |
| event class           | `Category`/`Kind` (new)  | drives logsource routing                 |

## 5. Ingestion: file tail vs journald auth facility

banken reads a FILE, always, through one cursor+rotation+inotify path (`main.go`, the stream/periodic
split at `main.go:285-351`). The question is only what file, and that splits by distro:

- **Debian / Ubuntu:** auth events are in `/var/log/auth.log` (facility authpriv, rsyslog). Tail it
  directly. This is the common honeypot target.
- **RHEL / Rocky / Alma / Fedora / Amazon Linux:** the file is `/var/log/secure`. Tail it directly
  where rsyslog is present.
- **journald-only hosts (NixOS default, and increasingly minimal RHEL/Fedora):** there is no
  auth.log or secure. Auth events live in the journal under facility authpriv / the sshd/sudo
  `_SYSTEMD_UNIT`. banken must NOT grow a journal client or cgo for this. There is already a tested
  precedent in the tree: the Sysmon source bridges the journal to a file with a tiny
  `journalctl -f -n0 -o cat` service running as a `DynamicUser` with
  `SupplementaryGroups = [ "systemd-journal" ]` and nothing else (`module.nix:445-470`). The auth
  source copies that exactly, filtering the journal to the auth facility / sshd+sudo+su units
  (`journalctl -f -o cat SYSLOG_FACILITY=10` for authpriv, or `-t sshd -t sudo -t su`), appending to
  a file banken tails. One caveat worth stealing from the Sysmon bridge comment: a bridge restart
  resumes at the journal tail (`-n0`), so events during a restart gap are missed - acceptable, same
  as today.

**Recommendation:** file-tail is the mechanism on every distro; the only variable is whether banken
tails the native rsyslog file (`auth.log` / `secure`) or a journal->file bridge on journald-only
hosts. The NixOS module picks automatically: if `/var/log/auth.log` or `/var/log/secure` exists, tail
it; otherwise stand up the authpriv journal bridge. Note one semantic difference from the rsyslog
files: `journalctl -o cat` gives the MESSAGE only (no syslog frame), so the parser's frame step must
tolerate a frameless line - which it must anyway, because the Sysmon bridge is already frameless.
`candidateSources` (`internal/config/config.go:117-120`) gains auth.log and secure entries so a bare
`banken` auto-detects an auth source alongside the audit log.

## 6. Detections this unlocks, and the honeypot / fleet tie

Nothing fires until auth rules exist and logsource routing lands. Once they do:

- **SSH brute force / password spraying.** N failed `sshd` logins from one SourceIp in a window, or
  one account tried from many IPs. Needs the `SourceIp`/`Outcome` fields and a counting/correlation
  primitive (a stateful rule or a sink-side aggregate - call out that banken's matcher is stateless
  per-event today, so brute-force counting is its own design question, noted in open questions).
- **Successful login after repeated failures** (the classic "they finally got in" pivot) - same
  correlation primitive.
- **New / invalid user logins** - `Accepted ...` for an account never seen before, or a flood of
  `invalid user` names (the honeypot's primary signal: who is knocking and with what usernames).
- **sudo abuse** - `N incorrect password attempts`, `command not allowed`, or sudo to root by an
  account that should not.
- **su to root**, **off-hours logins**, **login from an unexpected geo/IP** (IP enrichment is a
  later story; the field is the enabler).
- **Agentic tie-in** (the banken niche): an autonomous agent account logging in interactively, or
  pivoting over ssh, is an account-scoped auth signal that complements the agent process rules under
  `rules/agent/`.

Honeypot story: a honeypot's entire value is the auth log - failed credentials, source IPs, username
dictionaries. This source turns banken into the honeypot's detection brain for free. Fleet story:
auth events are the same shape on every host, so a fleet rollup of "failed-login sources across the
fleet" is a direct consequence of the normalised `SourceIp`/`Outcome` fields - the cross-host signal
that process execs alone do not give.

## 7. Config and logsource routing

- Config: `{ type = "syslog"; path = "/var/log/auth.log"; }` (or secure, or the bridge file), exactly
  like every other source. No new config shape; the NixOS module sets the path per distro and stands
  up the bridge when needed, mirroring `services.banken.sysmon`.
- **Routing is a dependency, not part of this source.** Because the matcher runs all rules against
  all events (`engine.go:37`, no `logsource` in `rule.go`), auth events and process events would
  cross-fire. The clean fix is the roadmap logsource-routing work: parse the Sigma `logsource:` block
  into `Rule`, carry a `Category`/`Kind` on the event, and gate rule evaluation so a
  `category: process_creation` rule skips an auth event and a `service: sshd` rule skips an exec.
  SigmaHQ organises Linux auth rules under `linux/builtin` with `product: linux` and
  `service: sshd|sudo|auth|su`; banken's routing maps those service tags to the `AuthService` field /
  event kind. This source should be sequenced AFTER (or jointly with) a minimal logsource-routing
  task; shipping the parser without routing produces a noisy, cross-firing ruleset.
- SigmaHQ reuse: once routing and the auth fields exist, a slice of SigmaHQ's `linux/builtin`
  sshd/sudo/auth rules becomes loadable, the same reuse play Sysmon makes for Windows rules - scope
  the claim honestly (many of those rules assume fields a bare auth.log line does not carry, so
  curate, do not bulk-import).

## 8. Testing

- **Golden fixtures.** A `testdata/` corpus of real auth.log and secure lines (Debian and RHEL
  forms), RFC 3164 and RFC 5424 framed, plus frameless journal-bridge lines, each with its expected
  `event.Event` - the same golden pattern the other parsers use (`internal/parser/golden_test.go`).
- **Fuzz.** A `FuzzSyslog` target, mandatory per the parser contract (`parser.go:4-12`): never panic,
  never mis-normalise on truncated/adversarial lines (a crafted auth line is attacker-controlled -
  anyone who can fail a login writes to this log).
- **The message-grammar table** gets unit tests per line pattern, including the `message repeated N
  times` expansion and the invalid-user / preauth variants.
- **VM + distro matrix.** A VM test on hokkaido (KVM works for claude) that generates real sshd/sudo
  events and asserts banken fires: Debian/Ubuntu auth.log, RHEL-family secure, and a journald-only
  (NixOS) host via the bridge. This mirrors the Sysmon switch test and the distro-matrix-mimi work
  this branch sits on.

## 9. Non-goals for v1

- No stateful brute-force correlation engine in v1 if the matcher stays per-event stateless; ship the
  structured fields and single-event rules first, correlation is a separate design (open question).
- No bulk import of the SigmaHQ auth corpus; a curated starter set only.
- No IP geo / threat-intel enrichment of `SourceIp` (the field is the enabler; enrichment is later).
- No generic syslog ingestion (cron, kernel, mail, app logs) - this source is auth/login only.
  General syslog is a different, lower-value story and would flood the matcher.
- No journal client or cgo in banken; journald-only hosts use the file bridge.
- No RFC 3164 timezone/year reconstruction beyond best-effort from file mtime.

## 10. Open questions and risks

- **Stateless matcher vs brute force.** banken matches one event at a time (`engine.go`,
  `matcher.go`). Counting failures per IP per window needs state - a windowed/stateful rule type, or
  aggregation in a sink, or a correlation pass. This is the biggest open design question and should
  be its own task; v1 auth can ship single-event detections (new user, invalid user, sudo abuse)
  without it.
- **Logsource-routing readiness.** This source is gated on routing landing. If routing slips, the
  fallback is to tag auth rules and auth events so they only match each other via a field convention -
  uglier, but it keeps the source shippable.
- **auth.log is attacker-influenced input.** A remote party chooses the username and (partly) the
  text that lands in the log (e.g. a crafted username containing syslog-frame-looking bytes). The
  parser must assume hostile content and the fuzz target must prove it - this is exactly the parser
  contract's threat model.
- **rsyslog variance.** Templates, "message repeated" dedup, and the authpriv-vs-auth facility split
  differ across distros and configs; the grammar table must be tested against real samples, not
  assumed.
- **Timestamp quality.** RFC 3164 has no year/timezone; the journal bridge strips the frame entirely.
  banken's `Time` stays best-effort, consistent with every other field.
- **OCSF evidence shape.** Extending the 2004 finding with an auth/src_endpoint evidence block
  touches `internal/alert/ocsf.go` and its golden tests; keep it additive so process findings are
  byte-identical.

## Sources

- banken code read for current state: `internal/parser/parser.go`, `internal/parser/stub.go`,
  `internal/parser/sysmon.go`, `internal/parser/mimi.go`, `internal/event/event.go`,
  `internal/engine/engine.go`, `internal/sigma/matcher.go`, `internal/sigma/rule.go`,
  `internal/alert/ocsf.go`, `internal/config/config.go`, `main.go`, `module.nix`, `docs/log-sources.md`,
  `docs/writing-rules.md`, `docs/design/sysmon-linux.md`.
- RFC 3164 (BSD syslog), RFC 5424 (syslog protocol) for the framing split.
- SigmaHQ `rules/linux/builtin` (sshd/sudo/auth/su service logsources) for the reusable auth rule
  corpus and the field names auth rules key on.
- OCSF 1.3.0 Authentication class (3002) field vocabulary (actor.user, src_endpoint, auth_protocol,
  status) borrowed for the finding's auth evidence; banken continues to emit Detection Finding (2004).
