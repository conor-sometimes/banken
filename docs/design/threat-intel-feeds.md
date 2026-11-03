# Threat-intel feed ingestion (STIX 2.1 / TAXII 2.1 / MISP)

banken already matches indicators through `internal/ioc`. These are flat sets of
hashes, IPs, domains and paths. It checks them three ways:

- set membership
- domain dot-suffix
- substring

What banken could not do was *get* indicators from the formats the threat
intelligence (threat-intel) world actually ships them in. `internal/intel` is
that ingestion layer. It matches nothing itself. It turns a feed into normalised
indicators and hands them to the existing `ioc.Set`. The rest of the path is
unchanged:

- the match engine
- the alert path
- the OCSF finding

## The model: normalise, don't fork the matcher

```
STIX bundle ---\
TAXII poll  ----> []intel.Indicator --AddToSet--> ioc.Set --(unchanged)--> engine.Match --> alert --> OCSF finding
MISP export ---/
```

An `intel.Indicator` is `{Value, Type, Source, Description, Labels}`. Only
`Value` and `Source` drive behaviour. `AddToSet` calls `ioc.Set.Add(value,
source)`. Then `ioc` classifies the value by shape, exactly as it does a line in
a `rules/ioc/*.txt` list. `Type` is kept for two reasons:

- provenance
- a reader that wants to type an indicator without re-parsing

The match itself is shape-driven. So a feed indicator and a hand-written list
indicator are indistinguishable once loaded. That is the whole design - one
match engine, many sources.

The ingestion layer normalises these indicator types:

- IPv4 and IPv6
- domain / hostname
- URL
- file hash (MD5/SHA*/ssdeep/imphash/...)
- file name / path

Each maps to an `ioc` kind:

- IPs become `KindIP` (whole-token match)
- domains become `KindDomain` (exact or dot-suffix)
- URLs, hashes and paths become `KindFilename` (substring)

So a hash or URL fires when it appears literally in a scanned field. The scanned
fields are CommandLine, Image, TargetFilename and CurrentDirectory. This is the
right behaviour for the auditd and laurel sources banken reads today. It carries
the same coverage caveat the flat lists have.

## STIX 2.1 (`stix.go`)

Reads any JSON document with an `objects` array (a bundle or a TAXII envelope).
Two object shapes carry indicators:

- **Indicator SDOs (STIX domain objects).** banken scans the `pattern`
  (pattern_type `stix`) for every `object-type:property = 'value'` equality
  comparison, such as:
  - `[ipv4-addr:value = 'x']`
  - `[domain-name:value = 'x']`
  - `[url:value = 'x']`
  - `[file:hashes.'SHA-256' = 'x']`
  - `[file:name = 'x']`

  Each half of an OR/AND join yields one indicator. The match side does not care
  how the feed grouped them.
- **Cyber-observable objects (SCOs)** that appear directly in the bundle:
  - `ipv4-addr`
  - `ipv6-addr`
  - `domain-name`
  - `url`
  - `file` (hashes + name)

  TAXII collections commonly return these.

The scope is deliberately narrow. banken extracts only `=` comparisons. That is
the form essentially every IOC feed uses. It does not evaluate `MATCHES`, `LIKE`
or `IN`, nor the pattern qualifiers `WITHIN`, `REPEATS`, `START` and `STOP`.
Those describe behaviour over observations, not a flat indicator. They have no
meaning in a set-membership matcher. Object or property types banken cannot
match on are skipped, never treated as an error. Examples are registry keys,
email addresses and `file:size`.

## TAXII 2.1 (`taxii.go`)

TAXII is the transport, STIX the payload. `TAXIIClient.PollCollection` does the
following:

- GETs `{api-root}/collections/{id}/objects/` with `Accept:
  application/taxii+json;version=2.1`
- decodes the response **envelope** (`{more, next, objects}`)
- feeds `objects` through the same STIX extractor
- follows `more`/`next` pagination, capped so a server that always says `more`
  cannot spin forever

Auth is optional. A bearer `Token` wins over `Username`/`Password` basic auth.
The token is read at runtime from a credential file, never inline.

## MISP (`misp.go`)

banken reads the two JSON shapes a MISP instance hands out:

- an event export: `{"Event": {"Attribute": [...], "Object": [{"Attribute":
  [...]}]}}`, optionally wrapped in `{"response": [{"Event": ...}]}`
- an attribute search: `{"response": {"Attribute": [...]}}`

Attributes are collected from the event and from each object's nested attribute
list. MISP attribute types map onto banken's kinds:

- `ip-src`/`ip-dst` -> IP
- `domain`/`hostname` -> domain
- `url`/`uri` -> URL
- `md5`/`sha*`/... -> hash
- `filename`/`filepath` -> file

Composite types like `filename|sha1` and `ip-dst|port` are split, and each
matchable half is emitted. An attribute flagged `to_ids: false` is dropped,
because an analyst marked it not-for-detection. An attribute with `to_ids: true`
or no such flag is kept.

## Config wiring

A feed is data in the config. It loads at the same point the `rules/ioc` lists
do (see `rules/ioc/README.md` for the YAML). STIX and MISP file feeds are read
from disk each run. A TAXII feed is polled each run under a timeout. A feed that
fails loads nothing. It is warned about, and the run continues with whatever
else loaded (never-die). Feed loading is `loadIntel` in `main.go`. It runs after
`loadIOCs` and before the engine is built.

## What is proven offline vs needs a live server

| Capability | Proof | Needs a live server? |
| --- | --- | --- |
| STIX 2.1 bundle parsing (SDOs + SCOs) | `TestParseSTIXBundle`, `TestIndicatorsFromPattern` against `testdata/stix_bundle.json` | no |
| MISP event + attribute-search parsing, composites, to_ids | `TestParseMISPEvent`, `TestParseMISPSearchAndComposites` | no |
| TAXII request shaping (path, Accept, bearer/basic), envelope decode, pagination | `TestTAXIIPollAgainstStub`, `TestTAXIIBasicAuthAndURL` against an `httptest` server serving recorded envelopes | no (local stub) |
| feed -> normalise -> match -> OCSF finding | `TestFeedToMatchToFinding` | no |
| reaching a real third-party TAXII endpoint | not tested | **yes** -- the walled CI/test host has no egress to a TAXII server, so banken is proven against a local stub and the live path is left to an operator with a reachable server. banken does not fake a live poll. |

## Sample data provenance

All feed samples under `internal/intel/testdata/` are **hand-authored** for this
repo. They are shaped to the OASIS STIX 2.1 and the MISP data-model
documentation. Every address and name comes from a reserved, non-routable range,
so no sample implies a real indicator:

- IPs are RFC 5737 TEST-NET (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
- IPv6 is RFC 3849 documentation space (`2001:db8::/32`)
- domains use RFC 2606 / RFC 6761 reserved TLDs (`.example`, `.test`)
- hashes are well-known constants (e.g. the SHA-256 of the empty input) or
  obviously synthetic

Nothing here was taken from a live feed.
