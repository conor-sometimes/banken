# Threat-intel feed ingestion (STIX 2.1 / TAXII 2.1 / MISP)

banken already matches indicators (`internal/ioc`): flat sets of hashes, IPs,
domains and paths, checked by set membership, domain dot-suffix and substring.
It had no way to *get* indicators from the formats the threat-intel world
actually ships them in. `internal/intel` is that ingestion layer. It does not
match anything itself -- it turns a feed into normalised indicators and hands
them to the existing `ioc.Set`, so the match engine, the alert path and the
OCSF finding are all unchanged.

## The model: normalise, don't fork the matcher

```
STIX bundle ---\
TAXII poll  ----> []intel.Indicator --AddToSet--> ioc.Set --(unchanged)--> engine.Match --> alert --> OCSF finding
MISP export ---/
```

An `intel.Indicator` is `{Value, Type, Source, Description, Labels}`. Only
`Value` and `Source` drive behaviour: `AddToSet` calls `ioc.Set.Add(value,
source)`, and `ioc` classifies the value by shape exactly as it does a line in a
`rules/ioc/*.txt` list. `Type` is kept for provenance and for a reader that
wants to type an indicator without re-parsing, but the *match* is shape-driven,
so a feed indicator and a hand-written list indicator are indistinguishable once
loaded. This is the whole design: one match engine, many sources.

Indicator types normalised: IPv4, IPv6, domain/hostname, URL, file hash
(MD5/SHA*/ssdeep/imphash/...), file name/path. In `ioc` terms IPs become
`KindIP` (whole-token match), domains `KindDomain` (exact or dot-suffix), and
URLs/hashes/paths `KindFilename` (substring). That means a hash or URL fires
when it appears literally in a scanned field (CommandLine, Image,
TargetFilename, CurrentDirectory) -- the right behaviour for the auditd/laurel
sources banken reads today, and the same coverage caveat the flat lists have.

## STIX 2.1 (`stix.go`)

Reads any JSON document with an `objects` array (a bundle or a TAXII envelope).
Two object shapes carry indicators:

- **indicator SDOs** -- the `pattern` (pattern_type `stix`) is scanned for every
  `object-type:property = 'value'` equality comparison. `[ipv4-addr:value =
  'x']`, `[domain-name:value = 'x']`, `[url:value = 'x']`,
  `[file:hashes.'SHA-256' = 'x']`, `[file:name = 'x']`. OR/AND joins each yield
  one indicator; the match side does not care how the feed grouped them.
- **cyber-observable objects (SCOs)** that appear directly in the bundle --
  `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file` (hashes + name). TAXII
  collections commonly return these.

Scope (honest): only `=` comparisons are extracted -- the form essentially every
IOC feed uses. `MATCHES`/`LIKE`/`IN` and pattern qualifiers
(`WITHIN`/`REPEATS`/`START`/`STOP`) are not evaluated: they describe behaviour
over observations, not a flat indicator, and have no meaning in a set-membership
matcher. Object/property types banken cannot match on (registry keys, email
addresses, `file:size`) are skipped, never an error.

## TAXII 2.1 (`taxii.go`)

TAXII is the transport, STIX the payload. `TAXIIClient.PollCollection` GETs
`{api-root}/collections/{id}/objects/` with `Accept:
application/taxii+json;version=2.1`, decodes the response **envelope**
(`{more, next, objects}`), feeds `objects` through the same STIX extractor, and
follows `more`/`next` pagination (capped so a server that always says `more` can
not spin forever). Auth is optional: a bearer `Token` (read at runtime from a
credential file, never inline) wins over `Username`/`Password` basic auth.

## MISP (`misp.go`)

Reads the two JSON shapes a MISP instance hands out: an event export
(`{"Event": {"Attribute": [...], "Object": [{"Attribute": [...]}]}}`, optionally
wrapped in `{"response": [{"Event": ...}]}`) and an attribute search
(`{"response": {"Attribute": [...]}}`). Attributes are collected from the event
and from each object's nested attribute list. MISP attribute types map onto
banken's kinds (`ip-src`/`ip-dst` -> IP, `domain`/`hostname` -> domain,
`url`/`uri` -> URL, `md5`/`sha*`/... -> hash, `filename`/`filepath` -> file);
composite types (`filename|sha1`, `ip-dst|port`) are split and each matchable
half emitted. An attribute flagged `to_ids: false` is dropped -- an analyst
marked it not-for-detection; `to_ids: true` or absent is kept.

## Config wiring

A feed is data in the config, loaded the same point the `rules/ioc` lists are
(see `rules/ioc/README.md` for the YAML). STIX/MISP file feeds are read from
disk each run; a TAXII feed is polled each run under a timeout. A feed that
fails loads nothing, is warned about, and the run continues with whatever else
loaded (never-die). Feed loading is `loadIntel` in `main.go`, after `loadIOCs`
and before the engine is built.

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
repo, shaped to the OASIS STIX 2.1 and the MISP data-model documentation. Every
address and name is from a reserved, non-routable range so no sample implies a
real indicator: IPs are RFC 5737 TEST-NET (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`) and RFC 3849 documentation IPv6 (`2001:db8::/32`); domains use
RFC 2606 / RFC 6761 reserved TLDs (`.example`, `.test`); hashes are well-known
constants (e.g. the SHA-256 of the empty input) or obviously synthetic. Nothing
here was taken from a live feed.
