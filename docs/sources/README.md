# Threat and detection sources

`security-feeds.yml` is a hand-maintained, curated list of security blogs, vendor
research, and newsletters worth watching to keep banken's detections current. It is
deliberately a pure data file (per house rule: data files hold data, notes live in a
README beside them), so a tool can read it without parsing prose.

## Why this exists

banken is a detection engine: it is only as good as our awareness of what attackers
actually do on Linux hosts. These sources are the raw signal that becomes new rules.
The plan is a "watch and ingest" skill (not built yet) that:

1. reads `security-feeds.yml`,
2. pulls the latest articles from each feed,
3. surfaces the ones that imply a detection gap (a new technique, LOLBin, or TTP),
4. and drafts candidate rules / emulations for review.

Until that skill exists, the file is just a good reading list grouped by relevance.

## Schema

Each entry under `sources:` has:

| field | meaning |
| --- | --- |
| `name` | display name |
| `url` | homepage or blog index (high confidence) |
| `rss` | best-known feed URL, or `null`; see the caveat below |
| `category` | `detection-engineering`, `threat-intel`, `linux-runtime`, `agentic-ai`, `vuln-research`, or `aggregator` |
| `tier` | `essential` (highest signal per minute), `core`, or `watch` |
| `focus` | one line on why it matters for banken |

`linux-runtime` and `agentic-ai` are banken's and mimi's own niche; those entries are
the closest peers to what we build. The `agentic-ai` set backs the `rules/agent/` work.

## The RSS caveat

`meta.rss_verified` is `false`. The `rss` values are plausible starting points, not
promises: feed paths drift, and some are guesses by site convention. The ingestion
skill should do proper RSS autodiscovery (parse `<link rel="alternate"
type="application/rss+xml">` from each `url`) and validate before trusting a feed.

## Checking the links

Link-check with [lychee](https://github.com/lycheeverse/lychee); it extracts URLs from
any text file (this YAML included) and also follows local relative links in Markdown:

```sh
# from the repo root
lychee docs/sources/security-feeds.yml docs/sources/README.md
```

Run it somewhere with open internet. On hokkaido the `claude` user's egress is an
allow-list that does not include these domains, so a check there would report nearly
everything as unreachable; run it on the Mac (or add a dedicated proxy allow entry if
the future skill runs on-host). Note lychee can report false negatives for sites that
return 403/429 to an automated client (Cloudflare, Akamai); treat those as "verify by
hand", not "dead".
