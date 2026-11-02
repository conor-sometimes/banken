# rules/ioc -- indicator sets

This directory holds banken's bulk indicators: thousands of flat values that
would be absurd as one Sigma YAML each, matched by set membership, domain
dot-suffix, and substring rather than by condition logic (see
`internal/ioc`). Two things live here, and both end up in the same match set:

## 1. Flat indicator lists (`*.txt`)

One value per line; blank lines and lines starting with `#` are comments. The
value's kind is inferred from its shape (`internal/ioc.classify`):

```
# rules/ioc/evil-c2.txt
198.51.100.23          # IPv4 or IPv6: whole-token match (never a loose substring)
evil.example           # domain: exact host or dot-suffix (c2.evil.example hits)
/opt/evil/dropper      # path / file name: substring anywhere in a scanned field
e3b0c4429...b7852b855  # a hash is just a value: substring match
```

Files here are **embedded into the binary** (`//go:embed rules`), so a fresh
install ships with them. On-disk lists under a configured rules dir
(`services.banken.extraRules`, the `-rules` flag) load on top. Keep the
embedded set small and high-confidence; large or operator-specific feeds belong
on disk or come from a threat-intel feed (below), not baked into the baseline.

## 2. Threat-intel feeds (STIX 2.1, TAXII 2.1, MISP)

`internal/intel` ingests the standard feed formats and **normalises every
indicator into this same IOC model**, so the match engine consumes a feed
exactly as it consumes a `.txt` list -- the same classifier, the same lookup,
the same OCSF osint observable on the finding. A feed is data named in config,
nothing more:

```yaml
# /etc/banken/banken.yml
intel:
  - type: stix                      # a STIX 2.1 bundle on disk, parsed each run
    name: misp-export
    path: /var/lib/banken/intel/bundle.json
  - type: misp                      # a MISP event/attribute JSON export on disk
    path: /var/lib/banken/intel/misp-event.json
  - type: taxii                     # a TAXII 2.1 collection, polled each run
    name: alienvault-otx
    url: https://otx.example/taxii2/api1/
    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116
    tokenFile: /run/credentials/banken/taxii-token   # bearer; keep the secret off the Nix store
```

A feed that fails to load or poll is warned about and skipped; the run goes on
with whatever loaded (never-die). A feed's `name` (or its file base name) is the
`source` carried onto every alert and into the OCSF finding's `osint.name`, so
an operator can tell which feed paged them.

Supported indicator types: IPv4/IPv6 addresses, domains/hostnames, URLs, file
hashes (MD5/SHA*/ssdeep/...), and file names/paths. STIX indicator patterns are
read as `=` comparisons (the form every IOC feed uses); MATCHES/LIKE and pattern
qualifiers are not evaluated. MISP `to_ids: false` attributes are dropped
(analyst-marked not-for-detection). See `docs/design/threat-intel-feeds.md` for
the format details and what is proven offline vs needs a live server.
