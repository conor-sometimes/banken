# Contributing to banken

This is the short version. The full guide lives in
[docs/install-and-onboarding.md](docs/install-and-onboarding.md) (Part B). It covers:

- developer onboarding
- the first-contribution loop
- the honest caveats

## The happy path (NixOS assumed)

```sh
git clone https://github.com/conor-sometimes/banken && cd banken
nix develop                 # full pinned toolchain, nothing to install (or: workbench, below)
just install-hooks          # once: core.hooksPath -> .githooks (enforces the commit-msg policy)
just                        # the fast gate: fmt, vet, lint, gosec, vulncheck, unit+fuzz, cover
just test                   # the whole battery (needs KVM + network): gate + integration + conformance + distros + attackrange
```

The shared toolbox works too, without cloning first:

```sh
nix run github:conor-sometimes/workbench#banken -- -c 'just default'
```

Off Nix, install the tools the `justfile` header names:

- `just`
- `gofumpt`
- `staticcheck`
- `errcheck`
- `gosec`
- `govulncheck`
- `golangci-lint`
- `gotestsum`

## Adding a detection (the core loop)

1. Write the Sigma rule under its ATT&CK tactic: `rules/<tactic>/my-rule.yml` (see
   [docs/writing-rules.md](docs/writing-rules.md)).
2. Check it fast: `banken check -image /usr/bin/cat 'cat /etc/shadow'`.
3. Add a benign emulation `tests/emulations/<family>.sh` (safety contract in that dir's README).
4. Save a fixture `tests/fixtures/NAME.expect-<rule>.json`. The `.expect-none.json` must fire
   nothing. Every rule needs one - the coverage gate requires it.
5. Golden the OCSF output where relevant (`tests/golden/ocsf/`, validated by `just ocsf-validate`).
6. Run `just`. Green is the fast proof; `just test` is the full one.

## Commit policy

- Run `just install-hooks` once after cloning. The `commit-msg` hook keeps AI-tool attribution out
  of commit messages. Do not add `Co-Authored-By` or "Generated with" lines to commits.
- Keep changes focused; stage files by name.

## Honest caveats

- The banken + mimi integration tests pull the private `github:conor-sometimes/mimi` flake input.
  They are `just integration` and the `-mimi` distro matrix. Without access to that input they
  cannot build. But banken's product is decoupled. `nix run .#distro-matrix` is banken-raw (A-E
  objectives only), so almost all banken work needs no mimi. A fully green `just test` does.
- `just` runs `govulncheck` against the live Go vuln DB. So the fast gate can start failing on a PR
  that changed no code of its own, when a new advisory lands. Rebase and re-run before concluding
  your change broke it.
- `just test` needs KVM and network and takes a while by design. The inner loop is bare `just`.

There is no issue/PR template yet. Open an issue or PR on
[github.com/conor-sometimes/banken](https://github.com/conor-sometimes/banken). Describe the change
and how you proved it.
