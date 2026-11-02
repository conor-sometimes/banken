# Install and onboarding

An honest, follow-along guide for two people: a **user** who wants banken running on a host, and a
**developer** who wants to change banken. It is grounded in what the repo actually does today, not
in packaging that does not exist yet.

The short version:

- **Users on NixOS**: `services.banken.enable = true;`. One line. Easiest by a wide margin.
- **Users on anything else**: there is no `.deb`, `.rpm`, AUR package, copr, or Homebrew tap yet, and
  no prebuilt release binary. You build (or cross-build) the one static Go binary yourself, install
  auditd from your distro, drop in the two systemd units, load the audit rules, and enable the timer.
  Three to five commands, plus one per-distro gotcha each.
- **Developers**: `nix develop` (or the shared `workbench` shell), then `just`. The whole toolchain
  is pinned; nothing to install by hand.

---

## Part A: installing banken as a user

### What banken actually is

- **One binary.** A static, `CGO_ENABLED=0` Go binary. No runtime, no Python, no kernel module, no
  shared-library dependencies. It runs on any Linux.
- **Two systemd units.** `packaging/systemd/banken.service` (the hardened one-shot scan) and
  `packaging/systemd/banken.timer` (runs the scan every two minutes).
- **Audit rules.** banken reads the Linux audit log; it does not hook syscalls itself. The host's
  auditd must be capturing `execve` (plus the `/etc/shadow` and `/etc/gshadow` watches the
  credential rule reads). banken auto-detects the log location
  (`/var/log/laurel/audit.log`, then `/var/log/audit/audit.log`).
- **Zero config.** With no `/etc/banken/banken.yml`, banken loads its embedded Sigma baseline,
  auto-detects the source, and alerts to the journal. A config file only *adds* (extra rule trees,
  jsonl/webhook/OTLP sinks, a different source).

systemd is a hard requirement, not a preference: banken's security model *is* the unit's sandbox
(`ProtectSystem=strict`, one capability, a syscall filter, no writable+executable memory). The
static binary runs under OpenRC or SysV too, but there it would be an unconfined root log parser, so
it is unsupported.

### The honest state of packaging

banken is **not packaged** anywhere today. There is no `.deb`, `.rpm`, AUR entry, copr repo,
Homebrew formula, or GitHub release binary (the repo has CI, CodeQL, fuzz and scorecard workflows,
but no release workflow that attaches artifacts). So on every distro except NixOS you supply the
binary yourself. That is the one real friction point for users, and Part C proposes fixes for it.

The install path below is not invented: it is exactly what the live distro matrix does inside each
test VM (`tests/distros/distrocheck/main.go`, functions `installPackages`, `loadAuditRules`,
`installBanken`), driven by the per-distro package names in `tests/distros/distros.json`. If it
passes there, it works on that distro.

### NixOS (the easy one)

```nix
# flake.nix
inputs.banken.url = "github:conor-sometimes/banken";
# in your nixosConfiguration's modules:
modules = [ banken.nixosModules.default ];
```

```nix
# configuration.nix
services.banken.enable = true;   # the whole setup
```

That one line pulls in auditd with the rules banken reads, the hardened one-shot unit, the timer,
and journal alerting. Everything else (`interval`, `extraRules`, `alerts.jsonl`, `alerts.webhook`,
`observeRules`/`optionalRules`) is optional. The module is proven end to end by `tests/vm.nix`
(`nix flake check`). Without flakes, import `module.nix` from a pinned checkout (see `default.nix`).

### Any other systemd Linux (the generic path)

Four stages. Stages 1-3 differ per distro only in the package name for auditd and the one gotcha;
stage 4 is identical everywhere.

**1. Get the `banken` binary.** No release exists, so build it. With Nix (no clone needed):

```sh
nix build github:conor-sometimes/banken#banken     # result/bin/banken, static, portable
```

Or from a clone with the Go toolchain:

```sh
just build                                          # -> output/banken (static, version-stamped)
# or plainly:
CGO_ENABLED=0 go build -o banken .
```

The binary is static, so you can build once and copy it to every host of the same architecture
(x86_64 is tested; aarch64 builds but is not yet tested).

**2. Install auditd and make sure it audits execve.** Use your distro's package (names below), then
install banken's audit rules:

```sh
sudo tee /etc/audit/rules.d/banken.rules >/dev/null <<'EOF'
-a always,exit -F arch=b64 -S execve,execveat -k banken-exec
-a always,exit -F arch=b32 -S execve -k banken-exec
-w /etc/shadow -p rwa -k banken-watch
-w /etc/gshadow -p rwa -k banken-watch
EOF
sudo systemctl enable --now auditd
sudo augenrules --load          # or: sudo auditctl -R /etc/audit/rules.d/banken.rules
sudo auditctl -l | grep banken-exec   # confirm the rules actually loaded
```

**3. Handle the one per-distro gotcha** (see the table). On Fedora and openSUSE this means
commenting out the stock `-a task,never` line *before* `augenrules --load`.

**4. Install the units and enable the timer** (identical on every distro):

```sh
sudo install -m0755 banken /usr/bin/banken
sudo install -m0644 packaging/systemd/banken.service packaging/systemd/banken.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now banken.timer
```

That is a working deployment. The alert feed is `journalctl -u banken -p err`; anything banken shows
at `warning` or above that is not an alert is banken telling you something is wrong (for example,
that it found a `-a task,never` rule blinding it). First scan runs two minutes after boot, then every
two minutes. For lower latency, shorten the timer or run `banken --watch` as a daemon. To add a
second sink, drop a `/etc/banken/banken.yml` (see `docs/deployment.md`).

### Per-distro install: friction ranking and the specific gotcha

Easiest to hardest. "Friction" is how many non-obvious steps stand between a user and a running,
*detecting* banken. The package column is the auditd-providing package from `distros.json`.

| Rank | Distro | auditd package | Friction | The specific gotcha |
| --- | --- | --- | --- | --- |
| 1 | **NixOS** | (module) | Lowest: one line | None. `services.banken.enable = true;` does auditd, rules, unit, timer. |
| 2 | **Debian 13** | `auditd` | Low | `auditctl`/`augenrules` ship in the same `auditd` package; AppArmor is active but denies banken nothing. Clean path. |
| 3 | **Ubuntu 24.04** | `auditd` | Low | Same as Debian. One extra watch-out: background `fwupd` can emit its own `modprobe`/kernel-module-load events (noise, not a blocker; the matrix masks fwupd to keep scan windows clean). |
| 4 | **Arch** | `audit` | Low | Rolling; `python` provides `python3` (name differs). No SELinux/AppArmor by default, so no MAC step. |
| 5 | **Rocky 9** | `audit` | Low-medium | SELinux is **enforcing** by default. It denies banken nothing as shipped, but if you relabel `/usr/bin` or move the binary, keep the standard `bin_t` label so the unit can exec it. `auditctl` is in the `audit` package. |
| 6 | **Amazon Linux 2023** | `audit` | Medium | `curl` is provided by `curl-minimal` (name differs from the RHEL norm); otherwise RHEL-family. SELinux enforcing. Image is dnf-based but trimmed, so confirm `audit` actually pulled `auditctl`. |
| 7 | **AlmaLinux 10 (RHEL 10)** | `audit` | Medium | `auditctl` and `augenrules` are **not** in `audit` on RHEL 10 and its rebuilds; they are in a separate **`audit-rules`** package the cloud image may lack: `dnf install audit-rules`. SELinux enforcing. |
| 8 | **Fedora 44** | `audit` | Medium-high | Ships a stock **`-a task,never`** rule in `/etc/audit/rules.d/audit.rules` that turns syscall auditing off entirely: banken runs clean while seeing nothing. Comment it out before `augenrules --load`. Also on RHEL 10's footing, `auditctl` lives in `audit-rules`. SELinux enforcing. (banken warns about `task,never` at startup, so the symptom is at least self-announcing.) |
| 9 | **openSUSE Leap 16** | `audit` | Highest | Same **`-a task,never`** blinding as Fedora, same fix. Plus: **Leap has no `nmap` provider**, so the optional portscan emulation can't be installed there (irrelevant to running banken, relevant only if you reproduce the test battery). zypper needs `--gpg-auto-import-keys` on first install. SELinux enforcing. |

Cross-family note: the two gotchas that actually *blind the detector* are the Fedora/openSUSE
`-a task,never` rule and (RHEL 10 family) the missing `audit-rules` package. Everything else is
naming trivia or a MAC that happens to allow banken anyway. banken's own `auditcheck` logs a warning
naming the file and line when it sees `task,never`, so a blinded install is diagnosable from the
journal rather than silently green.

---

## Part B: getting up to speed as a developer (NixOS assumed)

### The happy path, end to end

```sh
git clone https://github.com/conor-sometimes/banken && cd banken
nix develop                 # full toolchain, pinned, nothing to install
just install-hooks          # once: points core.hooksPath at .githooks (commit-msg policy)
just                        # the fast gate: fmt, vet, lint, gosec, vulncheck, unit+fuzz, cover
just test                   # the WHOLE battery (needs KVM + network): gate + integration + conformance + distros + attackrange
```

Two ways into the dev environment, both giving the identical pinned toolchain (Go 1.26, gofumpt,
golangci-lint, gosec, govulncheck, errcheck, staticcheck, gotestsum, delve, hyperfine, ...):

- **`nix develop`** on the repo (`flake.nix`, `devShells.default`). Then `just`.
- **The shared workbench**, which pins the same toolchain for the whole banken family (banken and
  mimi alike), without cloning first:

  ```sh
  nix run github:conor-sometimes/workbench#banken -- -c 'just default'
  ```

Off Nix entirely, install the tools `just` names at the top of the `justfile` (`brew install just
gofumpt staticcheck errcheck gosec govulncheck golangci-lint`, plus
`go install gotest.tools/gotestsum@v1.13.0`). Nix is the paved road; the justfile documents the
manual list for the rest.

### What `just` and `just test` actually run

- **`just`** (bare, alias of `just all` / `default`) is the **fast code gate**, no VMs or network:
  `fmt` (gofumpt check) -> `vet` -> `lint` (staticcheck) -> `golangci` -> `errcheck` -> `gosec`
  -> `vulncheck` (govulncheck) -> `unit` (every package, race on, plus a short fuzz smoke of every
  `Fuzz*` target and a deep rapid property sweep) -> `cover`. This is what CI runs on every push.
- **`just test`** is the **whole proof**, and needs KVM and network: `just default`, then
  `just integration` (`nix flake check` -> the `vm` module test and the banken+mimi switch suite),
  then `nix develop .#conformance --command just conformance` (SigmaHQ load coverage, the pySigma
  differential, the OCSF validator), then `just distros` (the live 8-distro matrix, which is also the
  deployment test), then `just attackrange` (the Atomic Red Team range).

### Where to start reading

In this order:

1. **`README.md`** -- the "What it supports" map is verified against the code, with each claim's
   check named. It is the honest surface area: what is implemented, what is stubbed, what is planned.
2. **`docs/architecture.md`** -- how one scan works end to end: sources -> one normalised `Event` ->
   the Aho-Corasick prefilter and Sigma matcher -> the cursor -> the sinks.
3. **`docs/writing-rules.md`** -- the exact Sigma subset banken evaluates (fields, modifiers, keyword
   selections, conditions), IOC lists, and how the embedded baseline and on-disk trees combine. This
   is where most first contributions land.
4. **`docs/design/PLAN.md`** and the rest of `docs/design/` -- the roadmap and the deeper design
   rationale. (Read-only for this audit: the Research lane owns `docs/design/`.)
5. The **rule + emulation + fixture + golden pattern** by example: open `rules/<tactic>/` for a rule,
   its matching `tests/emulations/<family>.sh`, the `tests/fixtures/NAME.expect-<rule>.json` it
   produces, and `tests/golden/ocsf/NAME.expect-<rule>.json`. One read across those four files shows
   the whole detection-and-proof loop.

### The first-contribution loop (adding a detection)

This is the core dev loop and it is well-supported:

1. **Write the Sigma rule** under the ATT&CK tactic it detects: `rules/<tactic>/my-rule.yml`
   (behavioural), `rules/malware/<family>/` (a family signature), or a flat list in `rules/ioc/*.txt`
   (bulk indicators). `docs/writing-rules.md` has the subset and worked examples.
2. **Check it fast, no log needed:**

   ```sh
   banken check -image /usr/bin/cat 'cat /etc/shadow'        # -> which rules fire
   banken check -json '{"image":"/bin/bash","commandLine":"...dev/tcp..."}'
   ```

3. **Add an emulation** under `tests/emulations/<family>.sh` -- the *harmless* analogue of the real
   behaviour (dummy data in a `mktemp -d`, unroutable `192.0.2.0/24` "C2", cleans up, needs no
   privilege; the safety contract is in `tests/emulations/README.md`). Its header lists the family,
   TTPs, and the rules it should fire. The VM test runs it against real auditd and asserts *exactly*
   those rules fire (a miss and a false positive both fail).
4. **Save the fixture** for the fast, no-VM regression test: a normalised event JSON under
   `tests/fixtures/`. `NAME.expect-<rule>.json` must fire that rule; `NAME.expect-none.json` must
   fire nothing. The coverage gate **requires every rule to have one**, so a rule ships with proof it
   does (and doesn't) fire.
5. **Golden the output** where relevant: the committed OCSF finding golden in
   `tests/golden/ocsf/`, validated against the official OCSF 1.3.0 schema by `just ocsf-validate`.
6. **Run `just`.** The unit suite replays your fixture, the coverage gate checks the rule is covered,
   and the static analysis + fuzz smoke run. Green here is the fast proof; `just test` is the full one.

### Be honest about the friction

- **No `CONTRIBUTING.md`.** The dev workflow is real and consistent, but it is scattered across the
  README's Testing section, the `justfile` header comments, and the per-directory `README.md`s. A new
  dev has to assemble it. (Part C proposes adding one; this document is the interim map.)
- **The banken + mimi integration tests need private mimi access.** `just integration`
  (`nix flake check`) builds the `switch`/`switch-floor`/`switch-restart` suites and the `-mimi`
  distro matrix, all of which pull `github:conor-sometimes/mimi` as a flake input. Without access to
  that repo those checks can't build. banken's *product* is decoupled (the package and NixOS module
  never reference mimi), and the plain `nix run .#distro-matrix` is banken-raw (A-E objectives only),
  so you can do almost all banken work without mimi -- but you cannot run the full `just test` green
  without it. Know that going in.
- **The `govulncheck` gate (vuln.go.dev).** `just` runs `govulncheck ./...` against the live Go vuln
  database, so the fast gate can start failing on a PR that changed no code of its own, the day an
  advisory lands for a dependency. That is deliberate (a security tool should not ship known-vuln
  deps), but it means "green yesterday" is not "green today" -- rebase and re-run before concluding
  your change broke something.
- **`just test` needs KVM and network and takes a while by design.** It is the full proof, not the
  inner-loop command. The inner loop is bare `just`; reach for `just test` before a PR that touches
  detection, the units, or the matrix, not on every save.

---

## Part C: top friction points and proposed fixes

Each fix has a seeded Taskwarrior task (project as noted, tagged `+ux-audit`); UUIDs are listed at
the end.

### User-facing

1. **No prebuilt binary and no native packages -- every non-NixOS user builds from source.** This is
   the single biggest user-facing friction: a security tool that asks you to install a Go toolchain
   (or Nix) before you can try it loses most of its "SentinelOne for the masses" audience at step one.
   - **Fix A (quick win): a one-line install script.** `curl -fsSL .../install.sh | sh` that detects
     the distro, installs auditd via the right package name (the `distros.json` map already encodes
     this), downloads the matching static binary from a GitHub release, drops the units, handles the
     `-a task,never` and `audit-rules` gotchas, and enables the timer. It is essentially
     `distrocheck`'s install path minus the test harness. (Pipe-to-shell installers are themselves a
     detection banken flags, so ship a "download then inspect then run" variant too, and say so.)
     *Owner: banken.ux.*
   - **Fix B (the real fix): prebuilt release binaries + native packages.** A release workflow that
     attaches the static x86_64 (and aarch64) binary, the SBOM (`just sbom` already exists), and
     `.deb`/`.rpm`/copr/AUR packages carrying the binary, units and audit rules. Then the per-distro
     install collapses to `apt install banken` / `dnf install banken` + the one gotcha.
     *Owner: banken.standards.*

2. **The `-a task,never` blinding is a silent-ish trap.** banken warns at startup, but a user who
   doesn't read the journal sees a clean, running service that detects nothing. The install script
   (Fix A) should fix it automatically; short of that, the deployment docs should lead with a
   "confirm you're actually seeing events" check (`auditctl -l | grep banken-exec` and a
   `banken check` smoke). *Folded into the banken.ux docs task.*

### Developer-facing

3. **No `CONTRIBUTING.md`.** The workflow (dev shell -> `just` -> the rule/emulation/fixture/golden
   loop -> `just install-hooks` -> the no-AI-attribution commit policy) is real but has to be
   reassembled from four places.
   - **Fix: add a `CONTRIBUTING.md`** that states the happy path, the first-contribution loop, the
     commit-message policy, and the honest caveats (mimi access, the KVM/network needs of
     `just test`). *Owner: banken.ux.* (A first cut can point at this document's Part B.)

4. **`just test` can't go fully green without private mimi access, and nothing tells a new dev that
   up front.** They hit an opaque flake-build failure on `nix flake check`.
   - **Fix: make the mimi dependency explicit and gracefully skippable** -- document it in
     CONTRIBUTING, and have `just integration` / the matrix print a clear "mimi unavailable; running
     banken-raw" message and run the banken-only subset rather than failing to build. *Owner:
     banken.testing.*

### Seeded tasks

Seeded into Taskwarrior, tagged `+ux-audit` (8-character UUIDs):

| Fix | Lane | UUID |
| --- | --- | --- |
| One-line `install.sh` | banken.ux | `0a5c41a0` |
| Release binaries + native packages (.deb/.rpm/copr/AUR) | banken.standards | `21e8123d` |
| Flesh out `CONTRIBUTING.md` + issue/PR templates | banken.ux | `8e030641` |
| Make the mimi dependency explicit and gracefully skippable | banken.testing | `a77b4279` |
