# Upstream currency scan, 2026-11-01

What changed upstream in the standards and toolchains banken tracks, whether banken should adopt
it, and the concrete task (each seeded into its owning lane, tagged `+research-seed`). Facts were
checked against the sources on 2026-11-01, not from memory; versions and dates are stated so the
next scan can diff against them.

## Summary table

| Area | banken now | Latest upstream | Date | Verdict |
| --- | --- | --- | --- | --- |
| SigmaHQ `rules/linux` | pin `r2026-07-01` | `r2026-07-01` | 2026-07-09 | CURRENT. We are on the latest release. No action; watch for the next quarterly tag. |
| pySigma (conformance ref) | lock `2.0.1`, floor `>=0.11` | `2.0.1` | 2026-10-11 | Lock is current; the pyproject floor `>=0.11` is stale and lets an old pySigma resolve. Raise the floor. |
| OCSF (emit) | `1.3.0` | `1.9.0` | 2026-08-03 | HOLD `1.3.0`. The pin is Amazon Security Lake's custom-source ceiling, still 1.3-and-earlier as of this scan. Document the pin; track the `detection_finding` enrichments in 1.4/1.5 for when response + YARA land. |
| ECS (second output) | targets `8.11`, not yet built | `9.1.0` | 2026 | Not built yet (task 1161/1157 owns it). The `8.11` target is ~1 year stale; retarget before building. Annotated, not re-seeded. |
| Sysmon for Linux | `1.5.3` (doc) | `1.5.3` | 2026-09-10 | CURRENT. `sysmon-linux.md` already tracks it. No action. |
| MITRE ATT&CK | Navigator layer declares `v15`; rule tags generic | `v20.0` | 2026-10-13 | ACT. Bump the layer version; adopt v20's new AI technique IDs for `rules/agent/`; re-validate tactic strings after the v19 Defense Evasion split. |
| Go toolchain | `go 1.26.8` | `1.26.x` (1.26 GA 2026-02-10) | 2026-02 | CURRENT. 1.27 is still in development. No action. |
| nixpkgs / NixOS | `26.05` (hokkaido) | `26.05` current release | - | CURRENT. No action. |

## SigmaHQ: we are on the latest release

banken pins `r2026-07-01` (`justfile` `sigma_release`, `conformance/`, README: 210/210 Linux rules
load, 182/182 pySigma agreement). The GitHub releases API confirms `r2026-07-01` (2026-07-09) is the
newest tag; SigmaHQ moved to a roughly quarterly cadence (r2026-01-01, r2026-04-01, r2026-07-01), so
the next tag (likely `r2026-10` or `r2027-01`) has not shipped yet. banken is current, not behind.

Verdict: no bump. The honest note is that "latest" and "our pin" coincide today; the task to raise is
only a lightweight watch for the next tag (not seeded as work; it is a one-line check next scan).

## pySigma: lock current, floor stale

`conformance/uv.lock` resolves pySigma `2.0.1` (published 2026-10-11), which is current. But
`conformance/pyproject.toml` declares `dependencies = ["pysigma>=0.11"]`. That floor predates the
1.x and 2.x lines; a fresh resolve on a machine without the lock could pull a years-old pySigma and
silently weaken the differential. The lock protects CI, but the floor should match reality.

Verdict: adopt. Raise the floor to `>=2.0` (keep the lock as the real pin). Seeded into
`banken.testing` (the conformance harness lane).

## OCSF: hold 1.3.0, but track the newer detection_finding

banken emits OCSF `1.3.0` (PLAN D3, `ocsf-output.md`), chosen as the Amazon Security Lake ceiling.
OCSF itself is now at `1.9.0` (2026-08-03). The Security Lake custom-source docs still state OCSF
1.3-and-earlier as of this scan, so the pin remains correct and deliberate: bumping would break the
Security Lake ingestion path that justified the number. This validates D3; do not bump the emit.

What did move in 1.4/1.5 that banken will want when the later features land:
- 1.4.0 added `is_alert` to `detection_finding` and moved the `security_control` profile onto
  `base_event` (this is exactly PLAN D4's `security_control`/`action_id`, which was deferred until
  response actions exist).
- 1.5.0 added `malware`, `malware_scan_info`, and `anomaly_analyses` to `detection_finding` (the
  natural home for YARA verdicts at quarantine time).

Verdict: hold 1.3.0 as the default emit; document why (so a future reader does not "helpfully" bump
it and break Security Lake); and plan a higher-version emit profile to adopt the response/YARA
enrichments when those features ship, rather than retrofitting 1.3.0. Seeded into `banken.standards`
(references the standing OCSF task 1059).

## ECS: target is stale, but the lane already owns the work

banken has no ECS output yet; `standards.md` lists it and task 1161 (std/output, ECS as a second
mapping, with a second SigmaHQ pin + pySigma) owns it. The design target of `8.11` is about a year
behind: ECS is at `9.1.0` (adds beta `gen_ai` fields, OTel semconv v1.34.0). Building to 8.11 now
would ship stale on day one.

Verdict: do not re-seed (the lane owns it). Annotated task 1161 with the currency fact so whoever
builds ECS retargets to a current 8.17.x or 9.x line and decides whether the `gen_ai` fields are
worth emitting (they align with banken's agentic niche).

## Sysmon for Linux: current

`sysmon-linux.md` already tracks Sysmon 1.5.3 (2026-09-10, aarch64 + Amazon Linux 2023) and
SysinternalsEBPF 2.2.2. The releases page shows nothing newer. No action.

## MITRE ATT&CK v20: the one with real adoption value

ATT&CK v20.0 shipped 2026-10-13 (current; v19.2 ran 2026-04-28..2026-10-12). Two things matter for
banken:

1. **Stale Navigator layer version.** `tools/attack-layer/main.go` line 111 hardcodes
   `Versions: {"attack": "15", "navigator": "5.0.0", "layer": "4.5"}`. ATT&CK v15 is from early
   2024; the exported heatmap advertises a framework five major versions old. Bump to
   `"attack": "20"` (and the matching Navigator/layer format versions the current Navigator expects).
   This is the recognisable-artifact the README leans on, so stale here is visible.

2. **v20 adds AI/agent technique IDs that banken's `rules/agent/` can finally map to.** Until now the
   agentic rules tagged the closest generic techniques (e.g. `agent_decode` -> T1140 defense-evasion,
   `agent_exfil_to_code_host` -> T1567.001, persistence rules -> T1546/T1574). v20 introduced five
   AI-focused Enterprise techniques (verify exact IDs against attack.mitre.org before tagging):
   - T1699 Direct Prompt Injection
   - T1698 Indirect Prompt Injection
   - T1700 AI-Enabled Exfiltration (has detection DET0927 with analytics)
   - T1608.007 AI Result Poisoning
   - T1685.007 Disable or Modify Tools: Impair Autonomous Defenses

   This is directly on banken's stated novel niche (detection rules FOR autonomous agents,
   `rules/agent/`, an upstream candidate). The agentic rules can now carry real upstream IDs:
   `agent_exfil_to_code_host` -> add T1700; a self-config/defense-tamper rule -> T1685.007; any
   prompt-injection-shaped rule -> T1698/T1699. This both sharpens the Navigator heatmap and
   strengthens the SigmaHQ-upstream story (the rules now reference techniques SigmaHQ can accept).

3. **v19 restructured Defense Evasion** (split toward Stealth and Defense Impairment tactics).
   banken's agent rules use the `attack.defense-evasion` tactic tag (e.g. `agent_decode`,
   `agent_git_config_persistence`, `agent_destructive_action`). Re-validate that every tactic string
   still resolves in the v20 dataset so the Navigator layer does not silently drop a lane.

Verdict: adopt all three. Two tasks: the layer-version bump + a tag-resolves-in-v20 check (one
coverage/attack PR), and the v20 AI-ID adoption in `rules/agent/` (a coverage PR). Both seeded.

## Go and nixpkgs: current

`go.mod` is `go 1.26.8`; Go 1.26 is the current stable line (GA 2026-02-10), 1.27 still in
development. NixOS/hokkaido is on 26.05, the current release. No action in either; noted so the next
scan can diff.

## Seeded tasks

| Lane | What | Why |
| --- | --- | --- |
| `banken.coverage.attack` | Bump `tools/attack-layer` Navigator layer to ATT&CK v20 (from v15) + matching navigator/layer format versions; add a check that every rule's ATT&CK tactic/technique tag resolves in the pinned v20 dataset (catches the v19 Defense Evasion split). | Exported heatmap is 5 major versions stale; v19 restructure may orphan tactic strings. |
| `banken.coverage` | Adopt v20 AI technique IDs in `rules/agent/` (T1699/T1698 prompt injection, T1700 AI-enabled exfil, T1608.007 AI result poisoning, T1685.007 impair autonomous defenses); verify IDs against attack.mitre.org first. | banken's agentic rules can finally carry real upstream ATT&CK IDs; strengthens the SigmaHQ-upstream-candidate story. |
| `banken.standards` | Document the OCSF 1.3.0 emit pin (Amazon Security Lake custom-source ceiling, confirmed 1.3 as of 2026-11) and plan a higher-version emit profile to adopt 1.4 `is_alert`/`security_control`-on-base_event and 1.5 `malware`/`malware_scan_info` when response + YARA land. | Keeps a future reader from breaking Security Lake by bumping; routes the newer schema to the features that need it. |
| `banken.testing` | Raise `conformance/pyproject.toml` pySigma floor from `>=0.11` to `>=2.0` (lock already at 2.0.1). | A lockless resolve could pull a years-old pySigma and weaken the differential. |

Annotated (not re-seeded, lane already owns it): task 1161 (ECS output) with ECS currency
(latest 9.1.0; `8.11` target ~1 year stale; `gen_ai` fields align with the agentic niche).
