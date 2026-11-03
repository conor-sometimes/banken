# Agentic AI detection rules

Detections written for the behaviour of an autonomous AI agent running under its own account (a
coding agent like Claude Code, or a CI/build agent).

This is a rule class **SigmaHQ does not cover**. SigmaHQ's rules target classic threats and catch an
agent only incidentally: a reverse shell is a reverse shell whoever spawns it. These rules instead
ask a question only the agent's *identity* makes meaningful - "should this account be doing this at
all?" That is how you detect an agent that has one of these problems:

- it has been prompt-injected
- it has gone off its task
- it is being driven by an attacker who got into its session

The mechanism is **account scoping**. Each rule names the agent accounts in a `User` selection. So a
behaviour that is noise on a human login is a clean signal when *the agent* does it. Examples of such
behaviour: reading `~/.ssh/config`, running `sudo`, reaching the network.

Edit the `User` list to match your accounts. The companion
[nixos-agent-containment](https://github.com/conor-sometimes/nixos-agent-containment) gives each
agent its own uid and audits it, which is where the account names come from.

## Rules here

- `agent_ssh_access` - an agent account touched an SSH file (private key, authorized_keys, config,
  known_hosts): theft, a backdoor, or lateral-movement recon.
- `agent_ssh_outbound` - the agent *ran* ssh/scp/sshpass or git-over-ssh (it has no host to reach).
- `agent_exfil_to_code_host` - pushed to a gist/release/new repo, published or uploaded (T1567.001).
- `agent_proxy_bypass` - unset/overrode the egress proxy, `--noproxy`, proxychains.
- `agent_git_config_persistence` - a git config or hook that runs code or steals credentials.
- `agent_self_config_modification` - wrote its own harness config: settings, hooks, skills, CLAUDE.md.
- `agent_decode` - the agent decoded encoded data (base64/base32/xxd/uudecode/openssl -d): unpacking
  an obfuscated payload (T1140). `deobfuscate_and_run` catches a decode piped into a shell host-wide.
- `agent_ai_enabled_exfil` - the agent ran a bulk transfer to external storage (rclone/aws s3/gsutil/
  curl --upload-file ...): **T1700 AI-Enabled Exfiltration** (new in ATT&CK v20). Owns object-storage
  and generic file-upload; `agent_exfil_to_code_host` owns the git/gist/release channel.
- `agent_impair_autonomous_defenses` - the agent stopped/killed/rewrote a security or EDR tool
  (Falcon, osquery, Wazuh, auditd, ClamAV, mdatp ...): **T1685.007 Impair Autonomous Defenses** (new in
  ATT&CK v20). The account-scoped framing of `tamper_banken` / the `disable_*` rules.
- `agent_anti_automation_evasion` - the agent called a CAPTCHA-solving service (2captcha/CapSolver/
  anti-captcha ...) or pulled in an anti-bot "stealth" automation toolkit (undetected-chromedriver,
  playwright-stealth ...): **T1696 Anti-Automation Evasion** (new in ATT&CK v20). banken sees the
  solver call / toolkit install, not the CAPTCHA itself.
- `agent_steal_app_password` - the agent read an application-specific password store: a mail client's
  saved credentials (.msmtprc/.mbsyncrc/.offlineimaprc/.muttrc/Thunderbird), .authinfo, a .netrc
  machine entry, or git-credentials: **T1697 Steal Application Specific Passwords** (new in ATT&CK
  v20), the host-observable "obtain an ASP stored on a system" slice only.
- `honeytoken_access` - any process opened a planted decoy credential (host-wide, critical).

## ATT&CK v20 AI techniques - what banken can and cannot see

ATT&CK v20 (Oct 2026) added the first AI/agent techniques. banken keys on **host process telemetry**,
so it detects an AI technique only when that technique has a host-observable footprint:

- **T1700 AI-Enabled Exfiltration** - detected (`agent_ai_enabled_exfil`). The injected prompt is
  invisible. But the agent *executing* the transfer is a process event, which is exactly what the
  technique's analytics (AN2079/AN2080) key on.
- **T1685.007 Impair Autonomous Defenses** - detected (`agent_impair_autonomous_defenses`). banken
  can't read the "fake system message" in the malware. But it sees the agent taking the defense tool
  down, which is the realised effect.
- **T1696 Anti-Automation Evasion** - **partially** detected (`agent_anti_automation_evasion`). The
  CAPTCHA image and the solved token live in browser/LLM content, which a host EDR cannot see. What
  banken *can* see is the agent's host-side footprint: a call to a known CAPTCHA-solving service, or
  the install/use of an anti-bot "stealth" automation toolkit. It deliberately does **not** try to
  catch the homegrown image-transform approach in T1696.001's own example (an ImageMagick script).
  ImageMagick is overwhelmingly benign, so matching it would be a false claim dressed as a detection.
  The site-side view (bot traffic reaching a protected form) is out of banken's reach by design.
  MITRE itself notes no target-side CAPTCHA telemetry exists.
- **T1697 Steal Application Specific Passwords** - **partially** detected (`agent_steal_app_password`),
  the host-observable slice only. T1697 is mostly an identity-provider / SaaS technique: generate an
  ASP at the IdP, phish a user for one, then log in over a legacy non-MFA path. All of that lives in
  IdP/SaaS audit logs and is invisible to a host EDR; the technique's own analytics (AN2075-AN2077)
  key on those logs. The one host-adjacent variant the technique lists is "obtain an ASP stored on a
  system": the agent reading an on-host ASP store (mail-client creds, .authinfo, .netrc,
  git-credentials). That is all `agent_steal_app_password` claims. The MFA-bypass login itself is not
  host-observable, and no rule pretends it is.
- **T1698 Indirect / T1699 Direct Prompt Injection** - **not** detected as such, and no rule pretends
  to. The injection lives in LLM-conversation content (a web page, a document, the prompt box), which
  is invisible to a host EDR by design. The harness transcript is the source, not banken. What banken
  *can* catch is the injection's downstream **effect**: the agent then exfiltrating, impairing a
  defense, reaching the network, or touching a secret. The rules above and the rest of this set
  already cover that. Writing a "prompt injection detector" over process telemetry would be a false
  claim.
- **T1608.007 AI Result Poisoning** - out of scope. It is a PRE/resource-development technique about
  seeding web content attackers control, and nothing executes on the host.

More ideas, ranked and grounded in banken's telemetry, are in
[docs/design/agentic-detection-ideas.md](../../docs/design/agentic-detection-ideas.md).

## Design notes

- **Scope, don't guess.** A rule here fires on a named account doing something it has no business
  doing, never on a heuristic about "looking like an AI". It is auditable and has a near-zero false
  positive rate by construction.
- **Upstream candidate.** Once this set is solid it is a candidate to contribute to SigmaHQ as a new
  category (agent / service-account abuse), which would be among the first detections written *for*
  AI agents. Until then it lives here and ships in banken's baseline.
