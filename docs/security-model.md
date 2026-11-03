# Security model

banken runs as root, because it reads the root-owned audit log. It may one day pull rules from a
remote repo. So the rule channel must never become a way to run code as root. A detector you can
turn into a trojan is worse than no detector. The guarantee is layered.

1. **Rules are inert data, never code.** The Sigma subset has no eval path: no shell-out, no
   template or format expansion, no plugin loading, no rule-controlled file/URL/exec. A rule value
   is only ever matched as an opaque string. A regexp is Go's RE2 - linear time, no catastrophic
   backtracking, no code execution. YAML is parsed with `yaml.v3`, which has none of the
   object-instantiation gadgets that make `yaml.load`-style parsers dangerous. So even a
   fully attacker-authored rule can at worst produce wrong or missing *detections* - never
   execution. `TestRuleValuesAreInertData` locks this: shell substitutions, format verbs,
   templates, globs and path-traversal strings all stay literal.
2. **Logs are inert data too - the log4j lesson.** The other untrusted channel is the log itself.
   banken parses attacker-influenced bytes, since an attacker can write to the audit stream through
   what they run. Parsing never interprets log content:
   - no exec or shell-out;
   - no format-string injection (every format string is a literal; log values are only ever
     `%q`/`%s` arguments);
   - no file opened or URL fetched from a field;
   - no template or `${...}` lookup expansion (the thing that made log4j a remote-code-execution
     bug);
   - the XML source refuses external entities and entity-expansion bombs (`TestSysmonNoXXE`; Go's
     `encoding/xml` resolves no external or DTD entities).

   A rule regex is RE2, so even a hostile regex matched against a crafted event cannot
   catastrophically backtrack (`TestRuleRegexCannotReDoS`, proven against the textbook evil
   patterns). Every parser is fuzzed to tens of millions of executions with zero crashes. The "never
   fail the batch on content" contract means a malformed or adversarial line is skipped, not a way
   to blind the detector.
3. **Memory-safe, no kernel component.** banken is pure Go - no `unsafe`, no cgo, no C anywhere. So
   whole bug classes that plague EDRs are structurally impossible: no buffer overflow, no
   use-after-free, no out-of-bounds read of the untrusted bytes it parses. It is one static binary
   with no kernel module and no driver. So, unlike the agents it takes after, it **cannot panic your
   kernel or blue-screen the host**. The worst a banken bug does is a missed or wrong detection in
   userspace, caught by the panic guards, never a downed machine. CodeQL's data-flow analysis runs
   on every push, on top of gosec and staticcheck.
4. **Response actions are operator policy, never rule-embedded.** A rule only emits a tag. The local
   operator config maps tags to actions (kill, quarantine). A remote rule can never carry its own
   "kill this / delete that."
5. **Trusted path (planned).** As root, banken should distrust rules from a directory writable by
   anyone but its owner - the classic local-unprivileged-user-edits-the-rule escalation - and flag
   it, with an opt-in strict mode to refuse. *Not yet implemented.* Today banken only loads from the
   paths it is given; make the rules dir root-owned and `0755` yourself.
6. **The fetch is deprivileged and can't run code (planned).** When remote rule sync exists it will
   be a separate command, never the scan. It will neuter git's code-execution surfaces (hooks,
   filter drivers, fsmonitor) or use a plain tarball, and run as a dedicated low-privilege user.
   *There is no fetch today.* Rules are local only, so this surface does not exist yet.
7. **Signed bundles (v2).** Remote rule and config bundles are signature-verified against a locally
   pinned public key, with a monotonic version. So a compromised transport or repo host cannot push
   a rogue rule set in the first place.

The scan itself is one-shot and has no inbound or rule-fetch network surface by design. The only
outbound connection is the optional webhook POST from the scan process. The hardened systemd unit
scores exposure 2.1 ("OK") under `systemd-analyze security` on every distro in the matrix.
