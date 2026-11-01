#!/usr/bin/env bash
# deobfuscate.sh - benign emulation of decode-and-run (deobfuscate into a shell), for detection-rule testing.
#
# What an attacker does: carry the next stage as base64/hex on the command line, then decode it and
# pipe it straight into a shell in one breath (base64 -d | sh), so it never appears in cleartext. This
# does the harmless analogue: the "payload" decodes to the no-op command `true`, so the shell runs
# nothing of consequence; the decode|shell pipeline exec is the signal. agent_decode catches an agent
# merely decoding; this is the run, host-wide. See ./README.md.
#
# Imitates: rules/defense-evasion/deobfuscate_and_run.yml - ATT&CK T1140 into T1059.004
# Expected rules: deobfuscate_and_run
set -u

# a base64 blob that decodes to the harmless no-op command `true`
payload=$(printf 'true\n' | base64 2>/dev/null) || exit 0

# --- TTP: decode piped straight into a shell, as one argv -> deobfuscate_and_run (decode_to_shell) ---
# bash -c so the whole `... | base64 -d | sh` is one process's argv (what the rule matches); the
# decoded command is `true`, so the shell runs nothing of consequence.
timeout 3 bash -c "echo $payload | base64 -d | sh" >/dev/null 2>&1 || true

exit 0
