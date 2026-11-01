#!/usr/bin/env bash
# agentdecode.sh - benign emulation of an agent account decoding encoded data, for detection-rule testing.
#
# What an attacker does: a derailed or prompt-injected agent stages its next payload as base64/hex and
# decodes it (base64 -d, xxd -r, uudecode, openssl -d) before running it, so the blob slips past a
# reviewer reading the session. This does the harmless analogue: it decodes a DUMMY base64 blob in its
# own scratch dir and throws the result away - the decode exec is the signal the rule catches; nothing
# is run. See ./README.md.
#
# Account-scoped: rules/agent/agent_decode.yml keys on User in {claude,redteam,lab}, so this only
# fires when run AS an agent account (the harness must run it as one); for an ordinary user, who
# decodes data routinely, it is inert by design.
#
# Imitates: rules/agent/agent_decode.yml - ATT&CK T1140 Deobfuscate/Decode Files (agent account)
# Expected rules: agent_decode
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

# a dummy base64 blob (decodes to the harmless word "hello"), in scratch
printf 'hello\n' | base64 > "$work/stage.b64" 2>/dev/null || true

# --- TTP: base64 -d a staged blob -> agent_decode (flag_decoder + decode_flag) ---
if command -v base64 >/dev/null 2>&1; then
	base64 -d "$work/stage.b64" >/dev/null 2>&1 || true
fi

# --- TTP: xxd -r (reverse a hexdump) -> agent_decode (flag_decoder + decode_flag) ---
if command -v xxd >/dev/null 2>&1; then
	printf '00000000: 6869\n' | xxd -r >/dev/null 2>&1 || true
fi

exit 0
