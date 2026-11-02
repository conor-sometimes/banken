#!/usr/bin/env bash
# syslogclear.sh - benign emulation of clearing system logs, for detection-rule testing.
#
# What an attacker does: wipe or truncate the host's system logs to destroy evidence - `truncate -s0
# /var/log/messages`, `rm /var/log/journal/*` (T1070.002). This does the harmless analogue: it
# truncates/removes DUMMY files under a scratch `.../var/log/` tree (removed on exit), so no real log
# is touched; the /var/log/<syslog> path in argv is the signal. An application log under /var/log is
# deliberately NOT matched - only the named system logs. See ./README.md.
#
# Imitates: rules/defense-evasion/system_log_cleared.yml - ATT&CK T1070.002 Clear Linux System Logs
# Expected rules: system_log_cleared
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
mkdir -p "$work/var/log/journal" >/dev/null 2>&1 || true
: > "$work/var/log/messages"
: > "$work/var/log/journal/dummy"

# --- TTP: truncate a system log to zero -> system_log_cleared (wiper + syslog_path) ---
truncate -s0 "$work/var/log/messages" >/dev/null 2>&1 || true

# --- TTP: remove a journal file -> system_log_cleared (wiper + syslog_path) ---
rm -f "$work/var/log/journal/dummy" >/dev/null 2>&1 || true

exit 0
