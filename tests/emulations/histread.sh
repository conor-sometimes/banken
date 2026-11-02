#!/usr/bin/env bash
# histread.sh - benign emulation of reading shell history for credentials, for detection-rule testing.
#
# What an attacker does: sweep command history for passwords and connection strings - `cat
# ~/.bash_history | grep -e pass -e ssh` (T1552.003). This does the harmless analogue: it writes a
# DUMMY .bash_history in scratch (removed on exit) and cats it; the history filename in argv is the
# signal (not the real ~/.bash_history). Wiping history is a separate rule (history_tamper). See
# ./README.md.
#
# Imitates: rules/credential-access/shell_history_read.yml - ATT&CK T1552.003 Bash/Zsh History
# Expected rules: shell_history_read
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
printf 'ls -la\nnotarealpassword=dummy\n' > "$work/.bash_history"

# --- TTP: read a shell history file -> shell_history_read (reader cat + histfile) ---
cat "$work/.bash_history" >/dev/null 2>&1 || true

exit 0
