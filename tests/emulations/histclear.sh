#!/usr/bin/env bash
# histclear.sh - benign emulation of shell-history tampering, for detection-rule testing.
#
# What an attacker does after the fact: wipe, truncate or symlink-to-/dev/null the shell history so
# their commands are not recorded (T1070.003). This does the harmless analogue: it creates DUMMY
# history files in its own scratch dir and rm/ln-s THOSE, never a real ~/.bash_history. The wipe exec
# (with the history path in argv) is the signal. (The shell-builtin forms - history -c, unset HISTFILE
# - run no process and are invisible to any exec detector, by design.) See ./README.md.
#
# Imitates: rules/defense-evasion/history_tamper.yml - ATT&CK T1070.003 Clear Command History
# Expected rules: history_tamper
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
printf 'ls\nwhoami\n' > "$work/.bash_history"
printf 'ls\n' > "$work/.zsh_history"

# --- TTP: rm the history file -> history_tamper (wiper + histfile_cmd) ---
rm -f "$work/.bash_history" >/dev/null 2>&1 || true

# --- TTP: symlink the history to /dev/null so nothing is ever recorded -> history_tamper (wiper + histfile_cmd) ---
ln -sf /dev/null "$work/.zsh_history" >/dev/null 2>&1 || true

exit 0
