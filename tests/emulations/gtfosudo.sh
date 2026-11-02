#!/usr/bin/env bash
# gtfosudo.sh - benign emulation of a sudo GTFOBin breakout, for detection-rule testing.
#
# What an attacker does: `sudo find ... -exec /bin/sh` (and friends) to get a root shell. This does
# the harmless analogue: it runs the SAME argv but through `sudo -n` (non-interactive), which fails
# without a cached credential and so never actually escalates - the execve of sudo with the breakout
# argv is logged (the attempt), which is the signal, and no shell is ever handed out. Targets a
# nonexistent scratch path, and the -exec'd command is `true`. Running sudo also (correctly) trips
# privilege_escalation_attempt; both are expected. See ./README.md.
#
# Imitates: rules/privilege-escalation/gtfobin_sudo_breakout.yml - ATT&CK T1548.003 / T1202
# Expected rules: gtfobin_sudo_breakout, privilege_escalation_attempt
set -u
command -v sudo >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no sudo"; exit 0; }

# --- TTP: sudo find -exec a shell -> gtfobin_sudo_breakout (sudo + gtfobin + escape_token) ---
sudo -n find /nonexistent-gtfosudo -exec /bin/sh -c true \; -quit >/dev/null 2>&1 || true

# --- TTP: sudo awk BEGIN{system()} -> gtfobin_sudo_breakout ---
sudo -n awk 'BEGIN{system("true")}' >/dev/null 2>&1 || true

exit 0
