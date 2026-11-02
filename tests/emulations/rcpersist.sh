#!/usr/bin/env bash
# rcpersist.sh - benign emulation of rc/init-script persistence, for detection-rule testing.
#
# What an attacker does: append a payload to a boot script so it runs at startup -
# `... | tee -a /etc/rc.local` (T1037.004), durable persistence. This does the harmless analogue: it
# tees a no-op line into a DUMMY scratch `.../etc/rc.local` (removed on exit) - never the real boot
# script; the /etc/rc.local path in argv is the signal. See ./README.md.
#
# Imitates: rules/persistence/rc_script_persistence.yml - ATT&CK T1037.004 RC Scripts
# Expected rules: rc_script_persistence
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
mkdir -p "$work/etc" >/dev/null 2>&1 || true

# --- TTP: append a command to a boot rc script -> rc_script_persistence (editor tee + rc_path) ---
printf '%s\n' 'exit 0' | tee -a "$work/etc/rc.local" >/dev/null 2>&1 || true

exit 0
