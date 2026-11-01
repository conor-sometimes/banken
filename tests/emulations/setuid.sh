#!/usr/bin/env bash
# setuid.sh - benign emulation of setting the setuid/setgid bit, for detection-rule testing.
#
# What an attacker does: set the setuid/setgid bit on a file (chmod u+s / 4755) so it runs with its
# owner's privileges for anyone who executes it - a privilege-escalation backdoor, especially if
# root-owned (T1548.001). This does the harmless analogue: it chmod-s the bit on a DUMMY file in its
# own scratch dir, owned by the unprivileged runner (so the setuid bit grants nothing) and removed on
# exit; the chmod argv is the signal. privilege_escalation_attempt catches USING sudo/su; this catches
# CREATING the mechanism. See ./README.md.
#
# Imitates: rules/privilege-escalation/setuid_bit_set.yml - ATT&CK T1548.001 Setuid and Setgid
# Expected rules: setuid_bit_set
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
: > "$work/dummybin"

# --- TTP: chmod u+s (symbolic setuid) -> setuid_bit_set (chmod + symbolic) ---
chmod u+xs "$work/dummybin" >/dev/null 2>&1 || true

# --- TTP: chmod 4755 (numeric setuid) -> setuid_bit_set (chmod + numeric) ---
chmod 4755 "$work/dummybin" >/dev/null 2>&1 || true

exit 0
