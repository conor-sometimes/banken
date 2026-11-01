#!/usr/bin/env bash
# stomp.sh - benign emulation of timestamp modification (timestomp), for detection-rule testing.
#
# What an attacker does: backdate a dropped file so it blends with its neighbours, or copy another
# file's time, with touch -t / -d / -r (T1070.006 anti-forensics). This does the harmless analogue: it
# touch-stomps a DUMMY file in its own scratch dir, removed on exit (a plain `touch` to now is NOT what
# fires - only an explicit time or a reference does); the touch -t/-r argv is the signal. See ./README.md.
#
# Imitates: rules/defense-evasion/timestomp.yml - ATT&CK T1070.006 Timestomp
# Expected rules: timestomp
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

# --- TTP: touch with an explicit timestamp (backdate) -> timestomp (touch + stomping) ---
touch -m -t 197001010000.00 "$work/dropped" >/dev/null 2>&1 || true

# --- TTP: touch copying another file's timestamp (-r reference) -> timestomp (touch + stomping) ---
touch -r /bin/sh "$work/ref" >/dev/null 2>&1 || true

exit 0
