#!/usr/bin/env bash
# sudoersedit.sh - benign emulation of a sudoers policy modification, for detection-rule testing.
#
# What an attacker does: edit /etc/sudoers or a /etc/sudoers.d/ drop-in to grant NOPASSWD, disable
# tty_tickets, or set an unlimited timestamp_timeout - rewriting who can become root and how freely
# (T1548.003). This does the harmless analogue: it cp-s the REAL /etc/sudoers to a scratch copy (a
# read-only reference naming the real path in argv, which is what the rule matches) and sed-s the
# NOPASSWD change into only the SCRATCH copy, validated with `visudo -c` - the real policy is never
# written. privilege_escalation_attempt covers running sudo; this covers rewriting its rules.
# See ./README.md.
#
# Imitates: rules/privilege-escalation/sudoers_modification.yml - ATT&CK T1548.003 Sudo and Sudo Caching
# Expected rules: sudoers_modification
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

# --- TTP: reference the real sudoers with a file tool -> sudoers_modification (editor + sudoers_cmd) ---
# cp READS /etc/sudoers into scratch (fails harmlessly if unreadable, as it is for a normal user); the
# real policy is never written. The argv (a file tool naming /etc/sudoers) is the signal.
cp /etc/sudoers "$work/sudoers.copy" >/dev/null 2>&1 || true

# --- benign analogue of the actual tamper: the NOPASSWD edit lands only on the SCRATCH copy ---
printf 'Defaults env_reset\n' > "$work/90-emul"
sed -i 's/env_reset/env_reset,timestamp_timeout=-1/' "$work/90-emul" >/dev/null 2>&1 || true
if command -v visudo >/dev/null 2>&1; then
	visudo -c -f "$work/90-emul" >/dev/null 2>&1 || true
fi

exit 0
