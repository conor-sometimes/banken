#!/usr/bin/env bash
# permtamper.sh - benign emulation of weakening/locking file permissions, for detection-rule testing.
#
# What an attacker does: chattr toggling the immutable/append-only attribute (locking an implant so
# it cannot be removed, or unlocking a protected system file), or chmod making a file world-writable
# (777 / 666 / o+w) so anyone can overwrite it (T1222.002). This does the harmless analogue: it
# chmod-s and chattr-s a DUMMY file in its own /tmp scratch dir, removed on exit; no system path is
# touched. setuid_bit_set covers the setuid bit; this covers the world-writable and immutable forms.
# See ./README.md.
#
# Imitates: rules/defense-evasion/permission_modification.yml - ATT&CK T1222.002 Linux File Permissions
# Expected rules: permission_modification
set -u
work=$(mktemp -d) || exit 0
trap 'chattr -i "$work/dummy" 2>/dev/null; rm -rf "$work" 2>/dev/null' EXIT
: > "$work/dummy"
: > "$work/drop.sh"

# --- TTP: chmod world-writable (777) on a scratch file -> permission_modification (chmod + world_writable) ---
chmod 777 "$work/drop.sh" >/dev/null 2>&1 || true

# --- TTP: chattr toggling the immutable attribute on a scratch file -> permission_modification (chattr) ---
# On tmpfs/overlayfs or unprivileged this fails harmlessly; the chattr -i argv is the signal either way.
if command -v chattr >/dev/null 2>&1; then
	chattr -i "$work/dummy" >/dev/null 2>&1 || true
fi

exit 0
