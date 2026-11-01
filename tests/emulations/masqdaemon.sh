#!/usr/bin/env bash
# masqdaemon.sh - benign emulation of a process masquerading as a system binary, for detection-rule testing.
#
# What an attacker does: run a payload from a world-writable scratch dir under the name of a core
# daemon (sshd, crond, systemd, kworker ...), or out of a directory named "..." (hidden in plain
# sight), so it blends into `ps` output (T1036.005). This does the harmless analogue: it copies the
# no-op binary `true` into a /tmp scratch dir under a daemon name and into a "..." dir, then execs
# those (they just exit 0). A real daemon never lives in /tmp, so the scratch-dir daemon name is the
# signal; nothing harmful runs. See ./README.md.
#
# Imitates: rules/defense-evasion/masquerading.yml - ATT&CK T1036.005 Match Legitimate Name or Location
# Expected rules: masquerading
set -u
# mktemp under /tmp so the Image path has the world-writable prefix the rule keys on.
work=$(mktemp -d /tmp/masq.XXXXXX) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

true_bin=$(command -v true 2>/dev/null) || exit 0

# --- TTP: a core-daemon name executing from a scratch dir -> masquerading (scratch_daemon) ---
cp "$true_bin" "$work/crond" >/dev/null 2>&1 && "$work/crond" >/dev/null 2>&1 || true

# --- TTP: a process running out of a directory named "..." -> masquerading (dotdir) ---
mkdir -p "$work/..." >/dev/null 2>&1 || true
cp "$true_bin" "$work/.../sh" >/dev/null 2>&1 && "$work/.../sh" -c id >/dev/null 2>&1 || true

exit 0
