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

# --- TTP: copy a shell into a scratch dir under a daemon name -> masquerading (shell_copy) ---
# This is the signal that does NOT depend on /tmp being exec-able: the `cp /bin/sh .../crond` argv
# is caught on the copy itself, so it fires even where a hardened /tmp is mounted noexec (which
# silently defeats the execute-from-scratch branches below). The copy is never run.
cp /bin/sh "$work/crond" >/dev/null 2>&1 || true

# --- TTP: a daemon name and a "..." dir executing from scratch -> masquerading (scratch_daemon,
# dotdir) ---
# Extra coverage where /tmp allows exec (same rule), harmless no-op where it does not. The copies
# are of `true`, so running them just exits 0.
cp "$true_bin" "$work/sshd" >/dev/null 2>&1 && "$work/sshd" >/dev/null 2>&1 || true
mkdir -p "$work/..." >/dev/null 2>&1 || true
cp "$true_bin" "$work/.../x" >/dev/null 2>&1 && "$work/.../x" >/dev/null 2>&1 || true

exit 0
