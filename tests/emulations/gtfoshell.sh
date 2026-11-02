#!/usr/bin/env bash
# gtfoshell.sh - benign emulation of a trusted binary spawning a shell (GTFOBins), for rule testing.
#
# What an attacker does: use a utility's own escape to fork a shell - find -exec /bin/sh, awk
# BEGIN{system()}, busybox sh. This does the harmless analogue: it runs the SAME recipes but the
# command the shell runs is `true` (a no-op), inside a scratch dir, so nothing of consequence
# happens; the abuse shape in the argv is identical to the real thing. See ./README.md.
#
# Imitates: rules/execution/gtfobin_shell_spawn.yml - ATT&CK T1059.004 / T1202 / T1218
# Expected rules: gtfobin_shell_spawn
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
: > "$work/f"

# --- TTP: find -exec a shell -> gtfobin_shell_spawn (argv_gtfobin + argv_recipe) ---
find "$work" -exec /bin/sh -c true \; -quit >/dev/null 2>&1 || true

# --- TTP: awk BEGIN{system()} -> gtfobin_shell_spawn (awk_system) ---
if command -v awk >/dev/null 2>&1; then
	awk 'BEGIN{system("true")}' >/dev/null 2>&1 || true
fi

# --- TTP: busybox shell applet -> gtfobin_shell_spawn (busybox_shell) ---
if command -v busybox >/dev/null 2>&1; then
	busybox sh -c true >/dev/null 2>&1 || true
fi

exit 0
