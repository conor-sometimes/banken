#!/usr/bin/env bash
# gtfopager.sh - benign emulation of a pager/editor shell escape (GTFOBins), for rule testing.
#
# What an attacker does: drive an editor non-interactively into running a command - `vim -c
# ':!/bin/sh'`. This does the harmless analogue: a stock test VM has no editor installed, so the
# script makes a harmless stand-in named `vim` in a scratch dir (the same pattern masqdaemon.sh
# uses) that just exits 0, and invokes it with the real GTFOBins escape argv - `vim -c ':!true'`.
# The editor name + the :! escape in the argv is exactly what the rule keys on; nothing runs. If a
# real vim is present it is also exercised. See ./README.md.
#
# Imitates: rules/execution/gtfobin_pager_escape.yml - ATT&CK T1059 / T1202
# Expected rules: gtfobin_pager_escape
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
: > "$work/f"

# --- TTP: an editor driven to a :! shell escape via -c -> gtfobin_pager_escape (editor_escape) ---
# Harmless stand-in so the abuse-shape argv is logged on a box with no editor installed.
printf '#!/bin/sh\nexit 0\n' > "$work/vim"
chmod +x "$work/vim" 2>/dev/null || true
"$work/vim" -c ':!true' -c ':q!' "$work/f" >/dev/null 2>&1 || true

# If a real vim exists, exercise it too (runs `true`, then quits) - same escape, real binary.
if command -v vim >/dev/null 2>&1; then
	timeout 5 vim -Es -c ':!true' -c ':q!' "$work/f" >/dev/null 2>&1 || true
fi

exit 0
