#!/usr/bin/env bash
# masqext.sh - benign emulation of extension masquerading, for detection-rule testing.
#
# What an attacker does: give a script a harmless-looking name so it runs unnoticed - `sh
# /tmp/image.png` (T1036.008), or a double extension `report.pdf.sh` (T1036.007). This does the
# harmless analogue: it makes DUMMY scripts in scratch (each just echoes, removed on exit) named
# image.png and report.pdf.sh and runs them; the media/double extension is the signal. A normal
# `sh script.sh` is NOT matched. See ./README.md.
#
# Imitates: rules/defense-evasion/masquerade_extension.yml - ATT&CK T1036.008 / T1036.007 Masquerading
# Expected rules: masquerade_extension
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

# --- TTP: a shell running a .png-named script -> masquerade_extension (shell_runs_media) ---
printf '#!/bin/sh\necho benign\n' > "$work/image.png"
sh "$work/image.png" >/dev/null 2>&1 || true

# --- TTP: a binary with a .pdf.sh double extension -> masquerade_extension (double_ext) ---
printf '#!/bin/sh\necho benign\n' > "$work/report.pdf.sh"
chmod +x "$work/report.pdf.sh" >/dev/null 2>&1 || true
"$work/report.pdf.sh" >/dev/null 2>&1 || true

exit 0
