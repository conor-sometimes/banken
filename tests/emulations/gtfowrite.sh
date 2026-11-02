#!/usr/bin/env bash
# gtfowrite.sh - benign emulation of a GTFOBins file-write to a code-execution sink, for rule tests.
#
# What an attacker does: use a file-write tool (tee/dd/cp) to drop content into a sink that runs
# code later - the loader preload list, a login profile script. This does the harmless analogue: it
# writes the SAME tools to a SCRATCH tree whose path mirrors the real sink
# (<scratch>/etc/ld.so.preload, <scratch>/etc/profile.d/...), so the sink path appears in the argv /
# file access (the signal) while nothing outside the scratch dir is touched. The real
# /etc/ld.so.preload is never written. See ./README.md.
#
# Imitates: rules/impact/gtfobin_file_write_sink.yml - ATT&CK T1565.001 / T1574.006 / T1546.004
# Expected rules: gtfobin_file_write_sink
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
mkdir -p "$work/etc/profile.d" 2>/dev/null || true

# --- TTP: tee the loader preload list -> gtfobin_file_write_sink (writer + sink_cmd) ---
echo '/tmp/evil.so' | tee "$work/etc/ld.so.preload" >/dev/null 2>&1 || true

# --- TTP: dd into a login profile script -> gtfobin_file_write_sink (writer + sink_cmd) ---
printf '' | dd of="$work/etc/profile.d/evil.sh" >/dev/null 2>&1 || true

exit 0
