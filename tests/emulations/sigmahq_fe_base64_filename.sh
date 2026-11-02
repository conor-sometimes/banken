#!/usr/bin/env bash
# sigmahq_fe_base64_filename.sh - benign SigmaHQ FILE_EVENT emulation.
#
# This exercises the file_event layer (see sigmahq_fe_ebpfbackdoor.sh header):
# the touch is only visible to banken because the watched scratch dir is in
# services.banken.audit.watchPaths.
#
# What an attacker does: VShell-style payloads use filenames that embed a bash
# brace-expansion such as '{echo,...}' or '{base64,-d}' so that a shell script
# globbing the directory silently executes the encoded command (T1059.004 /
# T1027). The SigmaHQ rule keys only on a TargetFilename containing '{echo' or
# '{base64,-d}'. Harmless analogue: create an empty file whose name contains the
# literal '{echo' marker in the harness's watched scratch dir - the name is never
# expanded by any shell, nothing executes.
#
# Imitates (SigmaHQ): file_event_lnx_susp_filename_with_embedded_base64_command.yml
#   ATT&CK T1059.004
# Expected rule: file_event_lnx_susp_filename_with_embedded_base64_command
set -u

w="/var/lib/bkfwatch"
[ -d "$w" ] || { echo "BANKEN-EMUL-SKIP: no watch dir $w"; exit 0; }

# Single-quoted so the brace is a literal filename character, never expanded.
: > "$w"'/bk-{echo' 2>/dev/null || true

exit 0
