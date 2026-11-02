#!/usr/bin/env bash
# sigmahq_fe_profile_script.sh - benign SigmaHQ FILE_EVENT emulation.
#
# This exercises the file_event layer (see sigmahq_fe_ebpfbackdoor.sh header):
# the create is only visible to banken because the watched scratch file is in
# services.banken.audit.watchPaths.
#
# What an attacker does: drop a shell script under /etc/profile.d/ so it runs at
# every login (T1546.004 persistence). The SigmaHQ rule keys on a TargetFilename
# that CONTAINS '/etc/profile.d/' and ends in '.sh' or '.csh' - it is not
# anchored to the real /etc, so a path with that segment anywhere matches.
# Harmless analogue: create an empty '.sh' file under a '.../etc/profile.d/'
# segment inside the harness's watched scratch tree - never sourced by any login.
#
# Imitates (SigmaHQ): file_event_lnx_susp_shell_script_under_profile_directory.yml
#   ATT&CK T1546.004
# Expected rule: file_event_lnx_susp_shell_script_under_profile_directory
set -u

d="/var/lib/bkfwatch/etc/profile.d"
[ -d "$d" ] || { echo "BANKEN-EMUL-SKIP: no watch dir $d"; exit 0; }

: > "$d/bk.sh" 2>/dev/null || true

exit 0
