#!/usr/bin/env bash
# sigmahq_fe_doas_conf.sh - benign SigmaHQ FILE_EVENT emulation.
#
# This exercises the file_event layer (see sigmahq_fe_ebpfbackdoor.sh header):
# the create is only visible to banken because the watched scratch file is in
# services.banken.audit.watchPaths.
#
# What an attacker does: write an /etc/doas.conf granting themselves passwordless
# doas (T1548 privilege escalation / persistence). The SigmaHQ rule keys on a
# TargetFilename that ENDS WITH '/etc/doas.conf'. Harmless analogue: create an
# empty file whose path ends in '.../etc/doas.conf' inside the harness's watched
# scratch tree - it is not the real /etc/doas.conf and doas never reads it.
#
# Imitates (SigmaHQ): file_event_lnx_doas_conf_creation.yml - ATT&CK T1548
# Expected rule: file_event_lnx_doas_conf_creation
set -u

d="/var/lib/bkfwatch/etc"
[ -d "$d" ] || { echo "BANKEN-EMUL-SKIP: no watch dir $d"; exit 0; }

: > "$d/doas.conf" 2>/dev/null || true

exit 0
