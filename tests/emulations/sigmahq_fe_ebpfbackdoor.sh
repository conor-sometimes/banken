#!/usr/bin/env bash
# sigmahq_fe_ebpfbackdoor.sh - benign SigmaHQ FILE_EVENT emulation.
#
# This exercises the file_event layer of the harness: banken only sees a file
# touch when the path is under services.banken.audit.watchPaths (auditd
# "-w <path> -p rwa"), so the harness watches a world-writable scratch directory
# and the script creates the rule's indicator file there.
#
# What an attacker does: the TripleCross eBPF rootkit drops an "ebpfbackdoor"
# file into cron.d / sudoers.d to persist (T1053.003). The SigmaHQ rule keys only
# on a TargetFilename ending in 'ebpfbackdoor', whatever the directory. Harmless
# analogue: create an empty file named ebpfbackdoor in the harness's watched
# scratch dir - no cron/sudoers entry, no persistence, just the filename the rule
# detects.
#
# Imitates (SigmaHQ): file_event_lnx_triple_cross_rootkit_persistence.yml - ATT&CK T1053.003
# Expected rule: file_event_lnx_triple_cross_rootkit_persistence
set -u

w="/var/lib/bkfwatch"
[ -d "$w" ] || { echo "BANKEN-EMUL-SKIP: no watch dir $w"; exit 0; }

: > "$w/ebpfbackdoor" 2>/dev/null || true

exit 0
