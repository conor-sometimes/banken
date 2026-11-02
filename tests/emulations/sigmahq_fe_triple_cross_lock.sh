#!/usr/bin/env bash
# sigmahq_fe_triple_cross_lock.sh - benign SigmaHQ FILE_EVENT emulation.
#
# This exercises the file_event layer (see sigmahq_fe_ebpfbackdoor.sh header):
# the create is only visible to banken because the watched file is in
# services.banken.audit.watchPaths.
#
# What an attacker does: the Triple Cross eBPF rootkit drops its default lock
# file at exactly '/tmp/rootlog' (T1014). The SigmaHQ rule keys on a
# TargetFilename equal to '/tmp/rootlog'. Harmless analogue: create an empty
# file at that path (world-writable /tmp) and truncate it - it is just a zero
# byte file, no rootkit, nothing loads it.
#
# Imitates (SigmaHQ): file_event_lnx_triple_cross_rootkit_lock_file.yml - ATT&CK T1014
# Expected rule: file_event_lnx_triple_cross_rootkit_lock_file
set -u

: > /tmp/rootlog 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot write /tmp/rootlog"; exit 0; }

exit 0
