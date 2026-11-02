#!/usr/bin/env bash
# sigmahq_find_perm.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: hunt for SUID/SGID/world-writable files for privilege
# escalation (T1548.001 recon), e.g. `find / -perm -4000`. Harmless analogue:
# `find <scratch> -perm -4000` over an empty scratch dir in the user's own home
# - read-only, finds nothing. The execve of /find whose command line contains
# '-perm -4000', which the rule keys on, is real. find also fires
# file_and_directory_discovery (any /find) - a legit twin.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_find_execution.yml - ATT&CK T1548.001
# Expected rules: proc_creation_lnx_susp_find_execution, proc_creation_lnx_file_and_directory_discovery
set -u

command -v find >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no find"; exit 0; }

d="$HOME/sigmaemul-findperm"
mkdir -p "$d" 2>/dev/null || true
find "$d" -perm -4000 >/dev/null 2>&1 || true

exit 0
