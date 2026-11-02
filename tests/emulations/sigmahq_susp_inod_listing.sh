#!/usr/bin/env bash
# sigmahq_susp_inod_listing.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: list the root directory's inode to spot a container
# (inode number of / differs inside vs outside) (T1083), e.g. `ls -id /`. The
# rule keys on /ls listing ' /' with both an inode flag (-i) and a directory
# flag (-d). Harmless analogue: exactly `ls -id /` - prints the one inode number
# and name of /, reading nothing else. The execve of /ls with '-id /', which the
# rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_inod_listing.yml - ATT&CK T1083
# Expected rule: proc_creation_lnx_susp_inod_listing
set -u

ls -id / >/dev/null 2>&1 || true

exit 0
