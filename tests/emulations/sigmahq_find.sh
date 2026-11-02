#!/usr/bin/env bash
# sigmahq_find.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: walk the filesystem to locate files of interest
# (T1083 File and Directory Discovery). Harmless analogue: a shallow `find`
# under the user's own home for a name that does not exist. Read-only.
#
# Imitates (SigmaHQ): proc_creation_lnx_file_and_directory_discovery.yml - ATT&CK T1083
# Expected rule: proc_creation_lnx_file_and_directory_discovery
set -u

command -v find >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no find"; exit 0; }

find "$HOME" -maxdepth 1 -name '.sigmaemul_nope' >/dev/null 2>&1 || true

exit 0
