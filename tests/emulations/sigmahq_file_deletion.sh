#!/usr/bin/env bash
# sigmahq_file_deletion.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: remove files to destroy evidence or artifacts
# (T1070.004 File Deletion). Harmless analogue: create a scratch file in the
# user's own home and `rm` it. Only that private scratch file is touched; no log
# or system file (its path is under $HOME, so the /var/log clear-logs variants
# do not apply).
#
# Imitates (SigmaHQ): proc_creation_lnx_file_deletion.yml - ATT&CK T1070.004
# Expected rule: proc_creation_lnx_file_deletion
set -u

command -v rm >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no rm"; exit 0; }

f="$HOME/.sigmaemul_del"
: > "$f" 2>/dev/null || true
rm -f "$f" >/dev/null 2>&1 || true

exit 0
