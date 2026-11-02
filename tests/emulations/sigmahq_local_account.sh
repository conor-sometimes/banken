#!/usr/bin/env bash
# sigmahq_local_account.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: enumerate local accounts (T1087.001), e.g. by running
# `id`, reading /etc/passwd, or `lsof -u`. Harmless analogue: run `id` with no
# arguments - it just prints the current user's own uid/gid. The execve of /id,
# which is all the rule keys on (selection_4), is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_local_account.yml - ATT&CK T1087.001
# Expected rule: proc_creation_lnx_local_account
set -u

command -v id >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no id"; exit 0; }

id >/dev/null 2>&1 || true

exit 0
