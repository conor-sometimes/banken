#!/usr/bin/env bash
# sigmahq_sensitive_file.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: read or edit a sensitive system file (login config,
# cron, hosts, sudoers) with an editor/stream tool (T1565.001 adjacent, data
# manipulation / recon of sensitive files). Harmless analogue: `sed` prints the
# first line of /etc/hosts to the bitbucket. Read-only; /etc/hosts is world
# readable and nothing is written.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_sensitive_file_access.yml - ATT&CK T1565.001
# Expected rule: proc_creation_lnx_susp_sensitive_file_access
set -u

command -v sed >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no sed"; exit 0; }

sed -n '1p' /etc/hosts >/dev/null 2>&1 || true

exit 0
