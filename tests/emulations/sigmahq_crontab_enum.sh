#!/usr/bin/env bash
# sigmahq_crontab_enum.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: list the current user's cron jobs while mapping
# persistence and scheduled execution (T1053.003 discovery). Harmless analogue:
# `crontab -l` for the unprivileged test user, which only reads (and usually
# reports "no crontab"); nothing is installed or changed.
#
# Imitates (SigmaHQ): proc_creation_lnx_crontab_enumeration.yml - ATT&CK T1053.003
# Expected rule: proc_creation_lnx_crontab_enumeration
set -u

command -v crontab >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no crontab"; exit 0; }

crontab -l >/dev/null 2>&1 || true

exit 0
