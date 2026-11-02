#!/usr/bin/env bash
# sigmahq_crontab_removal.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: wipe a user's crontab with `crontab -r` to remove a
# defender's scheduled job or to cover persistence tracks (T1053.003). Harmless
# analogue: `crontab -r` for the current (unprivileged) user, who has no crontab:
# it removes nothing ("no crontab for ...") and touches only this user's own
# spool - but the execve of crontab carrying ' -r', which is what the rule keys
# on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_crontab_removal.yml
# Expected rule: proc_creation_lnx_crontab_removal
set -u

command -v crontab >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no crontab"; exit 0; }

crontab -r >/dev/null 2>&1 || true

exit 0
