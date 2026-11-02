#!/usr/bin/env bash
# sigmahq_cron_tmp.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: install a crontab from a payload dropped in /tmp for
# scheduled-task persistence (T1053.003), e.g. `crontab /tmp/payload`. Harmless
# analogue: `crontab /tmp/<nonexistent>` - the file does not exist so crontab
# errors out and installs nothing, but the execve of /crontab with a '/tmp/'
# path, which the rule keys on, is real. No ' -l' / ' -r', so it does not cross
# into the crontab_enumeration / crontab_removal rules.
#
# Imitates (SigmaHQ): proc_creation_lnx_schedule_task_job_cron.yml - ATT&CK T1053.003
# Expected rule: proc_creation_lnx_schedule_task_job_cron
set -u

command -v crontab >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no crontab"; exit 0; }

crontab /tmp/banken-emul-nonexistent.cron >/dev/null 2>&1 || true

exit 0
