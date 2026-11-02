#!/usr/bin/env bash
# sigmahq_at.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: schedule a job with `at` so a payload runs later,
# detached from the session (T1053.002 Scheduled Task/Job: At). Harmless
# analogue: list the (empty) at queue with `at -l`. It schedules nothing and
# reads only this user's own spool - but the execve of `at`, which is all the
# rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_at_command.yml - ATT&CK T1053.002
# Expected rule: proc_creation_lnx_at_command
set -u

command -v at >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no at"; exit 0; }

at -l >/dev/null 2>&1 || true

exit 0
