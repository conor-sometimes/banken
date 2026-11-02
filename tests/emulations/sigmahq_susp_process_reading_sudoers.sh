#!/usr/bin/env bash
# sigmahq_susp_process_reading_sudoers.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: read the sudoers policy to find escalation paths
# (T1033/T1548.003), e.g. `cat /etc/sudoers`. The rule keys on a file-reading
# tool (cat/less/grep/head/...) whose command line carries ' /etc/sudoers'.
# Harmless analogue: `cat /etc/sudoers` as the unprivileged user - the file is
# mode 0440 root, so the read is denied and nothing is disclosed, but the execve
# of /cat with ' /etc/sudoers', which the rule keys on, is real.
#
# A cat of /etc/sudoers also trips proc_creation_lnx_local_account (its rule
# keys on a file reader whose command line carries /etc/passwd|shadow|sudoers) -
# a legitimate twin detection of the same read.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_process_reading_sudoers.yml - ATT&CK T1033
# Expected rules: proc_creation_lnx_susp_process_reading_sudoers, proc_creation_lnx_local_account
set -u

cat /etc/sudoers >/dev/null 2>&1 || true

exit 0
