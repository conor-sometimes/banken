#!/usr/bin/env bash
# sigmahq_susp_container_residence_discovery.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: check whether they are inside a container by reading
# procfs (T1083), e.g. `cat /proc/self/cgroup` or `cat /proc/1/sched`. The rule
# keys on a reading tool (cat/grep/head/...) whose command line contains '/proc/'
# and ends with '/cgroup' or '/sched'. Harmless analogue: `cat /proc/self/cgroup`
# - an ordinary read of the caller's own cgroup line. The execve of /cat with a
# '/proc/.../cgroup' argument, which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_container_residence_discovery.yml - ATT&CK T1083
# Expected rule: proc_creation_lnx_susp_container_residence_discovery
set -u

cat /proc/self/cgroup >/dev/null 2>&1 || true

exit 0
