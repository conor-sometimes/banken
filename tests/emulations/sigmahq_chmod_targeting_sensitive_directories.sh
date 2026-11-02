#!/usr/bin/env bash
# sigmahq_chmod_targeting_sensitive_directories.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: chmod files under sensitive directories (/tmp/, /etc/,
# /opt/, ...) to weaken permissions (T1222.002). The rule keys on /chmod whose
# command line references one of those directories (minus a few packaging-tool
# false positives). Harmless analogue: create a throwaway file in /tmp owned by
# the unprivileged user and `chmod 600` it - touches nothing sensitive. The
# execve of /chmod with '/tmp/', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_chmod_targeting_sensitive_directories.yml - ATT&CK T1222.002
# Expected rule: proc_creation_lnx_chmod_targeting_sensitive_directories
set -u

f="/tmp/bk-chmod-target.$$"
: > "$f" 2>/dev/null || true
chmod 600 "$f" >/dev/null 2>&1 || true
rm -f "$f" 2>/dev/null || true

exit 0
