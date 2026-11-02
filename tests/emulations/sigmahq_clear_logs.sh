#!/usr/bin/env bash
# sigmahq_clear_logs.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: wipe log files to destroy evidence (T1070.002), e.g.
# `rm /var/log/...`. Harmless analogue: build a scratch tree whose path contains
# the literal substring '/var/log' under the user's own home and rm a dummy file
# inside it. The rule keys on /rm whose command line contains '/var/log'; our
# path is $HOME/sigmaemul/var/log/... so no real system log is touched, and the
# command line does not match the rule's 'rm -f /var/log/sysstat/' legit filter.
# (file_deletion is background-allowed by the harness.)
#
# Imitates (SigmaHQ): proc_creation_lnx_clear_logs.yml - ATT&CK T1070.002
# Expected rule: proc_creation_lnx_clear_logs
set -u

command -v rm >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no rm"; exit 0; }

d="$HOME/sigmaemul/var/log"
mkdir -p "$d" 2>/dev/null || true
: > "$d/dummy" 2>/dev/null || true
rm -f "$d/dummy" >/dev/null 2>&1 || true

exit 0
