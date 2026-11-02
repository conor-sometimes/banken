#!/usr/bin/env bash
# sigmahq_history_delete.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: delete shell history to cover tracks (T1070.003), e.g.
# `rm ~/.bash_history`. Harmless analogue: rm a dummy '*.bash_history' scratch
# file we create in the user's own home - our own throwaway file. The rule keys
# on /rm whose command line contains a '*_history'/'.bash_history' path.
# (file_deletion is background-allowed by the harness.)
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_history_delete.yml - ATT&CK T1070.003
# Expected rule: proc_creation_lnx_susp_history_delete
set -u

command -v rm >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no rm"; exit 0; }

f="$HOME/.sigmaemul.bash_history"
: > "$f" 2>/dev/null || true
rm -f "$f" >/dev/null 2>&1 || true

exit 0
