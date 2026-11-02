#!/usr/bin/env bash
# sigmahq_history_recon.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: read a user's shell history to mine for secrets or
# commands (T1552.003), e.g. `cat ~/.bash_history`. Harmless analogue: cat a
# dummy .bash_history we create in the user's own home - our own throwaway file,
# not anyone's real history. The rule keys on /cat with a '*_history' path.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_history_recon.yml - ATT&CK T1552.003
# Expected rule: proc_creation_lnx_susp_history_recon
set -u

command -v cat >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no cat"; exit 0; }

f="$HOME/.bash_history"
[ -e "$f" ] || : > "$f" 2>/dev/null || true
cat "$f" >/dev/null 2>&1 || true

exit 0
