#!/usr/bin/env bash
# sigmahq_mkfifo.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: create a named pipe (FIFO) to wire together the two
# halves of a reverse shell or a C2 relay (T1059). Harmless analogue: make a
# FIFO under the user's own home; nothing ever reads or writes it. The FIFO
# lives in $HOME (not /tmp) so only the generic mkfifo rule fires, not the
# /tmp-location variant. These sigmahq_ scripts run only under the throwaway
# tests/sigmahq-emul.nix VM, so they skip `rm` cleanup (which would itself fire
# proc_creation_lnx_file_deletion) and let the VM teardown collect the file.
#
# Imitates (SigmaHQ): proc_creation_lnx_mkfifo_named_pipe_creation.yml - ATT&CK T1059
# Expected rule: proc_creation_lnx_mkfifo_named_pipe_creation
set -u

command -v mkfifo >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no mkfifo"; exit 0; }

mkfifo "$HOME/.sigmaemul_fifo" >/dev/null 2>&1 || true

exit 0
