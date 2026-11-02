#!/usr/bin/env bash
# sigmahq_nohup.sh - benign emulation that trips a SigmaHQ Linux rule, for the
# tests/sigmahq-emul.nix harness (proves banken detects the UPSTREAM SigmaHQ
# ruleset, not just banken's own rules). See ../emulations/README.md for the
# safety contract; this file holds to it (no secrets, no exfil, no persistence).
#
# What an attacker does: detach a payload from the controlling terminal so it
# survives logout (T1564.001-adjacent evasion). Harmless analogue: nohup a
# no-op. The abuse SHAPE (a process launched under nohup) is real; the process
# is `true`, which does nothing.
#
# Imitates (SigmaHQ): proc_creation_lnx_nohup.yml - ATT&CK T1564
# Expected rule: proc_creation_lnx_nohup
set -u

command -v nohup >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no nohup"; exit 0; }

nohup true >/dev/null 2>&1 || true

exit 0
