#!/usr/bin/env bash
# sigmahq_pnscan.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: TeamTNT's pnscan sends/receives raw binary probes across
# the network (T1046) with a '-W'/'-R' flag followed by hex byte pairs, e.g.
# `pnscan -W '16 03 01' ...`. The rule has NO Image constraint - it keys purely on
# that command-line regex ( -(W|R) then a quote/space then 2-20 hex pairs then a
# quote/space ). Reproducing that exact command line IS the faithful emulation,
# and pnscan itself is not in nixpkgs. Harmless analogue: pass the matching token
# as a single argument to the stock `true` binary, which ignores its args and
# exits 0. The execve carrying the '-W'/hex pattern the rule keys on is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_pnscan_binary_cli_pattern.yml - ATT&CK T1046
# Expected rule: proc_creation_lnx_pnscan_binary_cli_pattern
set -u

tb="$(type -P true)"
[ -n "$tb" ] || { echo "BANKEN-EMUL-SKIP: no true binary on PATH"; exit 0; }

# Run the real binary (not the shell builtin) so an execve is emitted. The single
# argv token (embedded quotes kept) matches -(W|R)('hex pairs').
"$tb" "-W'de ad be ef'" >/dev/null 2>&1 || true

exit 0
