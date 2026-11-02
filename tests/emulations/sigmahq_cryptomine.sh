#!/usr/bin/env bash
# sigmahq_cryptomine.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: launch a Monero/XMRig-style miner with its tell-tale
# pool and tuning flags (T1496 Resource Hijacking). Harmless analogue: pass
# those exact flag strings as arguments to coreutils `true`, which ignores them
# and exits - no miner runs, no pool is contacted (pool host is .invalid). The
# rule keys on the command-line indicators, which are genuinely present in the
# EXECVE argv.
#
# Imitates (SigmaHQ): proc_creation_lnx_crypto_mining.yml - ATT&CK T1496
# Expected rule: proc_creation_lnx_crypto_mining
set -u

# type -P forces a PATH lookup (not the shell builtin), so this is a real exec
# whose argv carries the miner indicators.
truebin="$(type -P true || true)"
[ -n "$truebin" ] || { echo "BANKEN-EMUL-SKIP: no true binary on PATH"; exit 0; }

"$truebin" --donate-level=0 -o pool.sigmaemul.invalid:3333 --cpu-priority=5 >/dev/null 2>&1 || true

exit 0
