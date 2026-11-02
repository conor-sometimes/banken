#!/usr/bin/env bash
# sigmahq_base64_decode.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: decode a base64 blob to unpack the next stage before it
# runs (T1140 Deobfuscate/Decode Files or Information). Harmless analogue:
# base64 -d a tiny constant ("hi"); the decoded bytes are discarded, never run.
#
# Imitates (SigmaHQ): proc_creation_lnx_base64_decode.yml - ATT&CK T1140
# Expected rule: proc_creation_lnx_base64_decode
set -u

command -v base64 >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no base64"; exit 0; }

echo "aGk=" | base64 -d >/dev/null 2>&1 || true

exit 0
