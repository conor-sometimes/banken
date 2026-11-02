#!/usr/bin/env bash
# sigmahq_python_base64_encoded_execution.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: decode and run a base64 payload with python (T1027), e.g.
# `python3 -c 'import base64;exec(base64.b64decode("..."))'`. The rule keys on a
# python ` -c` whose command line carries 'import', 'base64' and a decode call
# (b64decode/.decode/...). Harmless analogue: `python3 -c` that b64decodes an
# EMPTY string and does nothing with the (empty) result - no exec, no payload.
# The execve of python with 'import', 'base64', ' -c' and 'b64decode', which the
# rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_python_base64_encoded_execution.yml - ATT&CK T1027
# Expected rule: proc_creation_lnx_python_base64_encoded_execution
set -u

command -v python3 >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no python3"; exit 0; }

python3 -c 'import base64; base64.b64decode(b"")' >/dev/null 2>&1 || true

exit 0
