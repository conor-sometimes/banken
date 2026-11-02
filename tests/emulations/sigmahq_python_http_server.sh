#!/usr/bin/env bash
# sigmahq_python_http_server.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: stand up an ad-hoc web server with Python's http.server
# to stage or exfiltrate files from a compromised host (T1105 / T1071). Harmless
# analogue: `python3 -m http.server --help` - argparse prints usage and exits
# without ever binding a port or serving anything. The execve of python carrying
# 'http.server', which is what the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_python_http_server_execution.yml
# Expected rule: proc_creation_lnx_python_http_server_execution
set -u

command -v python3 >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no python3"; exit 0; }

python3 -m http.server --help >/dev/null 2>&1 || true

exit 0
