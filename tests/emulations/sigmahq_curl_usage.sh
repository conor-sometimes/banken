#!/usr/bin/env bash
# sigmahq_curl_usage.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: use curl to pull down tooling or a second stage, or to
# exfiltrate (T1105). This SigmaHQ rule is a broad "curl ran at all" signal.
# Harmless analogue: `curl --version` - it prints its version and makes no
# network connection. The execve of curl, which is all the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_curl_usage.yml - ATT&CK T1105
# Expected rule: proc_creation_lnx_curl_usage
set -u

command -v curl >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no curl"; exit 0; }

curl --version >/dev/null 2>&1 || true

exit 0
