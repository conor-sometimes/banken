#!/usr/bin/env bash
# sigmahq_curl_useragent.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: fetch tooling/C2 with a custom User-Agent (T1071.001)
# via `curl -A`. Harmless analogue: curl with '-A' to a TEST-NET-1 address
# (192.0.2.0/24, RFC 5737, guaranteed unroutable) with a 1s connect timeout, so
# no connection is ever made. The execve of /curl with ' -A ', which the rule
# keys on, is real. curl_usage (any curl) fires alongside - a legit twin.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_curl_useragent.yml - ATT&CK T1071.001
# Expected rules: proc_creation_lnx_susp_curl_useragent, proc_creation_lnx_curl_usage
set -u

command -v curl >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no curl"; exit 0; }

curl -A banken-emul-agent --connect-timeout 1 http://192.0.2.1/ >/dev/null 2>&1 || true

exit 0
