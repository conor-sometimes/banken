#!/usr/bin/env bash
# sigmahq_proxy_connection.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: route tooling through a proxy to mask C2 (T1090) by
# setting http_proxy=/https_proxy= on a command, e.g.
# `http_proxy=http://evil:8080 curl ...`. The rule keys on any command line
# containing 'http_proxy=' or 'https_proxy='. Harmless analogue: `env
# http_proxy=<unroutable TEST-NET-1 addr> true` - env sets the variable and runs
# `true`, which makes no network use at all, so the (unroutable) proxy is never
# contacted. The execve carrying 'http_proxy=', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_proxy_connection.yml - ATT&CK T1090
# Expected rule: proc_creation_lnx_proxy_connection
set -u

# 192.0.2.0/24 is TEST-NET-1 (RFC 5737), guaranteed unroutable; `true` ignores it.
env http_proxy=http://192.0.2.1:3128 true >/dev/null 2>&1 || true

exit 0
