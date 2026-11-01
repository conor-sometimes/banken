#!/usr/bin/env bash
# netcat.sh - benign emulation of a netcat/socat invocation, for detection-rule testing.
#
# What an attacker does: use nc/ncat/netcat/socat to move bytes over a raw socket - a bind/reverse
# shell, an ad-hoc transfer, a port probe or a relay (T1095). This does the harmless analogue: it runs
# nc as a connect probe to an UNROUTABLE TEST-NET address with a short timeout (the connection never
# establishes), so the nc exec - all this blanket, optional rule keys on - is the signal. revshell.sh
# and tunnel.sh cover the specific malicious shapes; this is the policy alert on the tool itself.
# See ./README.md.
#
# Imitates: rules/optional/netcat.yml - ATT&CK T1095 Non-Application Layer Protocol
# Expected rules: netcat
set -u

# 192.0.2.2 is TEST-NET-1 (RFC 5737): unroutable; the probe times out with no peer.
# --- TTP: netcat/socat runs (any invocation) -> netcat (tool: Image match) ---
if command -v nc >/dev/null 2>&1; then
	timeout 2 nc -z -w1 192.0.2.2 9 >/dev/null 2>&1 || true
elif command -v ncat >/dev/null 2>&1; then
	timeout 2 ncat -z -w1 192.0.2.2 9 >/dev/null 2>&1 || true
elif command -v socat >/dev/null 2>&1; then
	timeout 2 socat -T1 - TCP:192.0.2.2:9 </dev/null >/dev/null 2>&1 || true
fi

exit 0
