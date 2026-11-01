#!/usr/bin/env bash
# portscan.sh - benign emulation of a network service scan, for detection-rule testing.
#
# What an attacker does: sweep a host or network for open ports to find what to pivot to - nmap,
# masscan, zmap, rustscan, naabu, unicornscan, or nc -z zero-I/O mode (T1046). This does the harmless
# analogue: it invokes whichever scanner is present with `--version` only, so the scanner runs (the
# Image the rule keys on) but sweeps nothing and contacts no host. (The nc -z form is deliberately
# NOT used here - it would also trip the optional netcat rule; it is exercised by the replay fixture
# instead.) See ./README.md.
#
# Imitates: rules/discovery/network_service_scan.yml - ATT&CK T1046 Network Service Discovery
# Expected rules: network_service_scan
set -u

# --- TTP: a port/service scanner runs (any invocation) -> network_service_scan (scanner: Image match) ---
found=0
for tool in nmap masscan zmap rustscan naabu unicornscan; do
	if command -v "$tool" >/dev/null 2>&1; then
		timeout 5 "$tool" --version >/dev/null 2>&1 || true
		found=1
		break
	fi
done

# No scanner installable on this image (e.g. a distro with no nmap in its default repos): tell the
# matrix harness to skip rather than record a miss - the rule is still proven by the replay fixture.
[ "$found" = 0 ] && echo "BANKEN-EMUL-SKIP: no port scanner (nmap/masscan/zmap/rustscan/naabu) available"

exit 0
