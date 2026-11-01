#!/usr/bin/env bash
# killfw.sh - benign emulation of disabling / flushing the host firewall, for detection-rule testing.
#
# What an attacker does with a foothold: drop the firewall to open inbound access and clear the egress
# controls that contain an implant - ufw disable, iptables -F / -P ... ACCEPT, nft flush ruleset
# (T1562.004). This does the harmless analogue: it runs the SAME commands ONLY when UNPRIVILEGED,
# where they lack CAP_NET_ADMIN and so fail WITHOUT changing a single rule - the disable/flush exec is
# the signal. It never runs as root, where it WOULD actually take the firewall down (safety contract);
# this mirrors tamper.sh's unprivileged-only `auditctl -D`. See ./README.md.
#
# Imitates: rules/defense-evasion/disable_firewall.yml - ATT&CK T1562.004 Disable or Modify System Firewall
# Expected rules: disable_firewall
set -u

# Never run these as root: unlike a scratch-only emulation, these commands act on the live host
# firewall, so the only safe way to generate the exec is unprivileged, where the kernel refuses them.
if [ "$(id -u)" -eq 0 ]; then
	exit 0
fi

# --- TTP: iptables flush -> disable_firewall (iptables) ---
if command -v iptables >/dev/null 2>&1; then
	iptables -F >/dev/null 2>&1 || true
fi

# --- TTP: ufw disable -> disable_firewall (ufw) ---
if command -v ufw >/dev/null 2>&1; then
	ufw disable >/dev/null 2>&1 || true
fi

# --- TTP: nft flush ruleset -> disable_firewall (nft_flush) ---
if command -v nft >/dev/null 2>&1; then
	nft flush ruleset >/dev/null 2>&1 || true
fi

exit 0
