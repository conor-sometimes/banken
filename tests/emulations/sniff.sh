#!/usr/bin/env bash
# sniff.sh - benign emulation of network packet capture, for detection-rule testing.
#
# What an attacker does: capture traffic to harvest credentials and data in transit - tcpdump,
# tshark/dumpcap, ngrep, netsniff-ng (T1040). This does the harmless analogue: it invokes whichever
# sniffer is present with `--version` only, so the tool runs (the Image the rule keys on) but captures
# no packets and reads no interface. See ./README.md.
#
# Imitates: rules/discovery/network_sniffing.yml - ATT&CK T1040 Network Sniffing
# Expected rules: network_sniffing
set -u

# --- TTP: a packet sniffer runs (any invocation) -> network_sniffing (sniffer: Image match) ---
for tool in tcpdump tshark dumpcap ngrep netsniff-ng; do
	if command -v "$tool" >/dev/null 2>&1; then
		timeout 5 "$tool" --version >/dev/null 2>&1 || true
		break
	fi
done

exit 0
