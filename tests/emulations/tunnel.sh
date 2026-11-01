#!/usr/bin/env bash
# tunnel.sh - benign emulation of a tunnelling / relay tool, for detection-rule testing.
#
# What an attacker does: punch an inbound path through NAT/firewall with ngrok, cloudflared, frp,
# chisel, a VSCode tunnel, or an SSH port-forward (-L/-R/-D/-W), to reach a host the egress controls
# were meant to contain (T1572). This does the harmless analogue: it runs a named tunnel tool with
# `--version` if present, else an SSH local-forward to an UNROUTABLE TEST-NET host in batch mode with a
# short timeout (it never connects) - the tool/forward exec is the signal. reverse_shell covers the
# shell-back-out; this covers the tunnels. See ./README.md.
#
# Imitates: rules/command-and-control/tunnel_tool.yml - ATT&CK T1572 Protocol Tunneling
# Expected rules: tunnel_tool
set -u

# --- TTP: a named tunnel/relay tool runs -> tunnel_tool (tools: Image match) ---
done_one=0
for tool in cloudflared ngrok frpc chisel gost bore; do
	if command -v "$tool" >/dev/null 2>&1; then
		timeout 3 "$tool" --version >/dev/null 2>&1 || true
		done_one=1
		break
	fi
done

# --- TTP: SSH local port-forward (a tunnel) -> tunnel_tool (ssh_forward) ---
# 192.0.2.6 is TEST-NET-1 (RFC 5737): unroutable; ssh times out and no tunnel is established.
if [ "$done_one" -eq 0 ] && command -v ssh >/dev/null 2>&1; then
	timeout 5 ssh -o ConnectTimeout=2 -o BatchMode=yes -o StrictHostKeyChecking=no -L 8080:localhost:80 -N relay@192.0.2.6 >/dev/null 2>&1 || true
fi

exit 0
