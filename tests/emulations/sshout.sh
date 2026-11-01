#!/usr/bin/env bash
# sshout.sh - benign emulation of an agent account running SSH outbound, for detection-rule testing.
#
# What an attacker does: a coding agent talks to its forge over HTTPS through the proxy and has no host
# to SSH to, so an ssh/scp/sftp exec is lateral movement or exfil (T1021.004). This does the harmless
# analogue: it runs ssh to an UNROUTABLE TEST-NET host in batch mode with a short connect timeout, so
# it never connects - the ssh exec is the signal. agent_ssh_access catches reading SSH files; this
# catches running SSH. See ./README.md.
#
# Account-scoped: rules/agent/agent_ssh_outbound.yml keys on User in {claude,redteam,lab}.
#
# Imitates: rules/agent/agent_ssh_outbound.yml - ATT&CK T1021.004 Remote Services: SSH
# Expected rules: agent_ssh_outbound
set -u

# 192.0.2.5 is TEST-NET-1 (RFC 5737): unroutable; ssh times out with no peer.
# --- TTP: run ssh outbound -> agent_ssh_outbound (ssh_exec) ---
if command -v ssh >/dev/null 2>&1; then
	timeout 5 ssh -o ConnectTimeout=2 -o BatchMode=yes -o StrictHostKeyChecking=no deploy@192.0.2.5 whoami >/dev/null 2>&1 || true
fi

exit 0
