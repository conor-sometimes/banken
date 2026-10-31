#!/usr/bin/env bash
# Live ATT&CK range -- run on a SANDBOX host with auditd (hokkaido), never a
# real machine: it actually executes Atomic Red Team's Linux atomics so auditd
# captures the real behaviour, then scores banken's detections per technique.
# This is the faithful counterpart to attackrange.py's dry run.
#
# SKELETON: the per-atomic execution + banken-scan wiring is finalised and
# tested on hokkaido (this Mac has no auditd). The flow is real; treat the
# marked steps as the checklist to complete there.
#
# Usage (on hokkaido, as a user that can sudo, in a throwaway VM/container):
#   ./run-live.sh /path/to/atomic-red-team/atomics /path/to/banken
set -euo pipefail

ATOMICS="${1:?usage: run-live.sh <atomics-dir> <banken>}"
BANKEN="${2:?usage: run-live.sh <atomics-dir> <banken>}"

# --- safety rail: refuse to run outside a sandbox -----------------------------
# Atomics execute real (benign, self-cleaning) commands; never on a real host.
if [ ! -e /run/banken-range-sandbox ]; then
    echo "refusing: create /run/banken-range-sandbox to confirm this is a throwaway sandbox" >&2
    exit 1
fi

# --- prerequisites (hokkaido) -------------------------------------------------
# 1. auditd running with execve + the file-watch rules banken expects:
#      auditctl -e 2
#      -a always,exit -F arch=b64 -S execve -k exec   (+ the credential-path watches)
# 2. a fresh banken state so each scan reads only new events.
STATE="$(mktemp)"
LOG=/var/log/audit/audit.log      # or the Laurel JSON log

scorecard=$(mktemp)

# Drive the parser in attackrange.py to enumerate (technique, command, cleanup)
# for each Linux bash/sh atomic, then for each:
#   a) record banken's cursor position,
#   b) run the command (benign) and its cleanup_command,
#   c) run one `banken` scan over the new audit events,
#   d) record which rules fired -> map to the technique.
#
# TODO(hokkaido): emit the atomics as NDJSON from attackrange.py (--emit) and
# loop here; for now the dry run (attackrange.py) is the Mac-side proof and this
# is run interactively while finalising the capture wiring.
uv run attackrange.py "$ATOMICS" "$BANKEN" --emit 2>/dev/null | while IFS= read -r atomic; do
    tid=$(jq -r .technique <<<"$atomic")
    cmd=$(jq -r .command  <<<"$atomic")
    cleanup=$(jq -r .cleanup <<<"$atomic")

    before=$("$BANKEN" -state "$STATE" -source "auditd:$LOG" 2>&1 | grep -c 'alert' || true)
    bash -c "$cmd"  || true          # benign atomic
    bash -c "$cleanup" >/dev/null 2>&1 || true
    fired=$("$BANKEN" -state "$STATE" -source "auditd:$LOG" -journal 2>&1 | grep 'banken\[' || true)
    [ -n "$fired" ] && echo "$tid detected" >>"$scorecard" || echo "$tid missed" >>"$scorecard"
done

echo "=== live scorecard ==="
sort -u "$scorecard" | awk '{c[$2]++} END{print c["detected"]+0" detected, "c["missed"]+0" missed"}'
rm -f "$STATE" "$scorecard"
