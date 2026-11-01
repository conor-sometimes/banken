#!/usr/bin/env bash
# trap.sh - benign emulation of a shell trap armed for persistence, for detection-rule testing.
#
# What an attacker does: arm a shell trap to re-run a command on a signal or on exit - `trap "<cmd>"
# EXIT` - a foothold that fires inside any shell they get (T1546.005). This does the harmless analogue:
# it arms a trap bound to the no-op `true` in a throwaway `bash -c`, so nothing of consequence runs;
# the trap argv is the signal. A bare `trap` that only lists/clears handlers is NOT matched. See
# ./README.md.
#
# Imitates: rules/persistence/trap_persistence.yml - ATT&CK T1546.005 Event Triggered Execution: Trap
# Expected rules: trap_persistence
set -u

# --- TTP: arm a trap bound to a command on EXIT -> trap_persistence (trap) ---
bash -c 'trap "true" EXIT; true' >/dev/null 2>&1 || true

exit 0
