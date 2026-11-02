#!/usr/bin/env bash
# sudo_probe.sh - benign emulation of a privilege-escalation probe for detection-rule testing.
#
# What an attacker (or a compromised process) does: probe for a way up - run sudo/su/doas/pkexec to
# see what sticks. This does the harmless analogue: it runs sudo/doas in their NON-INTERACTIVE
# modes (`-n`), which make no change and simply succeed-or-fail immediately depending on existing
# policy. Either way it is the exec - the attempt - that the rule catches, exactly as designed.
# Nothing is escalated, nothing is modified. See ./README.md.
#
# Imitates: generic privilege-escalation probing (sudo/doas)
# Expected rules: privilege_escalation_attempt
set -u

# --- TTP: non-interactive sudo probe -> privilege_escalation_attempt ---
# `sudo -n true`: -n never prompts; with no passwordless rule it fails cleanly, with one it runs
# the no-op `true`. Harmless both ways; the /sudo exec is the signal.
sudo -n true >/dev/null 2>&1 || true

# --- TTP: doas probe, where present (BSD/!NixOS hosts) -> privilege_escalation_attempt ---
if command -v doas >/dev/null 2>&1; then
	doas -n true >/dev/null 2>&1 || true
fi

exit 0
