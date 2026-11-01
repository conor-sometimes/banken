#!/usr/bin/env bash
# newuser.sh - benign emulation of local account creation, for detection-rule testing.
#
# What an attacker does: add a local account as a durable backdoor / second identity to pivot through
# - useradd, adduser, newusers, pw useradd (T1136.001). This does the harmless analogue: it runs
# useradd ONLY when UNPRIVILEGED, where it lacks permission to write /etc/passwd and so fails WITHOUT
# creating any account - the useradd exec is the signal. It never runs as root, where it WOULD
# actually create the account (safety contract); this mirrors tamper.sh's unprivileged-only pattern.
# See ./README.md.
#
# Imitates: rules/persistence/account_creation.yml - ATT&CK T1136.001 Local Account
# Expected rules: account_creation
set -u

# Never run as root: useradd would actually create the account. Unprivileged, it fails cleanly and
# the only effect is the exec the rule catches.
if [ "$(id -u)" -eq 0 ]; then
	exit 0
fi

# --- TTP: useradd a dummy account (fails unprivileged, creates nothing) -> account_creation (create) ---
if command -v useradd >/dev/null 2>&1; then
	useradd -M -r banken-emul-dummy >/dev/null 2>&1 || true
elif command -v adduser >/dev/null 2>&1; then
	adduser --system --no-create-home banken-emul-dummy >/dev/null 2>&1 || true
fi

exit 0
