#!/usr/bin/env bash
# johncrack.sh - benign emulation of a password-cracking tool running, for detection-rule testing.
#
# What an attacker does: run an offline cracker (john, hashcat) or an online brute-forcer (hydra,
# medusa, ncrack, patator) against captured hashes or a service login (T1110). This does the harmless
# analogue: it invokes whichever cracker is present with `--version` only - the tool runs (the Image
# the rule keys on) but cracks nothing and contacts no host. The rule ships optional (it fires
# constantly on a pentest box); see ./README.md.
#
# Imitates: rules/optional/password_cracker.yml - ATT&CK T1110 Brute Force
# Expected rules: password_cracker
set -u

# --- TTP: a password cracker runs (any invocation) -> password_cracker (tool: Image match) ---
for tool in john hashcat hydra medusa ncrack patator; do
	if command -v "$tool" >/dev/null 2>&1; then
		timeout 5 "$tool" --version >/dev/null 2>&1 || true
		break
	fi
done

exit 0
