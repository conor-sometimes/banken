#!/usr/bin/env bash
# credsearch.sh - benign emulation of a credential-file search (the hunt before the read), for detection-rule testing.
#
# What an attacker does freshly landed: find the disk for credential filenames, or grep -r for
# password/secret/key material, to learn which files are worth reading. This does the harmless
# analogue: it runs the SAME find / grep but scoped to its own scratch dir (not /), so the search exec
# is the signal and nothing on the real disk is read. credential_file_read catches reading one known
# file; this catches the discovery hunt that precedes it. See ./README.md.
#
# Imitates: rules/credential-access/credential_search.yml - ATT&CK T1552.001 Credentials in Files (search)
# Expected rules: credential_search
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
mkdir -p "$work/home/.aws"
printf 'not a real secret\n' > "$work/home/.aws/credentials"

# --- TTP: find by a credential filename -> credential_search (find_cmd + find_creds) ---
find "$work" -name '.aws/credentials' -type f >/dev/null 2>&1 || true

# --- TTP: recursive grep for a secret keyword -> credential_search (grep_cmd + grep_recursive + grep_secret) ---
grep -ri password "$work" >/dev/null 2>&1 || true

exit 0
