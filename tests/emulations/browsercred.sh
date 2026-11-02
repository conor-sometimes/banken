#!/usr/bin/env bash
# browsercred.sh - benign emulation of browser credential-store theft, for detection-rule testing.
#
# What an attacker does: read a browser's saved-password and cookie stores to harvest credentials
# and sessions - cat/sqlite3 over Firefox logins.json / Chrome "Login Data", or a dumper like
# LaZagne (T1555.003); the same files are enumerated for bookmarks/history (T1217). This does the
# harmless analogue: it makes DUMMY store files under a scratch `.mozilla/firefox` profile (removed
# on exit) and cats one; the store filename/profile path in argv is the signal. See ./README.md.
#
# Imitates: rules/credential-access/browser_credential_access.yml - ATT&CK T1555.003 / T1217
# Expected rules: browser_credential_access
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
mkdir -p "$work/.mozilla/firefox/abcd.default" >/dev/null 2>&1 || true
printf '{"logins":[]}\n' > "$work/.mozilla/firefox/abcd.default/logins.json"

# --- TTP: read the Firefox saved-password store -> browser_credential_access (reader + browser_store) ---
cat "$work/.mozilla/firefox/abcd.default/logins.json" >/dev/null 2>&1 || true

exit 0
