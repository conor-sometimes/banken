#!/usr/bin/env bash
# appasswd.sh - benign emulation of an agent reading an application-specific password store.
#
# What an attacker does: drive a hijacked AI agent to lift an application-specific password (ASP)
# stored on the host - a mail client's saved credentials, a .authinfo, a .netrc machine entry - so a
# stolen ASP can reuse the account while bypassing interactive MFA. This does the harmless analogue:
# it plants DUMMY ASP stores in a scratch dir and `cat`s them (reading, not exfiltrating); the files
# hold fake creds and are removed on exit. The read of an ASP store path is the signal. Fires only
# when run as an AGENT account (User in claude/redteam/lab); proven by the engine golden/replay tests,
# since the VM runs as alice. See ./README.md.
#
# Imitates: rules/agent/agent_steal_app_password.yml - ATT&CK T1697 (v20, host-observable slice)
# Expected rules: agent_steal_app_password
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

# Plant DUMMY application-specific password stores (fake creds).
printf 'account bot\nhost smtp.example.invalid\nuser bot@example.invalid\npassword DUMMYapppassword\n' > "$work/.msmtprc"
printf 'machine imap.example.invalid login bot@example.invalid password DUMMYapppassword\n' > "$work/.authinfo"
printf 'machine example.invalid login bot password DUMMYnetrc\n' > "$work/.netrc"

# --- TTP: read the ASP stores -> agent_steal_app_password (reader + asp_path) ---
if command -v cat >/dev/null 2>&1; then
	cat "$work/.msmtprc" >/dev/null 2>&1 || true
	cat "$work/.authinfo" >/dev/null 2>&1 || true
	cat "$work/.netrc"    >/dev/null 2>&1 || true
fi

exit 0
