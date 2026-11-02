#!/usr/bin/env bash
# aidefense.sh - benign emulation of an agent impairing autonomous defenses, for rule testing.
#
# What an attacker does: drive a hijacked AI agent to take down the host's defensive tooling so its
# later actions go unseen - stop the EDR, kill osquery, truncate auditd's config. This does the
# harmless analogue: it targets NONEXISTENT `-emul-dummy` unit/process names that look like defense
# tools, so systemctl/pkill find nothing to act on - the stop/kill *attempt* in the argv (naming a
# defense tool) is the signal, and nothing real is stopped. Fires only when run as an AGENT account
# (User in claude/redteam/lab); proven by the engine golden/replay tests, since the VM runs as
# alice. Never names "banken" (that is tamper_banken's job). See ./README.md.
#
# Imitates: rules/agent/agent_impair_autonomous_defenses.yml - ATT&CK T1685.007 (v20)
# Expected rules: agent_impair_autonomous_defenses
set -u

# --- TTP: stop an EDR service -> agent_impair_autonomous_defenses (stop_verb + defense_target) ---
if command -v systemctl >/dev/null 2>&1; then
	systemctl stop clamav-emul-dummy.service >/dev/null 2>&1 || true
fi

# --- TTP: kill a security agent by name -> agent_impair_autonomous_defenses ---
if command -v pkill >/dev/null 2>&1; then
	pkill osqueryd-emul-dummy >/dev/null 2>&1 || true
fi

exit 0
