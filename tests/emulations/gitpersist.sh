#!/usr/bin/env bash
# gitpersist.sh - benign emulation of an agent setting a code-executing git config, for detection-rule testing.
#
# What an attacker does: set a git config key that runs a command on an ordinary git op
# (core.hooksPath / core.sshCommand / core.pager), captures credentials (credential.helper), or a
# `!`-shell alias - persistence that fires on the human's next pull, off the agent's account entirely.
# This does the harmless analogue: it writes the SAME config key to a SCRATCH config file
# (git config --file), never the real ~/.gitconfig or a live repo; the config argv is the signal.
# See ./README.md.
#
# Account-scoped: rules/agent/agent_git_config_persistence.yml keys on User in {claude,redteam,lab}.
#
# Imitates: rules/agent/agent_git_config_persistence.yml - ATT&CK T1546 / T1574
# Expected rules: agent_git_config_persistence
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

command -v git >/dev/null 2>&1 || exit 0

# --- TTP: set core.hooksPath (runs code on any git op) in a scratch config -> agent_git_config_persistence (git_cfg) ---
git config --file "$work/gitconfig" core.hooksPath "$work/.evil-hooks" >/dev/null 2>&1 || true

exit 0
