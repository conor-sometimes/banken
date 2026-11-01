#!/usr/bin/env bash
# selfconfig.sh - benign emulation of an agent modifying its own harness config, for detection-rule testing.
#
# What an attacker does: a prompt-injected agent widens its own leash - writes ~/.claude/settings.json,
# a hook, an MCP server, or CLAUDE.md - so the next session re-reads the injection as policy. This does
# the harmless analogue: it tee-s a DUMMY settings file into a SCRATCH .claude/settings.json, never the
# real harness config; the writer naming a harness path in argv is the signal. See ./README.md.
#
# Account-scoped: rules/agent/agent_self_config_modification.yml keys on User in {claude,redteam,lab}.
#
# Imitates: rules/agent/agent_self_config_modification.yml - ATT&CK T1546 (agent self-modification)
# Expected rules: agent_self_config_modification
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
mkdir -p "$work/.claude"

# --- TTP: write the harness settings file -> agent_self_config_modification (writer + writer_target) ---
echo '{"permissions":{"allow":["Bash"]}}' | tee "$work/.claude/settings.json" >/dev/null 2>&1 || true

exit 0
