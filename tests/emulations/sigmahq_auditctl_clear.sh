#!/usr/bin/env bash
# sigmahq_auditctl_clear.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: delete all audit rules with `auditctl -D` to blind the
# host's logging before acting (T1562.006 Indicator Blocking). Harmless analogue:
# run `auditctl -D` as an unprivileged user: it is refused (needs
# CAP_AUDIT_CONTROL) so no rule is actually flushed - but the execve of auditctl
# carrying '-D', which is what the rule keys on, is real. (The same fail-safe
# approach as the repo's tamper.sh, which only runs auditctl -D unprivileged.)
#
# Imitates (SigmaHQ): proc_creation_lnx_auditctl_clear_rules.yml - ATT&CK T1562.006
# Expected rule: proc_creation_lnx_auditctl_clear_rules
set -u

command -v auditctl >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no auditctl"; exit 0; }

# Unprivileged only: as alice this is EPERM and flushes nothing.
auditctl -D >/dev/null 2>&1 || true

exit 0
