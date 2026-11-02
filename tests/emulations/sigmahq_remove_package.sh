#!/usr/bin/env bash
# sigmahq_remove_package.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: remove a package (e.g. a security agent) for defense
# evasion (T1562.001), e.g. `dpkg --remove <pkg>`. Harmless analogue: `dpkg
# --remove banken-emul-dummy` as an unprivileged user - dpkg refuses (needs
# superuser / no such package) and removes nothing, but the execve of /dpkg
# with '--remove ', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_remove_package.yml - ATT&CK T1562.001
# Expected rule: proc_creation_lnx_remove_package
set -u

command -v dpkg >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no dpkg"; exit 0; }

dpkg --remove banken-emul-dummy >/dev/null 2>&1 || true

exit 0
