#!/usr/bin/env bash
# sigmahq_services_stop.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: stop or disable defensive/system services (T1489 /
# T1562.001) via `systemctl stop|disable <svc>`. Harmless analogue: `systemctl
# stop` a nonexistent '-emul-dummy' unit as an unprivileged user - it is a no-op
# (unit not loaded / denied). The execve of /systemctl with ' stop ', which the
# rule keys on, is real; the '-emul-dummy' name matches none of the rule's legit
# snapd/ssh-preinstall/ubuntu-upgrade filters.
#
# Imitates (SigmaHQ): proc_creation_lnx_services_stop_and_disable.yml - ATT&CK T1489
# Expected rule: proc_creation_lnx_services_stop_and_disable
set -u

command -v systemctl >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no systemctl"; exit 0; }

systemctl stop banken-emul-dummy.service >/dev/null 2>&1 || true

exit 0
