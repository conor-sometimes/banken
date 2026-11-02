#!/usr/bin/env bash
# sigmahq_security_tools_disabling.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: disable host defenses by stopping the firewall or an EDR
# service (T1562/T1686), e.g. `systemctl stop firewalld`. The rule keys on
# service/systemctl/chkconfig stopping or disabling a named defense (firewalld,
# cbdaemon, falcon-sensor, iptables, ...). Harmless analogue: `systemctl stop
# firewalld.service` on a host where firewalld is not a unit - systemctl reports
# "not loaded" and stops nothing, but the execve of /systemctl with 'firewalld'
# and 'stop', which the rule keys on, is real. services_stop_and_disable (any
# systemctl stop/disable) genuinely fires alongside - a legit twin.
#
# Imitates (SigmaHQ): proc_creation_lnx_security_tools_disabling.yml - ATT&CK T1562.004
# Expected rules: proc_creation_lnx_security_tools_disabling,
#                 proc_creation_lnx_services_stop_and_disable
set -u

command -v systemctl >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no systemctl"; exit 0; }

systemctl --no-ask-password stop firewalld.service >/dev/null 2>&1 || true

exit 0
