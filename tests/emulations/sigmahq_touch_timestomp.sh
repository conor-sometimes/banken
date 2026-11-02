#!/usr/bin/env bash
# sigmahq_touch_timestomp.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: backdate a dropped systemd unit with `touch -t` so it
# blends in with the OS files around it (T1070.006 Timestomp). Harmless
# analogue: touch -t a scratch ".service" file in the user's own home; it is a
# private file that no systemd ever reads.
#
# Imitates (SigmaHQ): proc_creation_lnx_touch_susp.yml - ATT&CK T1070.006
# Expected rule: proc_creation_lnx_touch_susp
set -u

command -v touch >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no touch"; exit 0; }

touch -t 202601010000 "$HOME/.sigmaemul.service" >/dev/null 2>&1 || true

exit 0
