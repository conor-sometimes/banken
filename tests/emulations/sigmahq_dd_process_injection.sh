#!/usr/bin/env bash
# sigmahq_dd_process_injection.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: inject code into a running process by overwriting its
# memory map with dd (T1055.009), e.g. `dd if=payload of=/proc/<pid>/mem seek=...`.
# The rule keys on /dd whose command line contains 'of=', '/proc/' and '/mem'
# together. Harmless analogue: aim dd at '/proc/0/mem' - pid 0 is never a real
# process, so dd fails to open the target (ENOENT) and writes nothing; input is
# /dev/null so there is no payload. The execve of /dd with 'of=', '/proc/' and
# '/mem', which the rule keys on, is real. (This rule matches any dd by basename,
# unlike dd_file_overwrite which needs an exact /bin/dd path - so it fires on the
# NixOS store-path dd.)
#
# Imitates (SigmaHQ): proc_creation_lnx_dd_process_injection.yml - ATT&CK T1055.009
# Expected rule: proc_creation_lnx_dd_process_injection
set -u

command -v dd >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no dd"; exit 0; }

dd if=/dev/null of=/proc/0/mem count=0 >/dev/null 2>&1 || true

exit 0
