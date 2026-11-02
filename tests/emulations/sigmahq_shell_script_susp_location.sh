#!/usr/bin/env bash
# sigmahq_shell_script_susp_location.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: run a dropped script out of a suspicious directory such
# as /tmp via a shell (T1059), e.g. `bash -c /tmp/payload.sh`. The rule keys on a
# shell (/bash, /sh, ...) with ' -c ' and '/tmp/' on the command line. Harmless
# analogue: `bash -c true /tmp/bk-script` - the shell runs the stock `true`
# builtin (the '/tmp/...' word is only $0, no such script is opened or executed),
# but the execve of a shell with ' -c ' and '/tmp/', which the rule keys on, is
# real. The shell's Image is /bash (not under /tmp), so the tmp-exec rules do not
# fire.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_shell_script_exec_from_susp_location.yml - ATT&CK T1059
# Expected rule: proc_creation_lnx_susp_shell_script_exec_from_susp_location
set -u

command -v bash >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no bash"; exit 0; }

bash -c true /tmp/bk-script-$$ >/dev/null 2>&1 || true

exit 0
