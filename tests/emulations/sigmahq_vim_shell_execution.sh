#!/usr/bin/env bash
# sigmahq_vim_shell_execution.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: break out to a shell from vim (GTFOBins T1059.004), e.g.
# `vim -c ':!/bin/sh'`. The rule keys on vim with ` -c`/` --cmd ` whose command
# line carries a shell-escape marker (':!/', ':shell', '/bin/sh', ...). Harmless
# analogue: `vim -es` (scripted ex mode, no UI) that only `:set shell=/bin/sh`
# then `:qa!` - the shell path appears as an option value, never spawned, and
# vim exits immediately. The execve of /vim with ` -c` and '/bin/sh', which the
# rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_vim_shell_execution.yml - ATT&CK T1059.004
# Expected rule: proc_creation_lnx_vim_shell_execution
set -u

command -v vim >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no vim"; exit 0; }

# -u NONE: no config. -es: silent ex mode, runs the -c commands and exits.
vim -u NONE -es -c ':set shell=/bin/sh' -c ':qa!' </dev/null >/dev/null 2>&1 || true

exit 0
