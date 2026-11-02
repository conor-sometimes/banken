#!/usr/bin/env bash
# sigmahq_base64_shebang_cli.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: pass a base64-encoded shell script on a command line
# (T1027), where the encoding of a '#!/bin/...' shebang produces a fixed prefix
# such as 'IyEvYmluL2Jhc2' (base64 of '#!/bin/bash'). The rule keys on any
# command line containing one of those shebang-prefix tokens. Harmless analogue:
# run a harmless tool (cat) with that literal token as a (nonexistent) filename
# argument - nothing is decoded or executed, cat just fails to open the "file".
# The execve whose command line carries 'IyEvYmluL2Jhc2', which the rule keys
# on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_base64_shebang_cli.yml - ATT&CK T1027
# Expected rule: proc_creation_lnx_base64_shebang_cli
set -u

# 'IyEvYmluL2Jhc2' is the base64 prefix of '#!/bin/bash'; here only a filename.
cat IyEvYmluL2Jhc2hX >/dev/null 2>&1 || true

exit 0
