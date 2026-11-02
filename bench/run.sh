#!/usr/bin/env bash
# run.sh drives the banken benchmark suite (docs/design/benchmarking.md) and
# writes one raw-JSON file per category under bench/results/, plus a combined
# all.json. It is the published script the README numbers come from -- run it
# the same way the ATT&CK loop is run, and keep the JSON it produces.
#
#   nix develop ~/wbdev#banken --command bash -lc 'bench/run.sh fast'
#
# Targets:
#   fast   (default)  the benches that run on any box in seconds-to-minutes:
#                     detection latency (t3..t5), rule scaling, rule load,
#                     throughput, fork-exec baseline, cold start, footprint.
#   idle N            sample a running banken daemon's RSS+CPU for N seconds
#                     (the 24h soak is this with N=86400, run by the manager).
#   kernelbuild       CPU+RSS of a kernel build with vs without banken (heavy).
#   heavy             print what the matrix harness (tests/bench.nix) runs after
#                     a rebuild and is NOT run here.
#
# PLATFORM= labels the matrix row (distro name); empty is a direct host run. The
# -platform flag is on every subcommand so one Run JSON per distro lines up as
# one row per platform, the method the spec asks for.
set -euo pipefail

cd "$(dirname "$0")/.."
PLATFORM="${PLATFORM:-}"
OUTDIR="${OUTDIR:-bench/results}"
RULES="${RULES:-./rules}"
ITERS="${ITERS:-20000}"
mkdir -p "$OUTDIR"

BB="$(mktemp -d)/banken-bench"
BIN="$(mktemp -d)/banken"
go build -o "$BB" ./bench/cmd/banken-bench
go build -ldflags="-s -w" -o "$BIN" .

plat=(); [ -n "$PLATFORM" ] && plat=(-platform "$PLATFORM")

fast() {
  echo "banken-bench: fast suite -> $OUTDIR (platform='${PLATFORM:-direct}')"
  "$BB" latency    -rules "$RULES" -iters "$ITERS" "${plat[@]}" -out "$OUTDIR/latency.json"
  "$BB" rulescale  -rules "$RULES" -iters "$ITERS" "${plat[@]}" -out "$OUTDIR/rulescale.json"
  "$BB" ruleload   -rules "$RULES" -iters 25       "${plat[@]}" -out "$OUTDIR/ruleload.json"
  "$BB" throughput -rules "$RULES" -duration 2s    "${plat[@]}" -out "$OUTDIR/throughput.json"
  local true_bin; true_bin="$(type -P true)"
  "$BB" forkexec   -n 3000 -cmd "$true_bin"        "${plat[@]}" -out "$OUTDIR/forkexec.json"
  "$BB" coldstart  -bin "$BIN" -rules "$RULES" -reps 12 "${plat[@]}" -out "$OUTDIR/coldstart.json"
  footprint
  echo "done. raw JSON in $OUTDIR"
}

footprint() {
  # cargo-deny's Go counterpart: near-free from `go list`. Modules under audit,
  # third-party packages actually linked into the production binary (test-only
  # deps like rapid do not count), and their total source bytes.
  local modules pkgs srcbytes tpfile
  modules="$(go list -m all | tail -n +2 | wc -l | tr -d ' ')"
  tpfile="$(mktemp)"
  go list -deps -f '{{.Standard}} {{.Dir}} {{.ImportPath}}' ./ \
    | awk '$1=="false" && $3 !~ /conor-sometimes\/banken/ {print $2}' | sort -u > "$tpfile"
  pkgs="$(wc -l < "$tpfile" | tr -d ' ')"
  srcbytes=0
  while read -r d; do
    for f in "$d"/*.go; do
      [ -f "$f" ] || continue
      case "$f" in *_test.go) continue;; esac
      srcbytes=$((srcbytes + $(wc -c < "$f")))
    done
  done < "$tpfile"
  rm -f "$tpfile"
  "$BB" footprint -bin "$BIN" -modules "$modules" -thirdparty-packages "$pkgs" \
    -source-bytes "$srcbytes" "${plat[@]}" -out "$OUTDIR/footprint.json"
}

idle() {
  local secs="${1:-8}"
  # The spec's idle CPU+RSS. Run banken the way a deployment does (the systemd
  # timer, or --watch against the LIVE mimi stream), not --watch against a
  # static file: that busy-polls and is not an idle measurement. The manager
  # runs this at N=86400 on a quiet pinned VM for the 24h number.
  echo "idle: start banken under the systemd timer / live sensor, then:"
  echo "  $BB sample -pid <bankend-pid> -duration ${secs}s -interval 1s ${plat[*]} -out $OUTDIR/idle.json"
}

heavy() {
  cat <<'EOF'
Harness-ready, pending a scheduled run by the manager (tests/bench.nix, after the rebuild):
  - detection latency t1 (sensor capture) + t2 (transport): live mimi sensor, capture_ns -> receive
  - resource cost idle 24h: `run.sh idle 86400` against the real daemon on a quiet pinned VM
  - resource cost under a kernel build, with vs without banken (and mimi)
  - backpressure: events/sec before the ring buffer drops, burst clear time, under a fork bomb
  - sensor overhead attached: fork-exec us/exec WITH the mimi probe minus the forkexec baseline
  - startup: boot-to-first-finding after reboot; backlog replay after an hour stopped
  - detection quality: false positives/host/day by rule on a benign workload; per-rule eval cost
  - competitor comparison: auditd+ausearch / Falco / Wazuh / osquery on the same events
Every one is wired (a banken-bench subcommand or a tests/bench.nix step); only the long window,
the reboot, the live sensor or the competitor install is pending.
EOF
}

case "${1:-fast}" in
  fast) fast ;;
  idle) idle "${2:-8}" ;;
  kernelbuild) echo "kernelbuild: heavy; run inside tests/bench.nix on a quiet VM"; heavy ;;
  heavy) heavy ;;
  *) echo "usage: run.sh [fast|idle N|kernelbuild|heavy]" >&2; exit 2 ;;
esac
