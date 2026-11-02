#!/usr/bin/env bash
# Test S (S1-S5), run in-guest as root on the distros packages.microsoft.com serves: the banken +
# Sysmon-for-Linux half of the matrix, done the REAL way. It adds Microsoft's package repo (apt for
# Ubuntu/Debian, the MS yum repo for the RHEL family), installs the genuine sysmonforlinux package,
# applies a minimal ProcessCreate config, runs real Sysmon, triggers a reverse-shell-shaped exec as
# the test user, and checks banken detects a reverse_shell off the SYSMON source (data_sources
# ["sysmon"]) -- the integration, proven per distro against Microsoft's own binary.
#
# It prints one "<id> PASS|FAIL <detail>" line per objective (distrocheck parses these into the
# report, mirroring mimicheck.sh). Where packages.microsoft.com ships no sysmonforlinux for this
# distro/version it prints a single "SYSMON-SKIP <reason>" line and exits 0: distrocheck records the
# skip in the report's Info (not a red check) and lists no S1-S5 objectives, exactly like an optional
# tool a distro's repos lack. distrocheck only invokes this on package managers it already gated to
# (apt, and dnf on the RHEL family); the in-script SKIP covers a repo a specific version still lacks.
#
# Args: <pm> <distro> <testuser>. The proxy and apt/dnf proxy config are already set by distrocheck.
set -uo pipefail
PM=${1:?pm}
DISTRO=${2:?distro}
TESTUSER=${3:-alice}
log() { echo "$1 $2 ${3:-}"; }
skip() {
	echo "SYSMON-SKIP $1"
	exit 0
}
notreached() { for id in "$@"; do log "$id" FAIL "not reached: $REASON"; done; }

# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null || true

# --- repo: add Microsoft's package source for this distro ---
case "$PM" in
apt)
	url="https://packages.microsoft.com/config/${ID:-ubuntu}/${VERSION_ID:-24.04}/packages-microsoft-prod.deb"
	if ! curl -fsSL "$url" -o /tmp/packages-microsoft-prod.deb 2>/tmp/sysmon-repo.log; then
		skip "no MS apt repo for ${ID:-?}/${VERSION_ID:-?} ($(tail -1 /tmp/sysmon-repo.log 2>/dev/null))"
	fi
	if ! dpkg -i /tmp/packages-microsoft-prod.deb >/tmp/sysmon-repo.log 2>&1; then
		skip "packages-microsoft-prod install failed ($(tail -1 /tmp/sysmon-repo.log 2>/dev/null))"
	fi
	apt-get update >/tmp/sysmon-aptupdate.log 2>&1 || true
	;;
dnf)
	rel=${VERSION_ID%%.*}
	url="https://packages.microsoft.com/config/rhel/${rel:-9}/prod.repo"
	if ! curl -fsSL "$url" -o /etc/yum.repos.d/microsoft-prod.repo 2>/tmp/sysmon-repo.log; then
		skip "no MS yum repo for rhel/${rel:-?} ($(tail -1 /tmp/sysmon-repo.log 2>/dev/null))"
	fi
	;;
*)
	skip "packages.microsoft.com ships no sysmonforlinux for $PM ($DISTRO)"
	;;
esac

# --- S1: install the genuine sysmonforlinux package from the MS repo ---
case "$PM" in
apt) apt-get install -y sysmonforlinux >/tmp/sysmon-install.log 2>&1 ;;
dnf) dnf install -y --setopt='*.skip_if_unavailable=1' sysmonforlinux >/tmp/sysmon-install.log 2>&1 ;;
esac
if command -v sysmon >/dev/null 2>&1; then
	log S1 PASS "sysmonforlinux installed ($(command -v sysmon))"
else
	skip "sysmonforlinux not installable here ($(tail -2 /tmp/sysmon-install.log 2>/dev/null | tr '\n' ' '))"
fi

# --- S2: apply a minimal ProcessCreate config and run real Sysmon ---
# onmatch="exclude" with no excludes => log every ProcessCreate (EventID 1): the smallest config that
# captures the reverse-shell exec. Sysmon loads its eBPF probe off this kernel's BTF, like mimi.
cat >/etc/banken-sysmon.xml <<'EOF'
<Sysmon schemaversion="4.81">
  <EventFiltering>
    <ProcessCreate onmatch="exclude"/>
  </EventFiltering>
</Sysmon>
EOF
sysmon -accepteula -i /etc/banken-sysmon.xml >/tmp/sysmon-start.log 2>&1 || true
active=""
for _ in $(seq 1 40); do
	if systemctl is-active --quiet sysmon 2>/dev/null; then active=1; break; fi
	sleep 0.25
done
if [ -n "$active" ]; then
	log S2 PASS "sysmon running with a ProcessCreate config"
else
	REASON="sysmon did not start ($(tail -2 /tmp/sysmon-start.log 2>/dev/null | tr '\n' ' '))"
	log S2 FAIL "$REASON"
	notreached S3 S4 S5
	exit 0
fi

# --- S3: banken --watch following the sysmon source ---
# Sysmon writes its XML via syslog; journald captures it under identifier "sysmon" on every systemd
# distro (the parser's documented bridge path, main.go isStreamSource). A tiny journalctl bridge
# appends those entries to a file banken tails -- the same shape module.nix's services.banken.sysmon
# uses, and the battle-tested single file path (cursor, inotify follow) does the reading.
mkdir -p /var/log/banken-sysmon /var/log/bsysmon /etc/banken
: >/var/log/banken-sysmon/sysmon.log
journalctl -o cat -t sysmon -f --no-pager >>/var/log/banken-sysmon/sysmon.log 2>/dev/null &
JPID=$!
printf 'sources:\n  - {type: sysmon, path: /var/log/banken-sysmon/sysmon.log}\nalerts:\n  jsonl: {enable: true, dir: /var/log/bsysmon, format: ocsf}\n' >/etc/banken/sysmon.yml
banken --watch -config /etc/banken/sysmon.yml -state /tmp/bsysmon.state >/var/log/bsysmon.err 2>&1 &
BPID=$!
sleep 1
if kill -0 "$BPID" 2>/dev/null; then
	log S3 PASS "banken --watch following the sysmon source"
else
	REASON="banken --watch did not start ($(tail -2 /var/log/bsysmon.err 2>/dev/null | tr '\n' ' '))"
	log S3 FAIL "$REASON"
	notreached S4 S5
	kill "$JPID" 2>/dev/null
	exit 0
fi

# --- S4: a reverse-shell-shaped exec as the test user, captured by Sysmon ---
# 192.0.2.30 is TEST-NET-1 (RFC5737), unroutable; the connect times out, but the exec -- the attempt,
# the classic bash /dev/tcp one-liner -- is what Sysmon's ProcessCreate records. A unique port ties
# the Sysmon record (and the alert) back to this exec.
PORT=47431
runuser -u "$TESTUSER" -- bash -c "timeout 2 bash -c 'exec 3<>/dev/tcp/192.0.2.30/$PORT' >/dev/null 2>&1 || true"
captured=""
for _ in $(seq 1 80); do
	if grep -q "/dev/tcp/192.0.2.30/$PORT" /var/log/banken-sysmon/sysmon.log 2>/dev/null; then captured=1; break; fi
	sleep 0.25
done
if [ -n "$captured" ]; then
	log S4 PASS "sysmon captured the reverse-shell exec (/dev/tcp)"
else
	log S4 FAIL "sysmon did not capture the exec (bridge tail: $(tail -1 /var/log/banken-sysmon/sysmon.log 2>/dev/null))"
fi

# --- S5: banken detects reverse_shell off the SYSMON source, data_sources ["sysmon"] ---
hit=""
for _ in $(seq 1 120); do
	hit=$(grep -h '"data_sources":\["sysmon"\]' /var/log/bsysmon/*.jsonl 2>/dev/null | grep reverse_shell | head -1)
	[ -n "$hit" ] && break
	sleep 0.25
done
if [ -n "$hit" ]; then
	log S5 PASS "reverse_shell detected off sysmon, data_sources=[sysmon]"
else
	log S5 FAIL "no sysmon-sourced reverse_shell ($(tail -1 /var/log/bsysmon.err 2>/dev/null))"
fi

kill "$JPID" "$BPID" 2>/dev/null
exit 0
