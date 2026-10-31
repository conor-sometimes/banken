#!/bin/sh
# Runs as root inside one throwaway distro VM (tests/distros/run.py), started by
# cloud-init from the seed ISO. Does what an operator following docs/deployment.md
# does -- auditd from the distro's own repos, banken's audit rules loaded the
# documented way, banken + the canonical portable unit (banken supports systemd hosts
# only: its security model is that unit's sandbox) -- then runs each benign
# emulation as an ordinary user and reports, over the serial console, which rules
# fired. Every report line starts with BANKEN-; run.py ignores everything else.
set -u
SEED=$(cd "$(dirname "$0")" && pwd)
T=/opt/banken-test
. "$SEED/distro.env" # NAME PM PROXY PKGS

say() { echo "$*" >/dev/ttyS0 2>/dev/null; echo "$*"; }
finish() { say "BANKEN-DONE"; sync; poweroff -f 2>/dev/null || poweroff; exit 0; }
fail() { say "BANKEN-ERROR $*"; finish; }

mkdir -p "$T" && cp -r "$SEED/payload/." "$T/" || fail "copy payload"
say "BANKEN-INFO os=$(. /etc/os-release && echo "$PRETTY_NAME" | tr ' ' '_') kernel=$(uname -r)"

# --- the distro's package manager, through the host's proxy when there is one ---
if [ -n "$PROXY" ]; then
	export http_proxy="$PROXY" https_proxy="$PROXY" HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY"
	case $PM in
	apt) printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "%s";\n' "$PROXY" "$PROXY" >/etc/apt/apt.conf.d/99banken-proxy ;;
	dnf)
		echo "proxy=$PROXY" >>/etc/dnf/dnf.conf
		# Pin repos to the vendor's own host: a mirror list hands out third-party
		# mirrors a proxy allow-list cannot name in advance.
		for r in /etc/yum.repos.d/*.repo; do
			sed -i -e 's/^\(mirrorlist\|metalink\)=/#&/' -e 's/^#\s*baseurl=/baseurl=/' \
				-e 's#download\.example/pub/fedora/linux#dl.fedoraproject.org/pub/fedora/linux#' "$r"
		done ;;
	zypper)
		printf 'PROXY_ENABLED="yes"\nHTTP_PROXY="%s"\nHTTPS_PROXY="%s"\n' "$PROXY" "$PROXY" >/etc/sysconfig/proxy
		sed -i 's#download\.opensuse\.org#downloadcontent.opensuse.org#g' /etc/zypp/repos.d/*.repo ;;
	esac
fi

need=""
for pair in $PKGS; do
	command -v "${pair%%:*}" >/dev/null 2>&1 || need="$need ${pair#*:}"
done
if [ -n "$need" ]; then
	say "BANKEN-INFO installing:$need"
	case $PM in
	dnf) dnf -y install $need ;;
	apt) apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y $need ;;
	zypper) zypper -n --gpg-auto-import-keys in $need ;;
	pacman) pacman -Sy --noconfirm --needed $need ;;
	esac >/var/log/banken-install.log 2>&1 || fail "package install failed:$need ($(tail -3 /var/log/banken-install.log | tr '\n' '|'))"
fi

# --- audit: banken's rules, loaded the documented way ---
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/banken.rules <<'EOF'
-a always,exit -F arch=b64 -S execve,execveat -k banken-exec
-a always,exit -F arch=b32 -S execve -k banken-exec
-w /etc/shadow -p rwa -k banken-watch
-w /etc/gshadow -p rwa -k banken-watch
EOF
systemctl enable --now auditd >/dev/null 2>&1 || service auditd start >/dev/null 2>&1
if command -v augenrules >/dev/null 2>&1; then augenrules --load >/dev/null 2>&1; else auditctl -R /etc/audit/rules.d/banken.rules >/dev/null 2>&1; fi
auditctl -e 1 >/dev/null 2>&1
rules=$(auditctl -l 2>/dev/null)
say "BANKEN-INFO audit_rules=$(echo "$rules" | grep -c .) banken_rules=$(echo "$rules" | grep -c banken-) task_never=$(echo "$rules" | grep -c 'task,never') status=$(auditctl -s 2>/dev/null | grep -E '^enabled' | tr ' ' '=')"
echo "$rules" | grep -q banken-exec || fail "banken's audit rules are not loaded"

# --- banken: binary, config, and the canonical portable unit ---
install -m0755 "$T/banken" /usr/bin/banken || fail "install banken"
mkdir -p /etc/banken
cat >/etc/banken/banken.yml <<'EOF'
statePath: /var/lib/banken/cursor.json
sources:
  - {type: auditd, path: /var/log/audit/audit.log}
alerts:
  journal: {enable: true}
  jsonl: {enable: true, dir: /var/log/banken, retentionDays: 30, format: ocsf}
EOF
say "BANKEN-INFO banken=$(/usr/bin/banken -version 2>&1 | tr ' ' '_')"

direct() { /usr/bin/banken -config /etc/banken/banken.yml >/dev/null 2>&1; }
scan=direct
install -m0644 "$T/banken.service" /etc/systemd/system/banken.service && systemctl daemon-reload
if systemctl start banken.service; then
	scan="systemctl start banken.service"
	say "BANKEN-UNIT ok"
else
	# A finding in its own right: report it, then keep collecting detection
	# results by running banken directly so one problem cannot hide the rest.
	say "BANKEN-UNIT fail $(journalctl -u banken.service -n 6 --no-pager -o cat 2>/dev/null | tr '\n' '|' | tr ' ' '_')"
fi
$scan # drain: setup's own events are not judged

# --- the emulations, as an ordinary user (runuser: su/sudo would fire a rule) ---
id alice >/dev/null 2>&1 || useradd -m alice
alerts() { cat /var/log/banken/alerts-*.jsonl 2>/dev/null; }
for script in "$T"/emulations/*.sh; do
	family=$(basename "$script" .sh)
	before=$(alerts | wc -l)
	runuser -u alice -- bash "$script" >/dev/null 2>&1
	sleep 1 # let auditd write the family's records
	$scan
	fired=$(alerts | tail -n +"$((before + 1))" | grep -o '"analytic":{[^}]*}' | grep -o '"name":"[^"]*"' |
		cut -d'"' -f4 | sort -u | tr '\n' ',')
	say "BANKEN-RESULT $family ${fired%,}"
done
finish
