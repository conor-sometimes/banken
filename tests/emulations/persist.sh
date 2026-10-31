#!/usr/bin/env bash
# persist.sh — benign emulation of persistence establishment for detection-rule testing.
#
# What an attacker does: arrange to run again after a reboot — drop a systemd user unit, append to
# a shell rc, install a crontab. This does the harmless analogue: it writes the SAME kinds of files
# but ENTIRELY INSIDE its own mktemp scratch (a fake $HOME), never a real ~/.bashrc, never a real
# ~/.config/systemd/user, never the real crontab. Nothing survives the run. See ./README.md.
#
# Imitates: generic persistence (systemd user unit, shell rc edit)
# Expected rules: persistence
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

mkdir -p "$work/.config/systemd/user"

# --- TTP: write a systemd *user* unit to persist -> persistence (systemd_user_unit) ---
# cp a dummy unit into a (scratch) ~/.config/systemd/user path; the rule keys on that path in argv.
printf '[Unit]\nDescription=emul\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=default.target\n' > "$work/emul.service"
cp "$work/emul.service" "$work/.config/systemd/user/emul.service" 2>/dev/null || true

# --- TTP: append to a shell rc to persist -> persistence (shell_rc) ---
# tee into a (scratch) .bashrc; the rule keys on /.bashrc in a tee/cp/mv/install argv.
echo '# emul persistence marker (harmless)' | tee "$work/.bashrc" >/dev/null 2>&1 || true

exit 0
