"""Atomic Red Team -> banken ATT&CK detection-coverage scorecard.

Two fidelities:

* DRY-RUN (this script, runs anywhere): parse each Linux atomic's command
  string, synthesise a process event from it, and ask `banken check` whether
  any rule fires. This tests banken's command-line / Image matching. It is a
  LOWER BOUND -- it cannot reproduce the real file (PATH) and network syscalls
  an atomic makes, so rules that key on TargetFilename or a live connection
  score lower here than they would against real telemetry.

* LIVE (run-live.sh, on a sandbox host with auditd): actually execute the
  atomics, let auditd capture the real behaviour, and run banken over the log.
  That is the faithful scorecard. See the README.

Both answer: of the ATT&CK techniques Atomic Red Team exercises on Linux, how
many does banken detect?

Run:  uv run attackrange.py <atomic-red-team>/atomics  [path/to/banken]
"""

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import yaml

# Commands that wrap the real one; skip to the wrapped binary for the Image.
WRAPPERS = {"sudo", "env", "nohup", "timeout", "doas", "setsid", "eval", "exec"}


def substitute(cmd, args):
    """Replace ART #{arg} placeholders with their declared defaults."""
    for name, spec in (args or {}).items():
        default = "" if spec is None else str(spec.get("default", ""))
        cmd = cmd.replace("#{" + name + "}", default)
    return cmd


def event_from_line(line):
    """Best-effort process event from one shell command line."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        toks = shlex.split(line)
    except ValueError:
        toks = line.split()
    if not toks:
        return None
    i = 0
    while i < len(toks) - 1 and os.path.basename(toks[i]) in WRAPPERS:
        i += 1
    cmd = toks[i]
    image = cmd if cmd.startswith("/") else "/" + os.path.basename(cmd)
    ev = {"image": image, "commandLine": line}
    # first absolute-path argument -> a best-effort TargetFilename, so
    # file-access rules have something to match in the dry run.
    for t in toks[i + 1:]:
        if t.startswith("/") and len(t) > 1:
            ev["targetFilename"] = t
            break
    return ev


def banken_detects(banken, event):
    out = subprocess.run(
        [banken, "check", "-json", json.dumps(event)],
        capture_output=True, text=True, timeout=30,
    )
    return "matched" in out.stdout and "no rules matched" not in out.stdout


def emit_atomics(atomics):
    """Print one NDJSON {technique,name,command,cleanup} per Linux bash/sh
    atomic, for the live runner (run-live.sh) to execute in a sandbox."""
    for yml in sorted(atomics.rglob("T*/T*.yaml")):
        try:
            doc = yaml.safe_load(yml.read_text())
        except Exception:
            continue
        tid = doc.get("attack_technique")
        for t in doc.get("atomic_tests", []):
            if "linux" not in (t.get("supported_platforms") or []):
                continue
            ex = t.get("executor", {}) or {}
            if ex.get("name") not in ("bash", "sh"):
                continue
            print(json.dumps({
                "technique": tid,
                "name": t.get("name", ""),
                "command": substitute(ex.get("command", ""), t.get("input_arguments")),
                "cleanup": substitute(ex.get("cleanup_command", ""), t.get("input_arguments")),
            }))


def main():
    args = [a for a in sys.argv[1:] if a != "--emit"]
    if len(args) < 1:
        sys.exit("usage: attackrange.py <atomics-dir> [banken] [--emit]")
    atomics = Path(args[0])
    if "--emit" in sys.argv:
        emit_atomics(atomics)
        return
    banken = args[1] if len(args) > 1 else "banken"

    techniques = 0
    detected = set()
    tested = set()
    for yml in sorted(atomics.rglob("T*/T*.yaml")):
        try:
            doc = yaml.safe_load(yml.read_text())
        except Exception:
            continue
        tid = doc.get("attack_technique")
        linux_tests = [
            t for t in doc.get("atomic_tests", [])
            if "linux" in (t.get("supported_platforms") or [])
            and (t.get("executor", {}) or {}).get("name") in ("bash", "sh")
        ]
        if not linux_tests:
            continue
        techniques += 1
        tested.add(tid)
        for t in linux_tests:
            cmd = substitute(t["executor"].get("command", ""), t.get("input_arguments"))
            for line in cmd.splitlines():
                ev = event_from_line(line)
                if ev and banken_detects(banken, ev):
                    detected.add(tid)
                    break
            if tid in detected:
                break

    print(f"Atomic Red Team Linux techniques with a runnable bash/sh atomic: {techniques}")
    print(f"banken DRY-RUN detection: {len(detected)}/{techniques} techniques "
          f"({100*len(detected)/techniques:.0f}%)")
    print("  (lower bound: command-line match only; live-sandbox run scores higher)")
    missed = sorted(tested - detected)
    print(f"\ndetected ({len(detected)}): {', '.join(sorted(detected))}")
    print(f"\nnot detected in dry-run ({len(missed)}) -- a mix of real gaps and "
          f"file/network behaviours the dry run can't synthesise:")
    print("  " + ", ".join(missed))


if __name__ == "__main__":
    main()
