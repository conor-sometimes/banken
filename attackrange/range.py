"""Live ATT&CK range: run Atomic Red Team's Linux atomics for real and score
which ones banken detects. Runs INSIDE the throwaway VM of
tests/attackrange.nix, as root, and nowhere else.

For each atomic (from `attackrange.py --emit`): restore audit if an earlier
atomic broke it, scan once to drain the log, run the atomic and its cleanup
(own process group, timeout), scan again, and record the rules that fired.
Results: results.ndjson (one line per atomic), scorecard.json and
scorecard.md (per technique), then a `done` marker the test waits on.

It is Python, not bash, on purpose: several atomics pkill or kill shells by
name, and a bash runner would kill itself.

Usage: range.py <atomics.ndjson> <banken> <audit.rules> <outdir>
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SANDBOX_MARKER = "/run/banken-range-sandbox"
AUDIT_LOG = "/var/log/audit/audit.log"
TIMEOUT = 30  # seconds per command and per cleanup

# Atomics that would end the range rather than test detection: they take the
# VM (and the test driver inside it) down. Each is skipped and reported as
# skipped in the scorecard, never silently dropped. Reviewed against every
# command of the pinned ART commit (tests/attackrange.nix).
SKIP_TECHNIQUES = {
    "T1529",  # System Shutdown/Reboot: every atomic shuts down or reboots
}
SKIP = {
    "Delete Filesystem - Linux",  # T1070.004: rm -rf / --no-preserve-root
    # T1489: sysrq 'e' sends SIGTERM to every process, the test driver included
    "Abuse of linux magic system request key for Send a SIGTERM to all processes",
    "Reboot Linux Host via Kernel System Request",  # T1685: sysrq 'b'
}


def quiet(*cmd):
    return subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False)


def restore_audit(rules):
    """Undo what an earlier atomic may have done to the audit pipeline."""
    if quiet("systemctl", "is-active", "--quiet", "auditd").returncode != 0 or not os.path.exists(AUDIT_LOG):
        quiet("systemctl", "restart", "auditd")
        time.sleep(1)
    quiet("auditctl", "-e", "1")
    listed = subprocess.run(["auditctl", "-l"], capture_output=True, text=True, check=False).stdout
    if "banken-exec" not in listed:
        quiet("auditctl", "-R", rules)


def run_group(cmd, cwd):
    """bash -c cmd in its own process group; on timeout kill the whole group."""
    p = subprocess.Popen(["bash", "-c", cmd], cwd=cwd, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    try:
        return p.wait(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
        return "timeout"


def scan(banken, state, dest):
    """One banken scan over the audit log since the cursor; native jsonl to dest."""
    shutil.rmtree(dest, ignore_errors=True)
    quiet(banken, "-state", state, "-source", "auditd:" + AUDIT_LOG, "-jsonl-dir", dest)
    rules = set()
    for f in Path(dest).glob("*.jsonl"):
        for line in f.read_text().splitlines():
            if line.strip():
                rules.add(json.loads(line)["rule"])
    return sorted(rules)


def main():
    atomics, banken, rules_file, out = sys.argv[1:5]
    if not os.path.exists(SANDBOX_MARKER):
        sys.exit(f"refusing: {SANDBOX_MARKER} absent -- this runs atomics for real, sandbox only")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    state = str(out / "cursor.json")
    results = []
    lines = Path(atomics).read_text().splitlines()
    with open(out / "results.ndjson", "w") as res:
        for i, line in enumerate(lines, 1):
            a = json.loads(line)
            rec = {"technique": a["technique"], "name": a["name"]}
            if a["technique"] in SKIP_TECHNIQUES or a["name"] in SKIP:
                rec["skipped"] = True
            else:
                restore_audit(rules_file)
                scan(banken, state, str(out / "drain"))
                work = tempfile.mkdtemp(prefix="art-")
                rec["exit"] = run_group(a["command"], work)
                if a.get("cleanup", "").strip():
                    run_group(a["cleanup"], work)
                shutil.rmtree(work, ignore_errors=True)
                time.sleep(1)  # let auditd flush the atomic's records
                rec["rules"] = scan(banken, state, str(out / "alerts"))
            results.append(rec)
            res.write(json.dumps(rec) + "\n")
            res.flush()
            (out / "progress").write_text(f"{i}/{len(lines)}\n")

    # Honest scoring: privilege_escalation_attempt fires on any sudo, and many
    # atomics run their command through sudo, so a hit on that rule alone says
    # the atomic used sudo, not that banken recognised the technique. It counts
    # "on merit" only for the privilege-escalation techniques themselves (T1548).
    def on_merit(r):
        rules = set(r.get("rules") or ())
        if r["technique"].startswith("T1548"):
            return bool(rules)
        return bool(rules - {"privilege_escalation_attempt"})

    by_tech = {}
    for r in results:
        t = by_tech.setdefault(r["technique"], {"atomics": 0, "detected": 0, "merit": 0, "skipped": 0, "rules": set()})
        t["atomics"] += 1
        if r.get("skipped"):
            t["skipped"] += 1
        elif r["rules"]:
            t["detected"] += 1
            t["merit"] += on_merit(r)
            t["rules"].update(r["rules"])
    run = {k: v for k, v in by_tech.items() if v["skipped"] < v["atomics"]}
    detected = sorted(k for k, v in run.items() if v["detected"])
    merit = sorted(k for k, v in run.items() if v["merit"])
    card = {
        "atomics": len(results),
        "atomics_detected": sum(1 for r in results if r.get("rules")),
        "atomics_on_merit": sum(1 for r in results if not r.get("skipped") and on_merit(r)),
        "techniques_on_merit": len(merit),
        "atomics_skipped": sum(1 for r in results if r.get("skipped")),
        "techniques": len(run),
        "techniques_detected": len(detected),
        "detected": {k: sorted(run[k]["rules"]) for k in detected},
        "missed": sorted(k for k in run if k not in detected),
    }
    (out / "scorecard.json").write_text(json.dumps(card, indent=2) + "\n")
    md = [
        "# banken live ATT&CK range",
        "",
        f"**{card['techniques_on_merit']}/{card['techniques']} techniques** detected on a rule about "
        f"the technique ({card['atomics_on_merit']}/{card['atomics'] - card['atomics_skipped']} atomics); "
        f"{card['techniques_detected']} counting hits that are only privilege_escalation_attempt firing "
        f"on the atomic's own sudo. {card['atomics_skipped']} atomics skipped as range-destroying.",
        "",
        "| Technique | Atomics on merit | Any rule | Rules |",
        "| --- | ---: | ---: | --- |",
    ]
    for k in sorted(run):
        v = run[k]
        n = v["atomics"] - v["skipped"]
        md.append(f"| {k} | {v['merit']}/{n} | {v['detected']}/{n} | {', '.join(sorted(v['rules'])) or '—'} |")
    (out / "scorecard.md").write_text("\n".join(md) + "\n")
    (out / "done").touch()


if __name__ == "__main__":
    main()
