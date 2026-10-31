"""Live distro matrix: boot each distro's official cloud image under KVM, deploy
banken the way docs/deployment.md says, run the benign emulations against that
distro's own kernel and auditd, and check that exactly the expected rules fire.

Per distro (tests/distros/distros.json): fetch the image if it is not cached and
verify the vendor's published checksum; boot a throwaway copy-on-write overlay
(the base image is never written) with a cloud-init seed ISO carrying guest.sh,
banken, the portable unit and the emulations; read the BANKEN- lines guest.sh
writes to the serial console; compare each family's fired rules with the set its
fixtures name (tests/fixtures/<family>.expect-<rule>.json), as tests/vm.nix does
for NixOS. Prints a distro x family matrix; exit 1 on any mismatch or error.

Needs KVM, qemu-system-x86_64, qemu-img and xorriso. Standard library only.

  python3 tests/distros/run.py --banken path/to/static/banken [--only rocky-9 ...]
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
BOOT_TIMEOUT = 20 * 60  # seconds for one distro: boot, package installs, the families


def expected_rules():
    """family -> sorted expected rules, from the fixture names (one source of truth)."""
    want = {}
    for f in (REPO / "tests" / "fixtures").glob("*.expect-*.json"):
        family, rule = f.name[: -len(".json")].split(".expect-", 1)
        if rule != "none":
            want.setdefault(family, set()).add(rule)
    families = [p.stem for p in (REPO / "tests" / "emulations").glob("*.sh")]
    return {fam: sorted(want.get(fam, ())) for fam in families}


def fetch(distro, cache):
    """The verified image path, downloading it once. The checksum is the vendor's."""
    name = Path(urllib.parse.urlparse(distro["url"]).path).name
    path = cache / name
    algo = "sha512" if "sha512" in distro else "sha256"
    if not path.exists():
        part = path.with_suffix(path.suffix + ".part")
        print(f"[{distro['name']}] downloading {name}", flush=True)
        with urllib.request.urlopen(distro["url"], timeout=60) as r, open(part, "wb") as out:
            shutil.copyfileobj(r, out, 1 << 20)
        part.rename(path)
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    if h.hexdigest() != distro[algo]:
        raise RuntimeError(f"{name}: {algo} mismatch (got {h.hexdigest()})")
    return path


def guest_proxy():
    """The host's proxy as the guest sees it: QEMU's user network reaches the host's
    loopback at 10.0.2.2. Empty when the host has no proxy (e.g. CI)."""
    p = os.environ.get("https_proxy") or os.environ.get("http_proxy") or ""
    if not p:
        return ""
    u = urllib.parse.urlparse(p)
    host = "10.0.2.2" if u.hostname in ("127.0.0.1", "localhost", "::1") else u.hostname
    return f"{u.scheme}://{host}:{u.port or 3128}"


def seed_iso(distro, banken, workdir):
    """A NoCloud seed (label cidata): cloud-init config plus everything guest.sh needs."""
    root = workdir / "seed"
    payload = root / "payload"
    (payload / "emulations").mkdir(parents=True)
    for s in (REPO / "tests" / "emulations").glob("*.sh"):
        shutil.copy(s, payload / "emulations")
    shutil.copy(banken, payload / "banken")
    shutil.copy(REPO / "packaging" / "systemd" / "banken.service", payload / "banken.service")
    shutil.copy(HERE / "guest.sh", root / "guest.sh")
    pkgs = " ".join(f"{cmd}:{pkg}" for cmd, pkg in distro["packages"].items())
    (root / "distro.env").write_text(
        f"NAME={distro['name']}\nPM={distro['pm']}\n"
        f"PROXY={guest_proxy()}\nPKGS='{pkgs}'\n")
    (root / "meta-data").write_text(f"instance-id: banken-{distro['name']}\nlocal-hostname: banken-{distro['name']}\n")
    (root / "user-data").write_text(
        "#cloud-config\n"
        "runcmd:\n"
        "  - [sh, -c, 'mkdir -p /mnt/seed && (mount -o ro LABEL=cidata /mnt/seed || mount -o ro /dev/sr0 /mnt/seed)"
        " && sh /mnt/seed/guest.sh']\n")
    iso = workdir / "seed.iso"
    subprocess.run(["xorriso", "-as", "mkisofs", "-quiet", "-output", str(iso), "-volid", "cidata",
                    "-joliet", "-rock", str(root)], check=True)
    return iso


def run_distro(distro, banken, cache, keep):
    """Boot one distro and return its parsed BANKEN- report."""
    name = distro["name"]
    image = fetch(distro, cache)
    workdir = Path(tempfile.mkdtemp(prefix=f"banken-{name}-"))
    overlay = workdir / "overlay.qcow2"
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(image),
                    str(overlay), "20G"], check=True)
    iso = seed_iso(distro, banken, workdir)
    serial = workdir / "serial.log"
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", "2048", "-smp", "2",
        "-display", "none", "-monitor", "none", "-no-reboot",
        "-drive", f"file={overlay},if=virtio,format=qcow2",
        "-drive", f"file={iso},media=cdrom,readonly=on",
        "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
        "-serial", f"file:{serial}",
    ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    print(f"[{name}] booted (serial: {serial})", flush=True)
    report = {"name": name, "info": [], "results": {}, "errors": [], "unit": None, "done": False}
    deadline = time.time() + BOOT_TIMEOUT
    try:
        while time.time() < deadline:
            text = serial.read_text(errors="replace") if serial.exists() else ""
            if "BANKEN-DONE" in text or qemu.poll() is not None:
                break
            time.sleep(3)
        else:
            report["errors"].append(f"timeout after {BOOT_TIMEOUT}s")
    finally:
        if qemu.poll() is None:
            qemu.kill()
        qemu.wait()
    for line in serial.read_text(errors="replace").splitlines():
        m = re.search(r"BANKEN-(\w+) ?(.*)$", line.strip())
        if not m:
            continue
        kind, rest = m.groups()
        if kind == "RESULT":
            family, _, rules = rest.partition(" ")
            report["results"][family] = sorted(r for r in rules.split(",") if r)
        elif kind == "ERROR":
            report["errors"].append(rest)
        elif kind == "UNIT":
            report["unit"] = rest
        elif kind == "INFO":
            report["info"].append(rest)
        elif kind == "DONE":
            report["done"] = True
    if not report["done"] and not report["errors"]:
        report["errors"].append("guest never reported BANKEN-DONE (see serial log)")
    report["serial"] = str(serial)
    if not keep and report["done"] and not report["errors"]:
        shutil.rmtree(workdir, ignore_errors=True)
        report["serial"] = None
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--banken", required=True, help="static linux/amd64 banken binary")
    ap.add_argument("--only", nargs="*", help="distro names to run (default: all)")
    ap.add_argument("--cache", default=os.path.expanduser("~/.cache/banken-distros"), help="image cache")
    ap.add_argument("--jobs", type=int, default=3, help="distros booted in parallel")
    ap.add_argument("--keep", action="store_true", help="keep every work dir (serial logs), even on success")
    ap.add_argument("--json", help="also write the full report here")
    args = ap.parse_args()

    distros = json.loads((HERE / "distros.json").read_text())
    if args.only:
        unknown = set(args.only) - {d["name"] for d in distros}
        if unknown:
            sys.exit(f"unknown distro(s): {', '.join(sorted(unknown))}")
        distros = [d for d in distros if d["name"] in args.only]
    cache = Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)
    want = expected_rules()

    reports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run_distro, d, args.banken, cache, args.keep): d for d in distros}
        for fut in concurrent.futures.as_completed(futures):
            d = futures[fut]
            try:
                reports.append(fut.result())
            except Exception as e:  # one distro's failure must not hide the others
                reports.append({"name": d["name"], "errors": [str(e)], "results": {}, "info": [], "unit": None})
    reports.sort(key=lambda r: r["name"])

    failed = False
    families = sorted(want)
    print("\n" + "distro".ljust(20) + "unit".ljust(6) + "".join(f.ljust(12) for f in families))
    for r in reports:
        unit = "ok" if (r.get("unit") or "").startswith("ok") else "FAIL"
        row = r["name"].ljust(20) + unit.ljust(6)
        for f in families:
            got = r["results"].get(f)
            ok = got == want[f]
            row += ("ok" if ok else ("—" if got is None else "DIFF")).ljust(12)
            failed |= not ok
        print(row)
        failed |= bool(r["errors"]) or unit == "FAIL"
    print()
    for r in reports:
        for f in families:
            got = r["results"].get(f)
            if got is not None and got != want[f]:
                print(f"{r['name']} {f}: fired {got}, expected {want[f]}")
        for e in r["errors"]:
            print(f"{r['name']} ERROR: {e}")
        if r.get("unit") and not r["unit"].startswith("ok"):
            print(f"{r['name']} UNIT: {r['unit'][:400]}")
        if r.get("serial"):
            print(f"{r['name']} serial log: {r['serial']}")
    if args.json:
        Path(args.json).write_text(json.dumps({"expected": want, "reports": reports}, indent=2) + "\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
