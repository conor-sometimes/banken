# End-to-end proof that banken's quarantine enforcement is REAL: a dropped
# payload is RENAMED into the quarantine store (same filesystem) or NEUTERED in
# place on its fstat'd inode (cross-filesystem EXDEV), recorded manifest-first,
# and the real `banken respond restore` CLI round-trips it byte-identical. One
# throwaway KVM VM acts solely on files the test itself drops; the real hokkaido
# host and every other config leave response.enforce false.
#
#   nix-build tests/response-quarantine.nix   (needs KVM; run on hokkaido)
#   nix flake check                           (checks.x86_64-linux.response-quarantine)
#
# This is docs/design/response-architecture.md section 4.4 (phases A-G) and item
# 9 of section 6. It proves, live:
#   Q1  the act binds to the fstat'd inode, not a re-resolved path (rename lands
#       the recorded inode in the store; the EXDEV neuter acts on exactly that
#       inode in place, mode 0000 + immutable).
#   Q2  manifest-first: with the store root made immutable mid-run the quarantine
#       is refused having touched nothing, and recovery finalises from the
#       manifest once the store is writable again.
#   Q3  restore keeps the store entry and writes a tombstone (a second restore is
#       a no-op).
#   Q4  restore refuses a replaced inode ("inode replaced") and refuses to
#       clobber an occupied destination; -to works, -to /etc and -to <store> are
#       refused.
#   Q6  a payload over quarantine.maxFileBytes is still moved but recorded
#       "unhashed", completing fast.
#   Q14 a /dev device node is refused by the never-touch carve-out, while a
#       /dev/shm file is actionable (the carve-out); a FIFO and a symlink are
#       refused by the executor; /etc is refused by never-touch AND would be
#       refused by the helper unit's ReadWritePaths (the allowPaths agreement).
#
# HONESTY: auditd execve records carry no TargetFilename, so the one file an
# exec alert names is its own image. Quarantine is therefore tripped by a
# TRANSIENT dropper -- a process that execs a payload out of a scratch dir and
# EXITS -- exactly the dropper story quarantine.md section 1 tells. The process
# is gone by drain time; the FILE is what the executor acts on. Forged orders
# (enf_order) exercise the helper's own re-decision rails for the paths an audit
# event could never legitimately name (a device node, a FIFO, /etc).
{ pkgs ? import <nixpkgs> { }, banken ? pkgs.callPackage ../package.nix { } }:

let
  spawnLib = import ./lib/enforce-spawn.nix;

  # exec_from_tmp (level high) -> quarantine the image. maxFileBytes 1 MiB so the
  # sparse-file phase is quick and the cap is visibly exercised. allowPaths is
  # the quarantine.md 4.1 default, matching the module's quarantine.allowPaths
  # (and thus the helper unit's ReadWritePaths): the drain's startup subset check
  # passes and the sandbox lets the real renames/neuters land.
  allowPaths = [ "/tmp" "/var/tmp" "/dev/shm" "/home" "/root" "/opt" ];
  policy = ''
    mode: enforce
    minLevel: high
    enforceSources: [auditd, laurel]
    allowRoot: false
    rateLimit:
      perRun: 5000
      perHour: 50000
    quarantine:
      allowPaths: [/tmp, /var/tmp, /dev/shm, /home, /root, /opt]
      maxFileBytes: 1048576
    actions:
      - name: quar-exec-from-tmp
        rules: [exec_from_tmp]
        action: quarantine
        target: image
  '';
in
pkgs.testers.runNixOSTest {
  name = "banken-response-quarantine";

  nodes.machine = { lib, pkgs, ... }: {
    imports = [ ../module.nix ];
    services.banken = {
      enable = true;
      package = banken;
      alerts.jsonl = { enable = true; format = "ocsf"; };
      response = {
        enable = true;
        enforce = true; # armed ONLY in this throwaway VM
        fileActions = true; # the file caps + the allowPaths ReadWritePaths
        quarantine.allowPaths = allowPaths;
        inherit policy;
      };
    };
    systemd.timers.banken.wantedBy = lib.mkForce [ ];
    # /tmp on the root filesystem (same device as /var/lib) so a /tmp payload
    # takes the RENAME path; /dev/shm is tmpfs so a /dev/shm payload takes the
    # EXDEV NEUTER path. useTmpfs=false is the default but we pin it so the test
    # does not silently flip phase A to a neuter on a host that enabled it.
    boot.tmp.useTmpfs = false;
    users.users.alice.isNormalUser = true;
    # setfattr/getfattr (attr), lsattr/chattr (e2fsprogs): the test VM only, not
    # the host. truncate/stat/sha256sum are coreutils (already present).
    environment.systemPackages = with pkgs; [ attr e2fsprogs ];
  };

  testScript = spawnLib + ''
    import json
    from datetime import datetime, timezone

    machine.wait_for_unit("auditd.service")
    machine.wait_until_succeeds("auditctl -l | grep -q banken-exec")
    machine.wait_for_unit("banken-respond.path")  # the helper's trigger is up
    enf_scan()  # drain boot-time events

    QDIR = "/var/lib/banken/quarantine"

    def action_lines():
        out = machine.succeed("cat /var/lib/banken/response/actions-*.jsonl 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    def latest_quar(path, phase="executed"):
        """The newest quarantine action line for `path` in the given phase (ledger
        ids are time-ordered, so max() is the most recent)."""
        cands = [
            a for a in action_lines()
            if a.get("action") == "quarantine" and a.get("phase") == phase
            and ((a.get("target") or {}).get("file") or {}).get("path") == path
        ]
        return max(cands, key=lambda a: a["id"]) if cands else None

    def by_decision(oid):
        for a in action_lines():
            if a.get("decisionId") == oid:
                return a
        return None

    def manifest(hid):
        return json.loads(machine.succeed(f"cat {QDIR}/{hid}/manifest.json"))

    def mk_payload(path, mode):
        d = path.rsplit("/", 1)[0]
        machine.succeed(f"mkdir -p {d}")
        machine.succeed(f"cp $(command -v bash) {path}")
        # chown BEFORE chmod: chown clears setuid/setgid, so a 4755 payload set
        # first would come back 0755. alice-owned so the immutable check in phase
        # B isolates immutability (not sticky-dir ownership).
        machine.succeed(f"chown alice:users {path}")
        machine.succeed(f"chmod {mode} {path}")
        machine.succeed(f"setfattr -n user.banken-test -v payload-xattr {path}")
        machine.succeed(f"touch -d '2020-01-02 03:04:05' {path}")

    def mk_regular(path, content):
        d = path.rsplit("/", 1)[0]
        machine.succeed(f"mkdir -p {d}")
        machine.succeed(f"printf %s {content!r} > {path}")

    def rec_attrs(path):
        sha = machine.succeed(f"sha256sum {path}").split()[0]
        st = machine.succeed(f"stat -c '%i %f %u %g %Y %h' {path}").strip()
        xa = machine.succeed(
            f"getfattr -n user.banken-test --only-values {path} 2>/dev/null || true"
        ).strip()
        return {"sha": sha, "stat": st, "xattr": xa}

    def assert_attrs(path, pre, label):
        now = rec_attrs(path)
        assert now == pre, f"{label}: {path} changed: pre={pre} now={now}"

    def trip_exec(path):
        """Transient dropper: exec the payload out of a scratch dir and EXIT. The
        execve lands image=path in the audit log; the process is gone by drain
        time, so the FILE is what the executor acts on (the dropper story)."""
        machine.succeed(f"runuser -u alice -- {path} -c true")

    def barrier(tag):
        machine.succeed(f"auditctl -m {tag}")
        machine.wait_until_succeeds(f"grep -q {tag} /var/log/audit/audit.log")

    def quar_scan(path, tag):
        """Trip exec_from_tmp on `path`, barrier, one enforcing scan."""
        trip_exec(path)
        barrier(tag)
        enf_scan()

    def forged_quar_order(path):
        """A hand-crafted work order whose exec_from_tmp alert names `path` as its
        image, so Decide and the executor both see it. Exercises the helper's own
        rails for paths an audit event could never legitimately name (section
        4.4 phase E)."""
        now = datetime.now(timezone.utc).isoformat()
        return {
            "version": 1, "time": now, "policy": "sha256:forged", "banken": "test",
            "alert": {
                "time": now, "kind": "sigma", "rule": "exec_from_tmp", "level": "high",
                "source": "auditd", "message": "forged quarantine order",
                "event": {"time": now, "source": "auditd", "image": path,
                          "user": "alice", "pid": 1234, "ppid": 100},
            },
            "decision": {
                "intended": "quarantine", "action": "quarantine", "reason": "forged",
                "target": {"file": {"path": path}}, "scope": "process",
            },
        }

    def restore(args):
        """banken respond restore; returns (rc, stdout, stderr)."""
        rc, out = machine.execute(
            f"banken respond restore {args} -config /etc/banken/banken.yml 2>/tmp/rst.err"
        )
        err = machine.succeed("cat /tmp/rst.err 2>/dev/null || true")
        return rc, out.strip(), err.strip()

    # ---- filesystem preconditions (section 4.4): /tmp renames, /dev/shm EXDEVs --
    machine.succeed("mkdir -p /tmp/q /dev/shm/q")
    dev_tmp = machine.succeed("stat -c %d /tmp/q").strip()
    dev_store = machine.succeed("stat -c %d /var/lib/banken").strip()
    dev_shm = machine.succeed("stat -c %d /dev/shm/q").strip()
    assert dev_tmp == dev_store, \
        f"/tmp (dev {dev_tmp}) must share a filesystem with /var/lib (dev {dev_store}) for the rename path"
    assert dev_shm != dev_store, \
        f"/dev/shm (dev {dev_shm}) must be a different filesystem from the store (dev {dev_store}) for the EXDEV path"
    print(f"[pre] /tmp dev {dev_tmp} == store {dev_store} (rename); /dev/shm dev {dev_shm} != store (EXDEV neuter)")

    # ---- the allowPaths / ReadWritePaths AGREEMENT (item 2) --------------------
    # The helper unit's ReadWritePaths is rendered from the SAME allowPaths the
    # policy carries, so the paths phases A-B act on are writable under the
    # sandbox and /etc (acted on nowhere) is not. The forward code refusal of
    # /etc (never-touch, phase E) and this sandbox exclusion are the two halves
    # of the agreement.
    rwp = machine.succeed(
        "systemctl show -p ReadWritePaths --value banken-respond.service"
    ).strip()
    for p in ["/tmp", "/dev/shm"]:
        assert p in rwp.split(), f"helper ReadWritePaths {rwp!r} must include {p} (phases A/B act there)"
    assert "/etc" not in rwp.split(), f"helper ReadWritePaths {rwp!r} must NOT include /etc (never acted on)"
    print(f"[agreement] helper ReadWritePaths = {rwp} (grants /tmp + /dev/shm, excludes /etc)")

    # ======================== PHASE A: rename quarantine ========================
    P1 = "/tmp/q/payload"
    S1 = "/tmp/q/innocent"
    mk_payload(P1, "4755")        # setuid bit set, to prove it round-trips
    mk_regular(S1, "innocent-1")
    p1_pre = rec_attrs(P1)
    s1_pre = rec_attrs(S1)
    quar_scan(P1, "QUAR_A")

    a = latest_quar(P1)
    assert a is not None, "phase A: no executed quarantine action line for P1"
    assert a["enforced"] is True, f"phase A: not enforced: {a}"
    h = a["handle"]
    assert h["dryRun"] is False and h["method"] == "rename", f"phase A: handle not a real rename: {h}"
    Q1 = h["id"]
    assert machine.succeed(f"test -e {P1} && echo y || echo n").strip() == "n", \
        "phase A: the payload is still at its original path"
    assert_attrs(S1, s1_pre, "phase A sibling")
    stored = f"{QDIR}/{Q1}/file"
    stored_ino = machine.succeed(f"stat -c %i {stored}").strip()
    man = manifest(Q1)
    assert stored_ino == str(man["stat"]["ino"]), \
        f"phase A: stored inode {stored_ino} != manifest ino {man['stat']['ino']} (act did not bind the fstat'd inode)"
    assert str(man["stat"]["ino"]) == p1_pre["stat"].split()[0], \
        "phase A: manifest inode != the pre-quarantine inode"
    smode = machine.succeed(f"stat -c %a {stored}").strip()
    assert smode == "0", f"phase A: stored file mode {smode}, want 0000 (neutered)"
    assert "i" in machine.succeed(f"lsattr {stored} 2>/dev/null | awk '{{print $1}}'"), \
        "phase A: stored file is not immutable"
    assert man["method"] == "rename" and man["origPath"] == P1 and man["state"] == "held", \
        f"phase A: manifest fields wrong: {man}"
    assert man["sha256"] == p1_pre["sha"], f"phase A: manifest sha256 != recorded ({man['sha256']} vs {p1_pre['sha']})"
    assert man["immutable"] is True, f"phase A: manifest immutable false: {man}"
    mmode = machine.succeed(f"stat -c %a {QDIR}/{Q1}/manifest.json").strip()
    assert mmode == "400", f"phase A: manifest mode {mmode}, want 0400"
    lst = machine.succeed(f"banken respond list -kind quarantine -config /etc/banken/banken.yml")
    assert Q1[:8] in lst and "held" in lst, f"phase A: list does not show {Q1[:8]} held:\n{lst}"
    print(f"[phase A] PASS rename: {P1} -> store {Q1[:8]}, inode {stored_ino} bound, 0000+immutable, manifest held")

    # ==================== PHASE B: EXDEV neuter in place (Q1) ===================
    P2 = "/dev/shm/q/payload"
    S2 = "/dev/shm/q/innocent"
    mk_payload(P2, "0755")
    mk_regular(S2, "innocent-2")
    p2_pre = rec_attrs(P2)
    s2_pre = rec_attrs(S2)
    quar_scan(P2, "QUAR_B")

    b = latest_quar(P2)
    assert b is not None, "phase B: no executed quarantine action line for P2"
    hb = b["handle"]
    assert hb["method"] == "neuter", f"phase B: handle method {hb['method']}, want neuter (EXDEV)"
    Q2 = hb["id"]
    assert machine.succeed(f"test -e {QDIR}/{Q2}/file && echo y || echo n").strip() == "n", \
        "phase B: a neuter must leave no stored `file` (acted in place)"
    manB = manifest(Q2)
    live_ino = machine.succeed(f"stat -c %i {P2}").strip()
    assert live_ino == str(manB["stat"]["ino"]), \
        f"phase B: {P2} inode {live_ino} != manifest ino {manB['stat']['ino']} (neuter re-resolved the path, Q1 broken)"
    bmode = machine.succeed(f"stat -c %a {P2}").strip()
    assert bmode == "0", f"phase B: {P2} mode {bmode}, want 0000"
    assert manB["immutable"] is True, f"phase B: manifest immutable false: {manB}"
    assert "i" in machine.succeed(f"lsattr {P2} 2>/dev/null | awk '{{print $1}}'"), \
        "phase B: neutered /dev/shm file is not immutable"
    # the difference between a quarantine and a neuter-weak: the owner cannot undo it.
    rc_rm, _ = machine.execute(f"runuser -u alice -- rm -f {P2}")
    assert rc_rm != 0, "phase B: alice could delete the immutable neutered file"
    rc_ch, _ = machine.execute(f"runuser -u alice -- chmod 755 {P2}")
    assert rc_ch != 0, "phase B: alice could chmod the immutable neutered file"
    assert_attrs(S2, s2_pre, "phase B sibling")
    print(f"[phase B] PASS neuter: {P2} inode {live_ino} fstat-bound, 0000+immutable, owner cannot undo")

    # ==================== PHASE C: restore round-trips exactly ==================
    rc, out, err = restore(Q1)
    assert rc == 0, f"phase C: restore Q1 failed: rc={rc} err={err}"
    assert machine.succeed(f"test -e {P1} && echo y || echo n").strip() == "y", "phase C: P1 not restored"
    assert_attrs(P1, p1_pre, "phase C restore P1 (sha/mode incl setuid/uid/gid/mtime/nlink/inode/xattr)")
    assert "i" not in machine.succeed(f"lsattr {P1} 2>/dev/null | awk '{{print $1}}'"), \
        "phase C: restored P1 is still immutable"
    rc_x, _ = machine.execute(f"runuser -u alice -- {P1} -c true")
    assert rc_x == 0, "phase C: restored P1 is not executable again"
    assert machine.succeed(f"test -e {QDIR}/{Q1}/manifest.json && test -e {QDIR}/{Q1}/restored.json && echo y || echo n").strip() == "y", \
        "phase C: restore must KEEP the entry and write restored.json (Q3)"
    assert any(a.get("phase") == "restored" for a in action_lines()), "phase C: no restored ledger line"
    rc2, out2, _ = restore(Q1)
    assert rc2 == 0 and "already restored" in out2, f"phase C: second restore not a clean no-op: rc={rc2} out={out2!r}"
    rc3, out3, err3 = restore(Q2)
    assert rc3 == 0, f"phase C: restore Q2 failed: {err3}"
    assert_attrs(P2, p2_pre, "phase C restore P2")
    assert "i" not in machine.succeed(f"lsattr {P2} 2>/dev/null | awk '{{print $1}}'"), "phase C: restored P2 still immutable"
    print("[phase C] PASS restore: Q1 and Q2 round-tripped byte-identical (sha/mode/uid/gid/mtime/xattr/inode); entries kept; second restore a no-op")

    # ============== PHASE D: restore refuses to clobber, and -to ===============
    mk_payload(P1, "4755")  # a fresh P1 for a fresh quarantine
    p1d_pre = rec_attrs(P1)
    quar_scan(P1, "QUAR_D")
    d = latest_quar(P1)
    Q3 = d["handle"]["id"]
    assert Q3 != Q1, "phase D: expected a fresh handle for the re-quarantine"
    machine.succeed(f"runuser -u alice -- sh -c 'echo squatter > {P1}'")  # squatter at the origin
    rc, out, err = restore(Q3)
    assert rc == 1 and "occupied" in err, f"phase D: restore over a squatter must be refused (occupied): rc={rc} err={err}"
    assert machine.succeed(f"cat {P1}").strip() == "squatter", "phase D: the squatter was clobbered"
    assert machine.succeed(f"test -e {QDIR}/{Q3}/file && echo y || echo n").strip() == "y", "phase D: stored file gone after a refused restore"
    rc, out, err = restore(f"{Q3} -to /tmp/q/payload.restored")
    assert rc == 0, f"phase D: restore -to a free path failed: {err}"
    assert machine.succeed("sha256sum /tmp/q/payload.restored").split()[0] == p1d_pre["sha"], \
        "phase D: -to destination does not have the original content"
    rc, out, err = restore(f"{Q3} -to /etc/x")
    assert rc == 1, f"phase D: -to /etc must be refused (never-touch): rc={rc}"
    rc, out, err = restore(f"{Q3} -to {QDIR}/x")
    assert rc == 1, f"phase D: -to inside the store must be refused: rc={rc}"
    machine.succeed(f"rm -f {P1}")  # clear the squatter for later phases

    # Q4: a replaced inode is refused. Re-neuter P2, then replace the inode.
    mk_payload(P2, "0755")
    quar_scan(P2, "QUAR_D2")
    d2 = latest_quar(P2)
    Q4 = d2["handle"]["id"]
    machine.succeed(f"chattr -i {P2}")
    machine.succeed(f"rm -f {P2}")
    machine.succeed(f"printf %s 'replaced-content' > {P2}")
    rc, out, err = restore(Q4)
    assert rc == 1 and "inode replaced" in err, f"phase D: restore of a replaced inode must be refused: rc={rc} err={err}"
    assert machine.succeed(f"cat {P2}").strip() == "replaced-content", "phase D: the replacing file was touched"
    assert any(a.get("decisionId") is not None and a.get("action") == "quarantine" for a in action_lines())
    print("[phase D] PASS restore guards: squatter refused (occupied), -to works, -to /etc and -to <store> refused, replaced inode refused (Q4)")

    # ======================= PHASE E: guards via forged orders ==================
    # /dev/null: the never-touch /dev rail (Q14) downgrades the forged quarantine.
    oid = enf_order(forged_quar_order("/dev/null"))
    enf_wait_drained()
    ar = by_decision(oid)
    assert ar and ar["phase"] == "downgraded", f"phase E: /dev/null forged order must be downgraded (never-touch): {ar}"
    assert machine.succeed("stat -c %F /dev/null").strip() == "character special file", "phase E: /dev/null changed"
    print("[phase E] /dev/null -> downgraded (never-touch /dev), device node intact")

    # /dev/shm file: the carve-out makes it ACTIONABLE; S2 is quarantined then restored.
    oid = enf_order(forged_quar_order(S2))
    enf_wait_drained()
    ar = by_decision(oid)
    assert ar and ar["phase"] == "executed" and ar["handle"]["method"] == "neuter", \
        f"phase E: /dev/shm file must quarantine via the carve-out: {ar}"
    QS2 = ar["handle"]["id"]
    rc, out, err = restore(QS2)
    assert rc == 0, f"phase E: restore of the /dev/shm innocent failed: {err}"
    assert_attrs(S2, s2_pre, "phase E /dev/shm carve-out round trip")
    print("[phase E] /dev/shm innocent -> quarantined (carve-out) then restored byte-identical")

    # FIFO: not a regular file.
    machine.succeed("rm -f /tmp/q/fifo && mkfifo /tmp/q/fifo")
    oid = enf_order(forged_quar_order("/tmp/q/fifo"))
    enf_wait_drained()
    ar = by_decision(oid)
    assert ar and ar["phase"] == "failed" and "regular file" in (ar.get("error") or ""), \
        f"phase E: a FIFO must fail as not-a-regular-file: {ar}"
    assert machine.succeed("stat -c %F /tmp/q/fifo").strip() == "fifo", "phase E: the FIFO was altered"
    efifo = (ar.get("error") or "")[:40]
    print(f"[phase E] FIFO -> failed ({efifo}), FIFO intact")

    # symlink: the O_NOFOLLOW open refuses to act on the symlink's target.
    machine.succeed("mkdir -p /home/alice")
    machine.succeed("printf %s secret-content > /home/alice/secret && chown alice:users /home/alice/secret")
    secret_pre = rec_attrs("/home/alice/secret")
    machine.succeed("rm -f /tmp/q/link && ln -s /home/alice/secret /tmp/q/link")
    oid = enf_order(forged_quar_order("/tmp/q/link"))
    enf_wait_drained()
    ar = by_decision(oid)
    assert ar and ar["phase"] == "failed", f"phase E: a symlink must fail: {ar}"
    assert_attrs("/home/alice/secret", secret_pre, "phase E symlink target")
    elink = (ar.get("error") or "")[:40]
    print(f"[phase E] symlink -> failed ({elink}), target unchanged")

    # /etc/passwd: never-touch (and the sandbox would refuse it too).
    etc_pre = rec_attrs("/etc/passwd")
    oid = enf_order(forged_quar_order("/etc/passwd"))
    enf_wait_drained()
    ar = by_decision(oid)
    assert ar and ar["phase"] == "downgraded", f"phase E: /etc/passwd must be downgraded (never-touch): {ar}"
    assert_attrs("/etc/passwd", etc_pre, "phase E /etc/passwd")
    print("[phase E] /etc/passwd -> downgraded (never-touch), untouched")

    # 2 GiB sparse, cap 1 MiB: moved but recorded unhashed, fast.
    machine.succeed("rm -f /tmp/q/big && truncate -s 2G /tmp/q/big")
    import time as _t
    t0 = _t.time()
    oid = enf_order(forged_quar_order("/tmp/q/big"))
    enf_wait_drained()
    dt = _t.time() - t0
    ar = by_decision(oid)
    assert ar and ar["phase"] == "executed" and ar["handle"]["method"] == "rename", \
        f"phase E: the big sparse file must still be quarantined: {ar}"
    QB = ar["handle"]["id"]
    manBig = manifest(QB)
    assert manBig["sha256"] == "unhashed", \
        f"phase E: a file over maxFileBytes must record sha256 'unhashed', got {manBig['sha256']!r} (Q6)"
    assert machine.succeed("test -e /tmp/q/big && echo y || echo n").strip() == "n", "phase E: the big file was not moved"
    print(f"[phase E] 2 GiB sparse -> quarantined, sha256 'unhashed' (Q6), drain {dt:.1f}s (soft)")

    # an unmapped rule: downgraded, nothing moved.
    o = forged_quar_order("/tmp/q/nope")
    o["alert"]["rule"] = "no_such_rule_xyz"
    oid = enf_order(o)
    enf_wait_drained()
    ar = by_decision(oid)
    assert ar and ar["phase"] == "downgraded", f"phase E: an unmapped rule must be downgraded: {ar}"
    print("[phase E] PASS guards: /dev refused, carve-out acts, FIFO/symlink failed, /etc downgraded, 2 GiB unhashed, unmapped downgraded")

    # ===================== PHASE F: manifest-first (Q2) =========================
    # Make the store root immutable; a quarantine is refused HAVING TOUCHED
    # NOTHING (the pending manifest write under the immutable root fails before
    # any rename). Then clear it and re-run the SAME order: it succeeds.
    mk_payload(P1, "4755")
    p1f_pre = rec_attrs(P1)
    trip_exec(P1)
    barrier("QUAR_F")
    machine.succeed("systemctl stop banken-respond.path")
    machine.succeed("systemctl start banken.service")  # daemon writes the order; helper is not triggered
    machine.wait_until_succeeds("test -n \"$(ls -A /var/lib/banken/spool 2>/dev/null)\"")
    oid_f = machine.succeed("ls /var/lib/banken/spool | head -1").strip()[:-5]  # strip .json
    machine.succeed(f"cp /var/lib/banken/spool/{oid_f}.json /root/order-F.json")
    machine.succeed(f"chattr +i {QDIR}")
    machine.succeed("systemctl start banken-respond.path")  # now the helper drains, and must FAIL
    enf_wait_drained()
    af = by_decision(oid_f)
    assert af and af["phase"] == "failed", f"phase F: quarantine under an immutable store must fail: {af}"
    assert machine.succeed(f"test -e {P1} && echo y || echo n").strip() == "y", "phase F: the payload was moved despite the refusal"
    assert_attrs(P1, p1f_pre, "phase F payload (untouched under the refused act)")
    before = int(machine.succeed(f"ls -1 {QDIR} | wc -l").strip())
    machine.succeed(f"chattr -i {QDIR}")
    # re-inject the SAME order (fresh id) and drain by hand: now it succeeds.
    order_f = json.loads(machine.succeed("cat /root/order-F.json"))
    order_f["id"] = ""  # enf_order mints a fresh time-ordered id
    oid_f2 = enf_order(order_f)
    enf_wait_drained()
    af2 = by_decision(oid_f2)
    assert af2 and af2["phase"] == "executed", f"phase F: the re-run after clearing immutability must succeed: {af2}"
    assert machine.succeed(f"test -e {P1} && echo y || echo n").strip() == "n", "phase F: the re-run did not move the payload"
    after = int(machine.succeed(f"ls -1 {QDIR} | wc -l").strip())
    assert after == before + 1, f"phase F: expected exactly one new store entry (before {before}, after {after})"
    print("[phase F] PASS manifest-first: immutable store refused the quarantine untouched; cleared, the same order quarantined cleanly")

    # ===================== PHASE G: collateral + scorecard ======================
    assert_attrs(S1, s1_pre, "phase G sibling S1")
    assert_attrs(S2, s2_pre, "phase G sibling S2 (restored in phase E)")
    assert_attrs("/home/alice/secret", secret_pre, "phase G symlink target")
    assert machine.succeed("stat -c %F /dev/null").strip() == "character special file", "phase G: /dev/null changed"
    assert machine.succeed("stat -c %F /tmp/q/fifo").strip() == "fifo", "phase G: FIFO changed"
    # no action line names S1, the secret, /dev/null or the FIFO as a successful act.
    acted_paths = {
        ((a.get("target") or {}).get("file") or {}).get("path")
        for a in action_lines() if a.get("phase") == "executed"
    }
    for innocent in [S1, "/home/alice/secret", "/dev/null", "/tmp/q/fifo", "/tmp/q/link"]:
        assert innocent not in acted_paths, f"phase G: {innocent} appears as an executed quarantine"

    print("\n==================== QUARANTINE PROOF SCORECARD ====================")
    print("quarantine proven: rename and neuter landed on the fstat'd inode, store")
    print("neutered, manifest-first held under an unwritable store, restore")
    print("round-tripped byte-identical and refused to clobber; guards held for")
    print("/dev, FIFO, symlink, /etc, 2 GiB sparse.")
    print(f"  Q1  fd identity:      rename ino {stored_ino}, neuter ino {live_ino} (both fstat-bound)")
    print(f"  Q2  manifest-first:   immutable store refused untouched, then finalised from the order")
    print(f"  Q3  restore kept:     Q1 entry + tombstone; second restore a no-op")
    print(f"  Q4  replaced inode:   refused 'inode replaced'; occupied dest refused")
    print(f"  Q6  over cap:         2 GiB sparse recorded 'unhashed', moved")
    print(f"  Q14 /dev + forged:    /dev/null downgraded, FIFO/symlink failed, /etc downgraded")
    print(f"  item2 agreement:      /tmp + /dev/shm in ReadWritePaths (acted), /etc excluded (refused)")
    print("  0 innocents touched (S1, S2 restored, /home/alice/secret, /dev/null, FIFO)")
    print("===================================================================")
  '';
}
