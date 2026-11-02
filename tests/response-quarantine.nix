# End-to-end proof that banken's quarantine enforcement is REAL: a dropped
# payload is NEUTERED in place on its fstat'd inode (mode 0000 + immutable) or
# RENAMED into the quarantine store, recorded manifest-first, and the real
# `banken respond restore` CLI round-trips it byte-identical. One throwaway KVM
# VM acts solely on files the test itself drops; the real hokkaido host and
# every other config leave response.enforce false.
#
#   nix-build tests/response-quarantine.nix   (needs KVM; run on hokkaido)
#   nix flake check                           (checks.x86_64-linux.response-quarantine)
#
# This is docs/design/response-architecture.md section 4.4 (phases A-G) and item
# 9 of section 6. It proves, live:
#   Q1  the act binds to the fstat'd inode, not a re-resolved path (the neuter
#       acts on exactly the fstat'd inode in place; the rename lands the recorded
#       inode in the store), 0000 + immutable either way.
#   Q2  manifest-first: with the store root made immutable mid-run the quarantine
#       is refused having touched nothing, then finalises once it is writable.
#   Q3  restore keeps the store entry and writes a tombstone (second restore is
#       a no-op).
#   Q4  restore refuses a replaced inode ("inode replaced") and refuses to
#       clobber an occupied destination; -to works, -to /etc and -to <store> are
#       refused.
#   Q6  a payload over quarantine.maxFileBytes is still quarantined but recorded
#       "unhashed", completing fast.
#   Q14 a /dev device node is refused by the never-touch carve-out, while a
#       /dev/shm file is actionable (the carve-out); a FIFO and a symlink are
#       refused by the executor; /etc is refused by never-touch AND would be
#       refused by the helper unit's ReadWritePaths (the allowPaths agreement).
#
# FINDING, proven here and surfaced to the manager: the production helper
# (banken-respond.service) runs with ProtectSystem=strict + per-path
# ReadWritePaths + StateDirectory, so every writable path -- each allowPath AND
# the quarantine store under /var/lib/banken -- is a SEPARATE systemd bind mount.
# renameat2 across two bind mounts returns EXDEV even on one underlying device,
# so under the armed helper a quarantine of any allowPath file ALWAYS takes the
# in-place NEUTER branch; it never renames the file into the store. The rename
# branch runs only UNSANDBOXED (a by-hand `banken respond drain`, the recovery
# pass run by hand, operator tooling). This test proves the neuter path under
# the real helper (phase B, both a /tmp and a /dev/shm payload) and the rename
# path under an unsandboxed by-hand drain (phase A), and asserts the EXDEV
# behaviour so the finding cannot silently regress.
#
# HONESTY: auditd execve records carry no TargetFilename, so the one file an
# exec alert names is its own image. Quarantine is tripped by a TRANSIENT
# dropper -- a process that execs a payload out of a scratch dir and EXITS --
# exactly the dropper story quarantine.md section 1 tells. The process is gone
# by drain time; the FILE is what the executor acts on. Forged orders (enf_order)
# exercise the helper's own re-decision rails for the paths an audit event could
# never legitimately name (a device node, a FIFO, /etc).
{ pkgs ? import <nixpkgs> { }, banken ? pkgs.callPackage ../package.nix { } }:

let
  spawnLib = import ./lib/enforce-spawn.nix;

  # exec_from_tmp (level high) -> quarantine the image. maxFileBytes 10 MiB: above
  # the ~1.2 MiB bash-copy payloads (so their sha256 is recorded and restore can
  # assert it) and far below the 2 GiB sparse file of phase E (so the cap is
  # still visibly exercised there). allowPaths is the quarantine.md 4.1 default,
  # matching the module's quarantine.allowPaths (and thus the helper unit's
  # ReadWritePaths): the drain's startup subset check passes and the sandbox
  # lets the real neuters land.
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
      maxFileBytes: 10485760
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
    # /tmp on the root filesystem (same device as /var/lib) so an UNSANDBOXED
    # by-hand drain can take the rename path; /dev/shm is tmpfs so it is a
    # genuine cross-filesystem neuter. useTmpfs=false is the default but we pin
    # it so the test does not silently change behaviour on a host that enabled it.
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

    def latest_quar(phase="executed"):
        """The newest quarantine action line in `phase`. Each drain produces at
        most one quarantine, and we read it immediately after, so the newest
        (ledger ids are time-ordered) is the one we just caused."""
        cands = [
            a for a in action_lines()
            if a.get("action") == "quarantine" and a.get("phase") == phase
        ]
        return max(cands, key=lambda a: a["id"]) if cands else None

    def by_decision(oid):
        for a in action_lines():
            if a.get("decisionId") == oid:
                return a
        return None

    def manifest(hid):
        return json.loads(machine.succeed(f"cat {QDIR}/{hid}/manifest.json"))

    def lsattr_flags(path):
        return machine.succeed(f"lsattr {path} 2>/dev/null | awk '{{print $1}}' || true").strip()

    def mk_payload(path, mode):
        d = path.rsplit("/", 1)[0]
        machine.succeed(f"mkdir -p {d}")
        machine.succeed(f"cp $(command -v bash) {path}")
        # chown BEFORE chmod: chown clears setuid/setgid, so a 4755 payload set
        # first would come back 0755. alice-owned so phase B's immutable check
        # isolates immutability (not sticky-dir ownership).
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

    def drain_byhand():
        """Drain the spool UNSANDBOXED, in a root shell. Here /tmp and the store
        share the one ext4 mount (no per-path bind mounts), so a /tmp payload
        takes the RENAME branch -- the branch the sandboxed helper can never
        reach (see FINDING). The daemon writes the order with the path unit
        stopped so nothing drains it first; we then run the identical drain code
        by hand and restart the path unit."""
        machine.succeed("systemctl stop banken-respond.path")
        machine.succeed("systemctl start banken.service")  # daemon writes the order
        machine.wait_until_succeeds('test -n "$(ls -A /var/lib/banken/spool 2>/dev/null)"')
        machine.succeed("banken respond drain -config /etc/banken/banken.yml")
        machine.succeed('test -z "$(ls -A /var/lib/banken/spool 2>/dev/null)"')
        machine.succeed("systemctl start banken-respond.path")

    def restore(handle_id, to=None):
        """banken respond restore; returns (rc, stdout, stderr). Flags MUST precede
        the positional handle id: Go's flag package stops parsing at the first
        non-flag token, so a -config/-to placed after the id is never seen."""
        cmd = "banken respond restore -config /etc/banken/banken.yml"
        if to is not None:
            cmd += f" -to {to}"
        cmd += f" {handle_id} 2>/tmp/rst.err"
        rc, out = machine.execute(cmd)
        err = machine.succeed("cat /tmp/rst.err 2>/dev/null || true")
        return rc, out.strip(), err.strip()

    def forged_quar_order(path):
        """A hand-crafted work order whose exec_from_tmp alert names `path` as its
        image. Exercises the helper's own rails for paths an audit event could
        never legitimately name (section 4.4 phase E). It drains through the path
        unit, i.e. the sandboxed helper, so an acting quarantine NEUTERS."""
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

    # ---- filesystem preconditions (section 4.4) -------------------------------
    # world-writable sticky scratch dirs, like real /tmp and /dev/shm: alice owns
    # the payloads she drops there, so phase B's owner-cannot-delete isolates the
    # immutable bit, and phase D's squatter can be created as alice.
    machine.succeed("mkdir -p /tmp/q /dev/shm/q && chmod 1777 /tmp/q /dev/shm/q")
    dev_tmp = machine.succeed("stat -c %d /tmp/q").strip()
    dev_store = machine.succeed("stat -c %d /var/lib/banken").strip()
    dev_shm = machine.succeed("stat -c %d /dev/shm/q").strip()
    assert dev_tmp == dev_store, \
        f"/tmp (dev {dev_tmp}) must share a filesystem with /var/lib (dev {dev_store}) for the unsandboxed rename"
    assert dev_shm != dev_store, \
        f"/dev/shm (dev {dev_shm}) must be a different filesystem from the store (dev {dev_store}) for the cross-fs neuter"
    print(f"[pre] /tmp dev {dev_tmp} == store {dev_store}; /dev/shm dev {dev_shm} != store")

    # ---- the allowPaths / ReadWritePaths AGREEMENT (item 2) --------------------
    # The helper unit's ReadWritePaths is rendered from the SAME allowPaths the
    # policy carries, so the paths phase B acts on are writable under the sandbox
    # and /etc (acted on nowhere) is not. The forward code refusal of /etc
    # (never-touch, phase E) and this sandbox exclusion are the two halves of the
    # agreement.
    rwp = machine.succeed(
        "systemctl show -p ReadWritePaths --value banken-respond.service"
    ).strip()
    # entries are '-' prefixed (ignore-if-absent), so strip the marker to compare.
    rwp_paths = {tok.lstrip("-") for tok in rwp.split()}
    for p in ["/tmp", "/dev/shm"]:
        assert p in rwp_paths, f"helper ReadWritePaths {rwp!r} must include {p} (phase B acts there)"
    assert "/etc" not in rwp_paths, f"helper ReadWritePaths {rwp!r} must NOT include /etc (never acted on)"
    print(f"[agreement] helper ReadWritePaths = {rwp}")

    # ============ PHASE A: rename quarantine (UNSANDBOXED by-hand drain) ========
    P1 = "/tmp/q/payload"
    S1 = "/tmp/q/innocent"
    mk_payload(P1, "4755")        # setuid bit set, to prove it round-trips
    mk_regular(S1, "innocent-1")
    p1_pre = rec_attrs(P1)
    s1_pre = rec_attrs(S1)
    trip_exec(P1)
    barrier("QUAR_A")
    drain_byhand()

    a = latest_quar()
    assert a is not None, "phase A: no executed quarantine action line"
    assert a["enforced"] is True, f"phase A: not enforced: {a}"
    h = a["handle"]
    assert h["dryRun"] is False and h["method"] == "rename", \
        f"phase A: want a real rename (unsandboxed drain), got {h}"
    Q1 = h["id"]
    assert machine.succeed(f"test -e {P1} && echo y || echo n").strip() == "n", \
        "phase A: the payload is still at its original path (rename should have moved it)"
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
    assert "i" in lsattr_flags(stored), "phase A: stored file is not immutable"
    assert man["method"] == "rename" and man["origPath"] == P1 and man["state"] == "held", \
        f"phase A: manifest fields wrong: {man}"
    assert man["sha256"] == p1_pre["sha"], f"phase A: manifest sha256 != recorded ({man['sha256']} vs {p1_pre['sha']})"
    assert man["immutable"] is True, f"phase A: manifest immutable false: {man}"
    mmode = machine.succeed(f"stat -c %a {QDIR}/{Q1}/manifest.json").strip()
    assert mmode == "400", f"phase A: manifest mode {mmode}, want 0400"
    lst = machine.succeed("banken respond list -kind quarantine -config /etc/banken/banken.yml")
    assert Q1[:8] in lst and "held" in lst, f"phase A: list does not show {Q1[:8]} held:\n{lst}"
    print(f"[phase A] PASS rename (unsandboxed drain): {P1} -> store {Q1[:8]}, inode {stored_ino} bound, 0000+immutable")

    # ====== PHASE B: neuter in place under the REAL armed helper (sandboxed) ====
    # B1 proves the FINDING: a /tmp payload under banken-respond.service neuters
    # in place -- the store is a separate bind mount, so the rename is EXDEV. It
    # also proves the helper can write /tmp (the agreement). B2 is the genuine
    # cross-filesystem case on /dev/shm.
    Pf = "/tmp/q/hpayload"
    mk_payload(Pf, "0755")
    trip_exec(Pf)
    barrier("QUAR_B1")
    enf_scan()  # the REAL sandboxed helper
    bf = latest_quar()
    assert bf is not None and bf["handle"]["method"] == "neuter", \
        f"phase B1 (finding): a /tmp payload under the sandboxed helper must NEUTER (store is a separate bind mount), got {bf}"
    Qf = bf["handle"]["id"]
    assert machine.succeed(f"test -e {QDIR}/{Qf}/file && echo y || echo n").strip() == "n", \
        "phase B1: a neuter must leave no stored file (acted in place)"
    assert machine.succeed(f"stat -c %a {Pf}").strip() == "0" and "i" in lsattr_flags(Pf), \
        "phase B1: the /tmp payload was not neutered in place (0000 + immutable)"
    print(f"[phase B1] PASS FINDING: sandboxed helper NEUTERS /tmp in place ({Pf} 0000+immutable), rename is EXDEV across bind mounts")

    P2 = "/dev/shm/q/payload"
    S2 = "/dev/shm/q/innocent"
    mk_payload(P2, "0755")
    mk_regular(S2, "innocent-2")
    p2_pre = rec_attrs(P2)
    s2_pre = rec_attrs(S2)
    trip_exec(P2)
    barrier("QUAR_B2")
    enf_scan()
    b = latest_quar()
    assert b is not None and b["handle"]["method"] == "neuter", \
        f"phase B2: /dev/shm payload must neuter (cross-fs), got {b}"
    Q2 = b["handle"]["id"]
    assert machine.succeed(f"test -e {QDIR}/{Q2}/file && echo y || echo n").strip() == "n", \
        "phase B2: a neuter must leave no stored file"
    manB = manifest(Q2)
    live_ino = machine.succeed(f"stat -c %i {P2}").strip()
    assert live_ino == str(manB["stat"]["ino"]), \
        f"phase B2: {P2} inode {live_ino} != manifest ino {manB['stat']['ino']} (neuter re-resolved the path, Q1 broken)"
    assert machine.succeed(f"stat -c %a {P2}").strip() == "0", f"phase B2: {P2} not mode 0000"
    assert manB["immutable"] is True, f"phase B2: manifest immutable false: {manB}"
    assert "i" in lsattr_flags(P2), "phase B2: neutered /dev/shm file is not immutable"
    # the difference between a quarantine and a neuter-weak: the owner cannot undo it.
    rc_rm, _ = machine.execute(f"runuser -u alice -- rm -f {P2}")
    assert rc_rm != 0, "phase B2: alice could delete the immutable neutered file"
    rc_ch, _ = machine.execute(f"runuser -u alice -- chmod 755 {P2}")
    assert rc_ch != 0, "phase B2: alice could chmod the immutable neutered file"
    assert_attrs(S2, s2_pre, "phase B2 sibling")
    print(f"[phase B2] PASS neuter (cross-fs): {P2} inode {live_ino} fstat-bound, 0000+immutable, owner cannot undo")

    # ==================== PHASE C: restore round-trips exactly ==================
    rc, out, err = restore(Q1)  # rename method
    assert rc == 0, f"phase C: restore Q1 failed: rc={rc} err={err}"
    assert machine.succeed(f"test -e {P1} && echo y || echo n").strip() == "y", "phase C: P1 not restored"
    assert_attrs(P1, p1_pre, "phase C restore P1 (sha/mode incl setuid/uid/gid/mtime/nlink/inode/xattr)")
    assert "i" not in lsattr_flags(P1), "phase C: restored P1 is still immutable"
    rc_x, _ = machine.execute(f"runuser -u alice -- {P1} -c true")
    assert rc_x == 0, "phase C: restored P1 is not executable again"
    assert machine.succeed(f"test -e {QDIR}/{Q1}/manifest.json && test -e {QDIR}/{Q1}/restored.json && echo y || echo n").strip() == "y", \
        "phase C: restore must KEEP the entry and write restored.json (Q3)"
    assert any(a.get("phase") == "restored" for a in action_lines()), "phase C: no restored ledger line"
    rc2, out2, _ = restore(Q1)
    assert rc2 == 0 and "already restored" in out2, f"phase C: second restore not a clean no-op: rc={rc2} out={out2!r}"
    rc3, out3, err3 = restore(Q2)  # neuter method
    assert rc3 == 0, f"phase C: restore Q2 failed: {err3}"
    assert_attrs(P2, p2_pre, "phase C restore P2 (neuter)")
    assert "i" not in lsattr_flags(P2), "phase C: restored P2 still immutable"
    print("[phase C] PASS restore: rename (Q1) and neuter (Q2) round-tripped byte-identical (sha/mode/uid/gid/mtime/xattr/inode); entries kept; second restore a no-op")

    # ============== PHASE D: restore refuses to clobber, and -to ===============
    # D1 needs a rename-method entry (origin freed) for the squatter test, so it
    # drains unsandboxed.
    mk_payload(P1, "4755")
    p1d_pre = rec_attrs(P1)
    trip_exec(P1)
    barrier("QUAR_D")
    drain_byhand()
    d = latest_quar()
    assert d["handle"]["method"] == "rename", f"phase D1: expected a rename for the squatter test, got {d['handle']}"
    Q3 = d["handle"]["id"]
    assert Q3 != Q1, "phase D: expected a fresh handle for the re-quarantine"
    machine.succeed(f"runuser -u alice -- sh -c 'echo squatter > {P1}'")  # squatter at the freed origin
    rc, out, err = restore(Q3)
    assert rc == 1 and "occupied" in err, f"phase D: restore over a squatter must be refused (occupied): rc={rc} err={err}"
    assert machine.succeed(f"cat {P1}").strip() == "squatter", "phase D: the squatter was clobbered"
    assert machine.succeed(f"test -e {QDIR}/{Q3}/file && echo y || echo n").strip() == "y", "phase D: stored file gone after a refused restore"
    rc, out, err = restore(Q3, to="/tmp/q/payload.restored")
    assert rc == 0, f"phase D: restore -to a free path failed: {err}"
    assert machine.succeed("sha256sum /tmp/q/payload.restored").split()[0] == p1d_pre["sha"], \
        "phase D: -to destination does not have the original content"
    rc, out, err = restore(Q3, to="/etc/x")
    assert rc == 1, f"phase D: -to /etc must be refused (never-touch): rc={rc}"
    rc, out, err = restore(Q3, to=f"{QDIR}/x")
    assert rc == 1, f"phase D: -to inside the store must be refused: rc={rc}"
    machine.succeed(f"rm -f {P1}")  # clear the squatter for later phases

    # D2: Q4, a replaced inode is refused (neuter method on /dev/shm).
    mk_payload(P2, "0755")
    trip_exec(P2)
    barrier("QUAR_D2")
    enf_scan()
    d2 = latest_quar()
    assert d2["handle"]["method"] == "neuter", f"phase D2: expected a neuter, got {d2['handle']}"
    Q4 = d2["handle"]["id"]
    machine.succeed(f"chattr -i {P2}")
    machine.succeed(f"rm -f {P2}")
    machine.succeed(f"printf %s 'replaced-content' > {P2}")
    rc, out, err = restore(Q4)
    assert rc == 1 and "inode replaced" in err, f"phase D: restore of a replaced inode must be refused: rc={rc} err={err}"
    assert machine.succeed(f"cat {P2}").strip() == "replaced-content", "phase D: the replacing file was touched"
    print("[phase D] PASS restore guards: squatter refused (occupied), -to works, -to /etc and -to <store> refused, replaced inode refused (Q4)")

    # ======================= PHASE E: guards via forged orders ==================
    # Forged orders drain through the path unit (the sandboxed helper), so an
    # acting quarantine NEUTERS.
    # /dev/null: the never-touch /dev rail (Q14) downgrades the forged quarantine.
    oid = enf_order(forged_quar_order("/dev/null"))
    enf_wait_drained()
    ar = by_decision(oid)
    assert ar and ar["phase"] == "downgraded", f"phase E: /dev/null forged order must be downgraded (never-touch): {ar}"
    assert machine.succeed("stat -c %F /dev/null").strip() == "character special file", "phase E: /dev/null changed"
    print("[phase E] /dev/null -> downgraded (never-touch /dev), device node intact")

    # /dev/shm file: the carve-out makes it ACTIONABLE; S2 is neutered then restored.
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

    # 2 GiB sparse, over the 10 MiB cap: still quarantined (neutered in place) but
    # recorded unhashed, and fast.
    machine.succeed("rm -f /tmp/q/big && truncate -s 2G /tmp/q/big")
    import time as _t
    t0 = _t.time()
    oid = enf_order(forged_quar_order("/tmp/q/big"))
    enf_wait_drained()
    dt = _t.time() - t0
    ar = by_decision(oid)
    assert ar and ar["phase"] == "executed", f"phase E: the big sparse file must still be quarantined: {ar}"
    QB = ar["handle"]["id"]
    manBig = manifest(QB)
    assert manBig["sha256"] == "unhashed", \
        f"phase E: a file over maxFileBytes must record sha256 'unhashed', got {manBig['sha256']!r} (Q6)"
    assert machine.succeed("stat -c %a /tmp/q/big").strip() == "0", "phase E: the big file was not neutered (0000)"
    print(f"[phase E] 2 GiB sparse -> quarantined, sha256 'unhashed' (Q6), drain {dt:.1f}s (soft)")

    # an unmapped rule: downgraded, nothing acted.
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
    # the act). Then clear it and re-run the SAME order via the helper: it
    # succeeds (neutering in place, per the finding). Driven through the path unit.
    mk_payload(P1, "4755")
    p1f_pre = rec_attrs(P1)
    trip_exec(P1)
    barrier("QUAR_F")
    machine.succeed("systemctl stop banken-respond.path")
    machine.succeed("systemctl start banken.service")  # daemon writes the order; helper not triggered
    machine.wait_until_succeeds('test -n "$(ls -A /var/lib/banken/spool 2>/dev/null)"')
    oid_f = machine.succeed("ls /var/lib/banken/spool | head -1").strip()[:-5]  # strip .json
    machine.succeed(f"cp /var/lib/banken/spool/{oid_f}.json /root/order-F.json")
    machine.succeed(f"chattr +i {QDIR}")
    machine.succeed("systemctl start banken-respond.path")  # the helper drains, and must FAIL
    enf_wait_drained()
    af = by_decision(oid_f)
    assert af and af["phase"] == "failed", f"phase F: quarantine under an immutable store must fail: {af}"
    assert machine.succeed(f"test -e {P1} && echo y || echo n").strip() == "y", "phase F: the payload was acted on despite the refusal"
    assert_attrs(P1, p1f_pre, "phase F payload (untouched under the refused act)")
    before = int(machine.succeed(f"ls -1 {QDIR} | wc -l").strip())
    machine.succeed(f"chattr -i {QDIR}")
    # re-inject the SAME order (fresh id): now it succeeds (neuters in place).
    order_f = json.loads(machine.succeed("cat /root/order-F.json"))
    order_f["id"] = ""  # enf_order mints a fresh time-ordered id
    oid_f2 = enf_order(order_f)
    enf_wait_drained()
    af2 = by_decision(oid_f2)
    assert af2 and af2["phase"] == "executed", f"phase F: the re-run after clearing immutability must succeed: {af2}"
    assert machine.succeed(f"stat -c %a {P1}").strip() == "0", "phase F: the re-run did not neuter the payload"
    after = int(machine.succeed(f"ls -1 {QDIR} | wc -l").strip())
    assert after == before + 1, f"phase F: expected exactly one new store entry (before {before}, after {after})"
    print("[phase F] PASS manifest-first: immutable store refused the quarantine untouched; cleared, the same order quarantined cleanly")

    # ===================== PHASE G: collateral + scorecard ======================
    assert_attrs(S1, s1_pre, "phase G sibling S1")
    assert_attrs(S2, s2_pre, "phase G sibling S2 (restored in phase E)")
    assert_attrs("/home/alice/secret", secret_pre, "phase G symlink target")
    assert machine.succeed("stat -c %F /dev/null").strip() == "character special file", "phase G: /dev/null changed"
    assert machine.succeed("stat -c %F /tmp/q/fifo").strip() == "fifo", "phase G: FIFO changed"
    # no action line names S1, the secret, /dev/null, the FIFO or the symlink as a
    # successful act.
    acted_paths = {
        ((a.get("target") or {}).get("file") or {}).get("path")
        for a in action_lines() if a.get("phase") == "executed"
    }
    for innocent in [S1, "/home/alice/secret", "/dev/null", "/tmp/q/fifo", "/tmp/q/link"]:
        assert innocent not in acted_paths, f"phase G: {innocent} appears as an executed quarantine"

    print("\n==================== QUARANTINE PROOF SCORECARD ====================")
    print("quarantine proven: neuter (real helper) and rename (unsandboxed drain)")
    print("landed on the fstat'd inode; manifest-first held under an unwritable")
    print("store; restore round-tripped byte-identical and refused to clobber;")
    print("guards held for /dev, FIFO, symlink, /etc, 2 GiB sparse.")
    print(f"  Q1  fd identity:      rename ino {stored_ino}, neuter ino {live_ino} (both fstat-bound)")
    print("  Q2  manifest-first:   immutable store refused untouched, then finalised from the order")
    print("  Q3  restore kept:     Q1 entry + tombstone; second restore a no-op")
    print("  Q4  replaced inode:   refused 'inode replaced'; occupied dest refused")
    print("  Q6  over cap:         2 GiB sparse recorded 'unhashed'")
    print("  Q14 /dev + forged:    /dev/null downgraded, FIFO/symlink failed, /etc downgraded")
    print("  item2 agreement:      /tmp + /dev/shm in ReadWritePaths (acted), /etc excluded (refused)")
    print("  FINDING:              the sandboxed helper neuters in place; rename is EXDEV across bind mounts")
    print("  0 innocents touched (S1, S2 restored, /home/alice/secret, /dev/null, FIFO)")
    print("===================================================================")
  '';
}
