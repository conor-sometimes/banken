# WHACK-A-MOLE enforcement safety stress. The safety-critical proof: under a
# kill-ALL-the-attack-rules policy, a randomized, interleaved mix of many live
# processes is judged by the real detect -> Decide -> executor path, and
# EXACTLY the should-kill processes die while ZERO innocents are slain. A false
# kill (collateral) is catastrophic, so zero collateral is the pass condition.
#
#   nix-build tests/response-whackamole.nix   (needs KVM; run on hokkaido)
#   nix flake check                            (checks.x86_64-linux.response-whackamole)
#
# SAFETY: enforcement is armed ONLY here, in a throwaway KVM VM, acting solely
# on processes this test spawns. Every victim is a benign process this test
# launches that carries a rule's triggering argv then sleeps (see
# lib/enforce-spawn.nix for the spawn discipline: exec-replace so no launcher
# carries the marker; a trailing ':' so bash does not exec-optimise its sleep
# and change the exe the rule matched). The real hokkaido host and every other
# config leave response.enforce false (dry-run).
#
# The mix, per iteration (randomized order + timing):
#   should-KILL    - a process tripping a kill-mapped rule (reverse_shell,
#                    data_destruction, ... and a /tmp/<x>/sshd MASQUERADE).
#   should-NOT-kill:
#     innocent     - normal commands / sleeps matching no rule.
#     non-kill rule- trips a rule the policy maps to `none` (observe), e.g.
#                    timestomp -> must NOT die.
#     real daemon  - a REAL protected binary refused two ways:
#                    * uid-0: the same kill rule, run as root -> the executor's
#                      live uid-0 rail refuses (allowRoot false).
#                    * trusted path: a binary named `sshd` under /usr (a trusted
#                      exe prefix) -> the denylist shields it (the exact inverse
#                      of the /tmp/<x>/sshd masquerade, which IS killed).
#     pid-reuse    - a victim exits; its freed pid is forced (ns_last_pid) onto
#                    a NEW innocent born after the event -> the executor's
#                    start-time bound refuses it (ErrStaleTarget).
{ pkgs ? import <nixpkgs> { }, banken ? pkgs.callPackage ../package.nix { } }:

let
  lib = pkgs.lib;
  spawnLib = import ./lib/enforce-spawn.nix;

  # Kill-mapped rules (should-kill). Each pinned by exact rule name (a tag-only
  # kill is refused by the policy loader).
  killRules = [
    "reverse_shell"
    "pipe_to_shell"
    "data_destruction"
    "tamper_banken"
    "credential_file_read"
    "download_ip_to_tmp"
    "proc_memory_dump"
    "gtfobin_shell_spawn"
    "setuid_bit_set"
    "disable_logging"
    "masquerading"
  ];
  # Rules the policy explicitly maps to `none`: a process tripping one of these
  # must NOT be killed (the observe/non-kill half of the mix).
  noneRules = [ "timestomp" "network_sniffing" "account_creation" ];

  killYaml = lib.concatMapStrings
    (r: "    - name: kill-${r}\n      rules: [${r}]\n      action: kill\n      scope: process\n")
    killRules;
  noneYaml = lib.concatMapStrings
    (r: "    - name: none-${r}\n      rules: [${r}]\n      action: none\n")
    noneRules;

  policy = ''
    mode: enforce
    minLevel: high
    enforceSources: [auditd, laurel]
    allowRoot: false
    rateLimit:
      perRun: 5000
      perHour: 50000
    actions:
${noneYaml}${killYaml}  '';
in
pkgs.testers.runNixOSTest {
  name = "banken-response-whackamole";

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
    users.users.bob.isNormalUser = true;
    environment.systemPackages = with pkgs; [ procps ];
  };

  testScript = spawnLib + ''
    import json, random

    random.seed(1312)  # fixed so a failure reproduces; order is still interleaved

    def barrier(tag):
        # A user audit record generated last; once it is on disk every earlier
        # execve is too (auditd writes its queue in order). The scan then judges
        # exactly the events spawned this iteration.
        machine.succeed(f"auditctl -m {tag}")
        machine.wait_until_succeeds(f"grep -q {tag} /var/log/audit/audit.log")

    def scan():
        # After the two-process split a scan is the daemon writing orders AND the
        # helper draining them: enf_scan waits for the spool to empty and the
        # helper to go idle, so the kill now lands from banken-respond.service.
        enf_scan()

    def action_lines():
        out = machine.succeed("cat /var/lib/banken/response/actions-*.jsonl 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    def decision_lines():
        out = machine.succeed("cat /var/lib/banken/response/decisions-*.jsonl 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    def executed_kill_pids():
        pids = set()
        for a in action_lines():
            h = a.get("handle") or {}
            if a.get("phase") == "executed" and a.get("action") == "kill":
                if a.get("enforced") is True and h.get("dryRun") is False and h.get("method") == "pidfd":
                    pids.add(str(h.get("pid")))
        return pids

    def failed_kill_line(pid):
        # A refused kill is a FAILED action line naming this pid as its target and
        # carrying the executor's ErrDenied/ErrStaleTarget message -- NOT an
        # executed-kill line. Return the newest such line (ledger ids are
        # time-ordered), or None. This is how a RAIL is proven, vs mere survival.
        hits = [a for a in action_lines()
                if a.get("phase") == "failed" and a.get("action") == "kill"
                and str(((a.get("target") or {}).get("process") or {}).get("pid")) == str(pid)]
        return max(hits, key=lambda a: a["id"]) if hits else None

    def decision_for(pid):
        # The daemon's decided line whose target process is this pid (newest), or
        # None. It carries the rail that downgraded the intended action (a none
        # verdict writes no order, so there is no action line -- the decision line
        # is the only evidence the denylist/other rail fired).
        hits = [d for d in decision_lines()
                if str((((d.get("decision") or {}).get("target") or {}).get("process") or {}).get("pid")) == str(pid)]
        return max(hits, key=lambda d: d["id"]) if hits else None

    machine.wait_for_unit("auditd.service")
    machine.wait_until_succeeds("auditctl -l | grep -q banken-exec")
    enf_scan()  # drain boot-time events (daemon + helper)

    # ---- the should-kill victim shapes (verified offline to trip their rule) ----
    KILL = [
        {"rule": "reverse_shell",        "carrier": "shell", "trigger": ": /dev/tcp/192.0.2.30/4444"},
        {"rule": "pipe_to_shell",        "carrier": "shell", "trigger": "echo curl http://192.0.2.10/x | sh"},
        {"rule": "data_destruction",     "carrier": "image", "image": "dd",        "trigger": "of=/dev/sda bs=1 count=0"},
        {"rule": "tamper_banken",        "carrier": "image", "image": "systemctl", "trigger": "stop banken"},
        {"rule": "credential_file_read", "carrier": "image", "image": "cat",       "trigger": "/etc/shadow"},
        {"rule": "download_ip_to_tmp",   "carrier": "image", "image": "curl",      "trigger": "http://192.0.2.10/x -o /tmp/y"},
        {"rule": "proc_memory_dump",     "carrier": "image", "image": "dd",        "trigger": "if=/proc/1/mem"},
        {"rule": "gtfobin_shell_spawn",  "carrier": "image", "image": "find",      "trigger": "-exec /bin/sh -c true"},
        {"rule": "setuid_bit_set",       "carrier": "image", "image": "chmod",     "trigger": "u+s /tmp/x"},
        {"rule": "disable_logging",      "carrier": "image", "image": "systemctl", "trigger": "stop rsyslog"},
    ]
    # the MASQUERADE that must be KILLED and recorded masquerade:true: a sleeper
    # exec'd as /tmp/<scratch>/sshd (protected NAME, untrusted path).
    MASQ_KILL = {"rule": "masquerading", "carrier": "image", "image": "sshd", "dir": "/tmp/mq"}

    # ---- should-NOT-kill shapes ----
    NONE_RULE = [
        {"label": "timestomp_none",       "carrier": "image", "image": "touch",   "trigger": "-t 200001010000 /tmp/x"},
        {"label": "network_sniffing_none","carrier": "image", "image": "tcpdump", "trigger": ""},
        {"label": "account_creation_none","carrier": "image", "image": "useradd", "trigger": "baduser"},
    ]
    INNOCENT = [
        {"label": "innocent_shell", "carrier": "shell", "trigger": "echo hello world"},
        {"label": "innocent_sleep", "carrier": "image", "image": "myjob", "trigger": ""},  # /run/enf/myjob: no rule keys on it
        {"label": "innocent_bob",   "carrier": "shell", "trigger": "echo ordinary", "user": "bob"},
    ]
    # a REAL protected binary refused by the live uid-0 rail (kill rule, run as root)
    REAL_UID0 = {"label": "real_uid0_root", "carrier": "shell", "trigger": ": /dev/tcp/192.0.2.30/4444", "user": "root"}
    # a REAL protected name under a TRUSTED prefix -> denylist shield (inverse of
    # the masquerade). /usr is a trusted exe prefix; /usr/local/sbin is freely
    # creatable on NixOS, so the copy's realpath is genuinely under /usr.
    REAL_TRUSTED = {"label": "real_trusted_sshd", "carrier": "image", "image": "sshd",
                    "dir": "/usr/local/sbin", "trigger": ": /dev/tcp/192.0.2.31/9"}

    # confirm the trusted prefix is really writable+under /usr before relying on it
    machine.succeed("mkdir -p /usr/local/sbin")

    totals = {"procs": 0, "kills": 0, "collateral": 0}
    masq_seen = {"killed": False, "recorded": False}
    uid0_refused = False
    trusted_refused = False

    def assert_mix(spawned):
        # spawned: list of dicts {pid, shouldKill, label}
        kp = executed_kill_pids()
        for s in spawned:
            alive = enf_alive(s["pid"])
            if s["shouldKill"]:
                if alive:
                    raise Exception(f"SHOULD-KILL survived: {s['label']} pid {s['pid']} (rule {s.get('rule')})")
                totals["kills"] += 1
            else:
                if not alive:
                    totals["collateral"] += 1
                    raise Exception(f"COLLATERAL: innocent {s['label']} pid {s['pid']} was KILLED")
                if s["pid"] in kp:
                    totals["collateral"] += 1
                    raise Exception(f"COLLATERAL (ledger): {s['label']} pid {s['pid']} recorded as killed")
            print(f"  {s['label']:24s} pid {s['pid']:>6} alive={alive} shouldKill={s['shouldKill']}")

    # ================= Phase A: benign-only under kill-all =================
    # Only innocents, under the kill-ALL policy -> zero actions taken.
    before = len(action_lines())
    benign = []
    for spec in INNOCENT:
        c = dict(spec); c["name"] = "A_" + spec["label"]
        benign.append({"pid": enf_spawn(c), "shouldKill": False, "label": spec["label"]})
    barrier("WHACK_BENIGN")
    scan()
    after_lines = action_lines()
    new_exec = [a for a in after_lines[before:] if a.get("phase") == "executed"]
    print(f"[Phase A benign-only] innocents={len(benign)} new executed actions={len(new_exec)}")
    for b in benign:
        if not enf_alive(b["pid"]):
            raise Exception(f"benign-only: innocent {b['label']} pid {b['pid']} was killed")
    assert len(new_exec) == 0, f"benign-only under kill-all took {len(new_exec)} actions, want 0"
    totals["procs"] += len(benign)
    print("[Phase A] PASS: zero actions under kill-all with only innocents")

    # ================= Phase B: N randomized interleaved iterations =================
    N = 3
    for it in range(N):
        print(f"\n[Phase B iteration {it}] building randomized mix")
        mix = []
        for spec in KILL:
            mix.append(("kill", dict(spec)))
        # per-iteration dirs: a surviving (shielded) victim holds its exe busy,
        # so a fixed path would hit ETXTBSY on the next iteration's copy.
        mk = dict(MASQ_KILL); mk["dir"] = f"/tmp/mq{it}"
        mix.append(("kill_masq", mk))
        for spec in NONE_RULE:
            mix.append(("none", dict(spec)))
        for spec in INNOCENT:
            mix.append(("innocent", dict(spec)))
        mix.append(("real_uid0", dict(REAL_UID0)))
        rt = dict(REAL_TRUSTED); rt["dir"] = f"/usr/local/sbin/e{it}"
        mix.append(("real_trusted", rt))
        random.shuffle(mix)

        spawned = []
        for idx, (kind, spec) in enumerate(mix):
            spec["name"] = f"B{it}_{idx}_{kind}"
            # random tiny interleave so spawns are not ordered-by-kind
            if random.random() < 0.5:
                machine.succeed("true")  # jitter point (no real sleep: keep it fast)
            pid = enf_spawn(spec)
            sk = kind in ("kill", "kill_masq")
            label = spec.get("label") or spec.get("rule") or kind
            rec = {"pid": pid, "shouldKill": sk, "label": f"{label}#{it}", "kind": kind, "rule": spec.get("rule")}
            if kind == "kill_masq":
                rec["masq"] = True
            spawned.append(rec)

        barrier(f"WHACK_ITER_{it}")
        scan()
        print(f"[Phase B iteration {it}] asserting {len(spawned)} processes")
        assert_mix(spawned)
        totals["procs"] += len(spawned)

        # masquerade bookkeeping: the /tmp/mq/sshd victim killed + recorded true
        for s in spawned:
            if s.get("masq"):
                if not enf_alive(s["pid"]):
                    masq_seen["killed"] = True
        kp = executed_kill_pids()
        # The /tmp/mqN/sshd victim is the ONLY masquerade in the whole test, so
        # any decision recording masquerade:true is it.
        for d in decision_lines():
            dec = d.get("decision") or {}
            if dec.get("masquerade") is True:
                masq_seen["recorded"] = True
                img = ((dec.get("target") or {}).get("process") or {}).get("image", "?")
                print(f"  masquerade recorded: image={img} action={dec.get('action')} rail={dec.get('rail')}")
        # real-protected refusals: assert the actual RAIL fired, not merely that
        # the process survived (a process can survive for unrelated reasons).
        for s in spawned:
            if s["kind"] == "real_uid0":
                # uid-0 is an EXECUTOR rail: the order is written (reverse_shell ->
                # kill) and the executor refuses the live uid-0 target (allowRoot
                # false) with ErrDenied, so the evidence is a FAILED kill line.
                assert enf_alive(s["pid"]), f"real uid-0 pid {s['pid']} was KILLED (uid-0 rail did not hold)"
                assert s["pid"] not in kp, f"real uid-0 pid {s['pid']} recorded as an executed kill"
                fl = failed_kill_line(s["pid"])
                assert fl is not None, \
                    (f"real uid-0 pid {s['pid']}: no failed-kill ledger line -- survival alone does not "
                     f"prove the uid-0 rail fired")
                err = fl.get("error") or ""
                assert "allowRoot is false" in err, \
                    f"real uid-0 pid {s['pid']} refused for the WRONG reason: want the live uid-0 rail (ErrDenied), got {err!r}"
                uid0_refused = True
            if s["kind"] == "real_trusted":
                # The trusted-prefix shield is a DECIDE rail (denylist): a built-in
                # protected name under a trusted exe prefix downgrades to none, so
                # no order is written and the evidence is the decision line's rail.
                assert enf_alive(s["pid"]), f"real trusted sshd pid {s['pid']} was KILLED (denylist shield did not hold)"
                assert s["pid"] not in kp, f"real trusted sshd pid {s['pid']} recorded as an executed kill"
                dec = decision_for(s["pid"])
                assert dec is not None, f"real trusted sshd pid {s['pid']}: no decision line found to prove the rail"
                dv = dec.get("decision") or {}
                assert dv.get("rail") == "denylist", \
                    (f"real trusted sshd pid {s['pid']} not shielded by the denylist rail: "
                     f"rail={dv.get('rail')!r} action={dv.get('action')!r} intended={dv.get('intended')!r}")
                assert dv.get("action") == "none", \
                    f"real trusted sshd pid {s['pid']} denylist rail did not downgrade to none: action={dv.get('action')!r}"
                trusted_refused = True

    assert masq_seen["killed"], "masquerade /tmp/mq/sshd was NOT killed"
    assert masq_seen["recorded"], "masquerade was NOT recorded masquerade:true in the decision ledger"
    assert uid0_refused, "real uid-0 process was not refused (should survive)"
    assert trusted_refused, "real sshd under a trusted prefix was not refused (should survive)"

    # ================= Phase C: pid-reuse (ErrStaleTarget) =================
    # A victim trips a kill rule then EXITS; its freed pid is forced onto a NEW
    # innocent born > skew after the event. The executor's start-time bound must
    # refuse it (same image, so ONLY the start-time check can refuse): the new
    # process is NOT the one the alert described.
    print("\n[Phase C pid-reuse]")
    import base64 as _b
    alice_uid = machine.succeed("id -u alice").strip()
    alice_gid = machine.succeed("id -g alice").strip()
    machine.succeed("mkdir -p /run/enf && cp $(command -v bash) /run/enf/cat && chmod 0755 /run/enf/cat")
    # The reuser: drops to alice and exec-replaces into the SAME image the alert
    # named, then sleeps. setpriv exec-REPLACES (no fork), so the first fork after
    # writing ns_last_pid -- the backgrounding `&` -- becomes the reuser itself at
    # the freed pid. Same image => the exe-binding passes and the start-time bound
    # is the SOLE thing that can refuse: the reuser started AFTER the event.
    reuse_boot = 'echo $$ > /tmp/enf_reuse_w.pid; exec /run/enf/cat -c "sleep 100000 ; :"'
    rb64 = _b.b64encode(reuse_boot.encode()).decode()

    # Deterministic pid-reuse. A transient victim trips credential_file_read then
    # EXITS, freeing its pid; ns_last_pid forces that exact pid onto the reuser. A
    # stray fork can steal the pid first (then vpid is gone and cannot be reused),
    # so retry with a FRESH victim until the reuser lands on the freed pid. If it
    # cannot be forced, FAIL -- we never pass on a NOTE, or "pid-reuse refused"
    # becomes a claim nobody actually proves.
    vpid = wpid = None
    for attempt in range(20):
        vpf = f"/tmp/enf_reuse_v{attempt}.pid"
        machine.succeed(f"rm -f {vpf} /tmp/enf_reuse_w.pid")
        vboot = f'echo $$ > {vpf}; exec /run/enf/cat -c true /etc/shadow'
        vb64 = _b.b64encode(vboot.encode()).decode()
        machine.succeed(f'( runuser -u alice -- setsid bash -c "$(printf %s {vb64} | base64 -d)" >/dev/null 2>&1 & ) ; true')
        machine.wait_for_file(vpf)
        vpid = machine.succeed(f"cat {vpf}").strip()
        machine.wait_until_fails(f"kill -0 {vpid}")  # it exited; the pid is free
        barrier(f"WHACK_REUSE_EVENT_{attempt}")       # the credential_file_read execve is on disk
        machine.succeed("sleep 3")                    # past the 2s skew: the reuser starts provably after
        machine.succeed(
            f'echo $(({vpid}-1)) > /proc/sys/kernel/ns_last_pid; '
            f'setpriv --reuid={alice_uid} --regid={alice_gid} --clear-groups '
            f'bash -c "$(printf %s {rb64} | base64 -d)" >/dev/null 2>&1 & echo ok'
        )
        machine.wait_for_file("/tmp/enf_reuse_w.pid")
        wpid = machine.succeed("cat /tmp/enf_reuse_w.pid").strip()
        if wpid == vpid:
            break
        machine.succeed(f"kill -9 {wpid} 2>/dev/null || true")  # a stray won the pid; retry with a fresh victim
        wpid = None
    assert wpid is not None and wpid == vpid, \
        ("pid-reuse could not be forced deterministically in 20 attempts (ns_last_pid never landed the "
         "freed pid); FAILING rather than passing on a NOTE")
    print(f"[Phase C] victim pid={vpid} freed; reuser forced onto the SAME pid={wpid}")
    reuse_hit = True
    barrier("WHACK_REUSE_SCAN")
    scan()
    kp = executed_kill_pids()
    assert enf_alive(wpid), f"pid-reuse: reuser pid {wpid} was KILLED (stale target not refused)"
    assert wpid not in kp, f"pid-reuse: reuser pid {wpid} recorded as killed"
    # Prove the RAIL, not just survival: a FAILED kill line for this pid carrying
    # ErrStaleTarget. Same image as the alert, so only the start-time bound can
    # refuse it -- the reuser started after the event.
    fl = failed_kill_line(wpid)
    assert fl is not None, \
        (f"pid-reuse: reuser pid {wpid} survived but has NO failed-kill ledger line -- survival alone "
         f"does not prove the start-time rail fired")
    err = fl.get("error") or ""
    assert "is not the process the alert described" in err, \
        f"pid-reuse: reuser pid {wpid} refused for the WRONG reason: want ErrStaleTarget (start-time bound), got {err!r}"
    print(f"[Phase C] PASS: reused pid {wpid} refused (ErrStaleTarget), reuser alive, failed-kill line asserted")
    machine.succeed(f"kill -9 {wpid} 2>/dev/null || true")

    # ================= Scorecard =================
    print("\n================ WHACK-A-MOLE RESULT ================")
    print(f"total processes spawned : {totals['procs']}")
    print(f"kills (should-kill dead): {totals['kills']}")
    print(f"collateral (MUST be 0)  : {totals['collateral']}")
    print(f"masquerade /tmp/mq/sshd : killed={masq_seen['killed']} recorded_masquerade_true={masq_seen['recorded']}")
    print(f"real uid-0 refused      : {uid0_refused}")
    print(f"real sshd(/usr) refused : {trusted_refused}")
    print("pid-reuse refused       : yes (ErrStaleTarget, reuser alive, failed-kill line asserted)")
    assert totals["collateral"] == 0, "COLLATERAL KILLS OCCURRED"
    print("WHACK-A-MOLE PASS: exactly the should-kill died, zero innocents slain.")
  '';
}
