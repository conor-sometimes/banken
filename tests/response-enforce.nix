# End-to-end proof that banken's response layer performs a REAL enforcement
# action: a detection rule fires on a live process and banken KILLS that
# process with a real SIGKILL, driven by the real detect -> Decide -> execute
# path. This is the ONLY place real enforcement is ever armed
# (services.banken.response.enforce = true): a throwaway KVM VM, acting solely
# on processes the test itself spawns. The real hokkaido host and every other
# test leave enforce false (observe/dry-run).
#
#   nix-build tests/response-enforce.nix     (needs KVM; uses <nixpkgs> unless pkgs is passed)
#   nix flake check                          (the same test, as checks.x86_64-linux.response-enforce)
#
# SAFETY: every victim is a benign process this test launches as an ordinary
# user (alice) that carries a rule's triggering argv and then sleeps, so it is
# alive to be killed. No real or system process is ever a target: the policy's
# rails (minLevel, enforceSources, the built-in denylist) and banken's own
# identity checks stand between an alert and a kill, and the test only asserts
# on its own spawned pids.
#
# Harness shape (built to be EXTENDED by the follow-up enforcement-coverage /
# whack-a-mole stress phase): the process set is a parametrized `cases` list of
# {name, user, trigger, rule, shouldKill}. A helper spawns each as a live
# process carrying the triggering argv (the same shapes tests/emulations/*.sh
# use to trip a rule), then one banken scan decides and acts on all of them at
# once. A follow-up can grow `cases` (and the policy's kill map) to the whole
# emulation set and report an "enforcement killed on X/X rules" scorecard
# without touching the harness.
{ pkgs ? import <nixpkgs> { }, banken ? pkgs.callPackage ../package.nix { } }:

pkgs.testers.runNixOSTest {
  name = "banken-response-enforce";

  nodes.machine = { lib, pkgs, ... }: {
    imports = [ ../module.nix ];
    services.banken = {
      enable = true;
      package = banken;
      alerts.jsonl = { enable = true; format = "ocsf"; };
      response = {
        enable = true;
        # THE one place real enforcement is armed. Throwaway VM only.
        enforce = true;
        # Two kill rules, each pinned by rule name (kill must be rule-pinned, never
        # tag-only). Process scope: one SIGKILL of the matched pid, the simplest
        # primitive to prove first. observe-mode default is overridden to enforce
        # here, which only matters because the executor is also armed above.
        policy = ''
          mode: enforce
          minLevel: high
          enforceSources: [auditd, laurel]
          rateLimit:
            perRun: 50
            perHour: 500
          actions:
            - name: kill-reverse-shell
              rules: [reverse_shell]
              action: kill
              scope: process
            - name: kill-pipe-to-shell
              rules: [pipe_to_shell]
              action: kill
              scope: process
        '';
      };
    };
    # The test drives each scan itself, so a scan lands after the victims spawn.
    systemd.timers.banken.wantedBy = lib.mkForce [ ];

    users.users.alice.isNormalUser = true;
    environment.systemPackages = with pkgs; [ procps curl ];
  };

  testScript = ''
    import json

    # Parametrized process set. Each case spawns ONE long-lived process whose argv
    # carries the triggering shape of `rule` (or none, for an innocent), then the
    # single enforcing scan decides+acts on all of them. shouldKill is the
    # assertion. Extend this list (and the module policy above) to grow the
    # enforcement-coverage scorecard.
    #   trigger: a shell snippet whose presence in the bash argv trips `rule`.
    #            192.0.2.x is TEST-NET-1 (RFC5737), unroutable: nothing leaves.
    cases = [
        {"name": "revshell_alice", "user": "alice",
         "trigger": ": /dev/tcp/192.0.2.30/4444",
         "rule": "reverse_shell", "shouldKill": True},
        {"name": "pipe_alice", "user": "alice",
         "trigger": "echo curl http://192.0.2.10/x | sh",
         "rule": "pipe_to_shell", "shouldKill": True},
        {"name": "innocent_alice", "user": "alice",
         "trigger": "true",
         "rule": "", "shouldKill": False},
    ]

    machine.wait_for_unit("auditd.service")
    machine.wait_until_succeeds("auditctl -l | grep -q banken-exec")

    # Drain boot-time audit events so the enforcing scan judges only the victims.
    machine.succeed("systemctl start banken.service")

    def spawn(case):
        # Launch a detached, long-lived process as `user`. It records its own pid
        # ($$ of the bash that carries the triggering argv) and then sleeps, so the
        # exact process the rule matched is still alive when banken acts. setsid +
        # background (the switch.nix pattern) keeps it alive past this command.
        pidfile = f"/tmp/enf_{case['name']}.pid"
        machine.succeed(f"rm -f {pidfile}")
        body = f"echo $$ > {pidfile}; {case['trigger']}; sleep 100000"
        pre = "" if case["user"] == "root" else f"runuser -u {case['user']} -- "
        machine.succeed(f"({pre}setsid bash -c '{body}' >/dev/null 2>&1 &) ; true")
        machine.wait_for_file(pidfile)
        pid = machine.succeed(f"cat {pidfile}").strip()
        machine.succeed(f"kill -0 {pid}")  # alive before the scan
        return pid

    # Spawn the whole set first (interleaved, like the future stress phase), then
    # make sure the audit records are on disk before the single enforcing scan.
    pids = {}
    for c in cases:
        pids[c["name"]] = spawn(c)
    machine.wait_until_succeeds("grep -q 'dev/tcp' /var/log/audit/audit.log")

    # The enforcing scan: detect -> Decide -> executor. Synchronous, so by the
    # time the oneshot returns every decided kill has been attempted.
    machine.succeed("systemctl start banken.service")

    def alive(pid):
        return machine.succeed(f"kill -0 {pid} 2>/dev/null && echo yes || echo no").strip() == "yes"

    # Assert each case: a should-kill victim is gone (real SIGKILL), a should-not
    # survivor is untouched (zero collateral).
    failures = []
    for c in cases:
        pid = pids[c["name"]]
        if c["shouldKill"] and alive(pid):
            failures.append(f"{c['name']} (rule {c['rule']}) pid {pid} STILL ALIVE, expected killed")
        if not c["shouldKill"] and not alive(pid):
            failures.append(f"{c['name']} pid {pid} was KILLED, expected to survive (collateral)")
        print(f"{c['name']}: pid {pid} alive={alive(pid)} shouldKill={c['shouldKill']}")

    # The ledger records each real kill: an executed action line, enforced (not a
    # dry-run), method pidfd, and the handle pid matching the victim. This proves
    # the pidfd identity was held to the pid banken intended.
    def action_lines():
        out = machine.succeed("cat /var/lib/banken/response/actions-*.jsonl 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    acts = action_lines()
    killed_in_ledger = {}
    for a in acts:
        h = a.get("handle") or {}
        if a.get("phase") == "executed" and a.get("action") == "kill":
            assert a.get("enforced") is True, f"ledger kill not enforced (dry-run?): {a}"
            assert h.get("dryRun") is False, f"ledger kill handle is dry-run: {a}"
            assert h.get("method") == "pidfd", f"unexpected kill method: {a}"
            killed_in_ledger[str(h.get("pid"))] = a

    for c in cases:
        pid = pids[c["name"]]
        if c["shouldKill"] and pid not in killed_in_ledger:
            failures.append(f"{c['name']} pid {pid} has no executed-kill ledger line")
        if not c["shouldKill"] and pid in killed_in_ledger:
            failures.append(f"{c['name']} pid {pid} was recorded as killed in the ledger")

    assert not failures, "ENFORCEMENT FAILURES:\n" + "\n".join(failures)

    killed = sum(1 for c in cases if c["shouldKill"])
    print(f"ENFORCE PROOF PASS: banken KILLED {killed}/{killed} rule-matched live "
          f"process(es) via real pidfd SIGKILL; {len(cases) - killed} innocent process(es) "
          f"untouched; ledger recorded every kill. rules proven: "
          f"{sorted({c['rule'] for c in cases if c['shouldKill']})}")
  '';
}
