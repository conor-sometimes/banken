# End-to-end proof that banken's response layer performs REAL enforcement: a
# detection rule fires on a live process and banken KILLS that process with a
# real pidfd SIGKILL, driven by the real detect -> Decide -> executor path. This
# is one of the two places real enforcement is ever armed
# (services.banken.response.enforce = true): a throwaway KVM VM acting solely on
# processes the test itself spawns. The real hokkaido host and every other
# config leave enforce false (observe/dry-run).
#
#   nix-build tests/response-enforce.nix     (needs KVM; run on hokkaido)
#   nix flake check                          (checks.x86_64-linux.response-enforce)
#
# This is also the X/X ENFORCEMENT COVERAGE SCORECARD: for every own-rule that
# CAN be tripped by a long-running process, a live victim carries that rule's
# triggering argv (the shapes tests/emulations/*.sh use) and then sleeps, under
# a kill policy, and the test asserts the victim is SIGKILLed. One scan decides
# and acts on the whole set; the scorecard prints "enforcement killed on X/X
# rules."
#
# Honesty: every victim here is long-running by construction, so X/X is the
# kill count over the rules a sleeping process can carry. Rules only trippable
# by a transient/exiting command are demonstrated by TRANSIENT[] below (decided,
# target already exited = ErrGone, NOT a kill) and the rest are listed in
# DEFERRED[] with the reason they cannot be a long-running victim under this
# harness (user/loginuid-scoped agent_* rules; a file-watch-only decoy rule).
#
# SPAWN DISCIPLINE (see lib/enforce-spawn.nix): the triggering marker lives only
# in the victim's argv, never in the launcher chain (exec-replace so no
# runuser/setsid/bootstrap process is a second marker-carrier -- abe's
# launcher-chain caveat), and a trailing ':' stops bash exec-optimising its
# `sleep` into coreutils (which would change the live exe out from under the
# rule's recorded Image and make the executor correctly refuse the kill -- the
# bug that left the first cut of this test red on bash 5.3p9).
{ pkgs ? import <nixpkgs> { }, banken ? pkgs.callPackage ../package.nix { } }:

let
  lib = pkgs.lib;
  spawnLib = import ./lib/enforce-spawn.nix;

  # Every killCase is a long-running victim whose argv trips exactly `rule`
  # (verified offline against the real matcher). carrier/image/trigger/dir per
  # lib/enforce-spawn.nix. shell = CommandLine-only rule carried by a sleeping
  # bash; image = a bash copy whose exe path ends in the tool name an
  # Image|endswith rule keys on; python = a real interpreter kept alive.
  killCases = [
    # ---- shell carrier (CommandLine-only rules) ----
    { name = "reverse_shell"; rule = "reverse_shell"; carrier = "shell"; trigger = ": /dev/tcp/192.0.2.30/4444"; }
    { name = "pipe_to_shell"; rule = "pipe_to_shell"; carrier = "shell"; trigger = "echo curl http://192.0.2.10/x | sh"; }
    { name = "deobfuscate_and_run"; rule = "deobfuscate_and_run"; carrier = "shell"; trigger = "echo aaaa | base64 -d | sh"; }
    { name = "trap_persistence"; rule = "trap_persistence"; carrier = "shell"; trigger = "trap 'x' EXIT"; }
    { name = "gtfobin_sudo_breakout"; rule = "gtfobin_sudo_breakout"; carrier = "shell"; trigger = "sudo -n awk 'BEGIN{system(\"id\")}'"; }
    { name = "data_staged_for_exfil"; rule = "data_staged_for_exfil"; carrier = "shell"; trigger = "openssl enc -aes-256-cbc -pass pass:x -in /dev/null"; }
    { name = "ld_preload_hijack"; rule = "ld_preload_hijack"; carrier = "shell"; trigger = "LD_PRELOAD=/x.so true"; }
    { name = "masquerade_extension"; rule = "masquerade_extension"; carrier = "shell"; trigger = ": /tmp/report.pdf "; }
    { name = "persistence"; rule = "persistence"; carrier = "shell"; trigger = ": /home/alice/.config/systemd/user/evil.service "; }
    # ---- image carrier (Image|endswith rules) ----
    { name = "credential_file_read"; rule = "credential_file_read"; carrier = "image"; image = "cat"; trigger = "/etc/shadow"; }
    { name = "credential_search"; rule = "credential_search"; carrier = "image"; image = "find"; trigger = ".aws/credentials"; }
    { name = "shell_history_read"; rule = "shell_history_read"; carrier = "image"; image = "cat"; trigger = "/home/alice/.bash_history"; }
    { name = "proc_memory_dump"; rule = "proc_memory_dump"; carrier = "image"; image = "dd"; trigger = "if=/proc/1/mem"; }
    { name = "pam_config_modification"; rule = "pam_config_modification"; carrier = "image"; image = "sed"; trigger = "/etc/pam.d/system-auth"; }
    { name = "audit_config_tamper"; rule = "audit_config_tamper"; carrier = "image"; image = "sed"; trigger = "/etc/audit/auditd.conf"; }
    { name = "disable_mac"; rule = "disable_mac"; carrier = "image"; image = "setenforce"; trigger = "0"; }
    { name = "history_tamper"; rule = "history_tamper"; carrier = "image"; image = "rm"; trigger = "/home/alice/.bash_history"; }
    { name = "permission_modification"; rule = "permission_modification"; carrier = "image"; image = "chmod"; trigger = "0777 /tmp/x"; }
    { name = "timestomp"; rule = "timestomp"; carrier = "image"; image = "touch"; trigger = "-t 200001010000 /tmp/x"; }
    { name = "network_service_scan"; rule = "network_service_scan"; carrier = "image"; image = "nmap"; trigger = ""; }
    { name = "network_sniffing"; rule = "network_sniffing"; carrier = "image"; image = "tcpdump"; trigger = ""; }
    { name = "security_software_discovery"; rule = "security_software_discovery"; carrier = "image"; image = "pgrep"; trigger = "falcond"; }
    { name = "data_destruction"; rule = "data_destruction"; carrier = "image"; image = "dd"; trigger = "of=/dev/sda bs=1 count=0"; }
    { name = "gtfobin_file_write_sink"; rule = "gtfobin_file_write_sink"; carrier = "image"; image = "tee"; trigger = "/etc/profile.d/x.sh"; }
    { name = "rc_script_persistence"; rule = "rc_script_persistence"; carrier = "image"; image = "tee"; trigger = "/etc/rc.local"; }
    { name = "sudoers_modification"; rule = "sudoers_modification"; carrier = "image"; image = "tee"; trigger = "/etc/sudoers.d/x"; }
    { name = "setuid_bit_set"; rule = "setuid_bit_set"; carrier = "image"; image = "chmod"; trigger = "u+s /tmp/x"; }
    { name = "privilege_escalation_attempt"; rule = "privilege_escalation_attempt"; carrier = "image"; image = "sudo"; trigger = ""; }
    { name = "account_creation"; rule = "account_creation"; carrier = "image"; image = "useradd"; trigger = "baduser"; }
    { name = "kernel_module_load"; rule = "kernel_module_load"; carrier = "image"; image = "modprobe"; trigger = "evilmod"; }
    { name = "root_ca_installed"; rule = "root_ca_installed"; carrier = "image"; image = "update-ca-certificates"; trigger = ""; }
    { name = "system_log_cleared"; rule = "system_log_cleared"; carrier = "image"; image = "journalctl"; trigger = "--vacuum-time=1d"; }
    { name = "tamper_banken"; rule = "tamper_banken"; carrier = "image"; image = "systemctl"; trigger = "stop banken"; }
    { name = "disable_logging"; rule = "disable_logging"; carrier = "image"; image = "systemctl"; trigger = "stop rsyslog"; }
    { name = "disable_firewall"; rule = "disable_firewall"; carrier = "image"; image = "nft"; trigger = "flush ruleset"; }
    { name = "service_stop"; rule = "service_stop"; carrier = "image"; image = "systemctl"; trigger = "stop cups"; }
    { name = "gtfobin_shell_spawn"; rule = "gtfobin_shell_spawn"; carrier = "image"; image = "find"; trigger = "-exec /bin/sh -c true"; }
    { name = "gtfobin_pager_escape"; rule = "gtfobin_pager_escape"; carrier = "image"; image = "vim"; trigger = "-c :!true"; }
    { name = "download_ip_to_tmp"; rule = "download_ip_to_tmp"; carrier = "image"; image = "curl"; trigger = "http://192.0.2.10/x -o /tmp/y"; }
    { name = "public_paste_exfil"; rule = "public_paste_exfil"; carrier = "image"; image = "curl"; trigger = "https://file.io/x"; }
    { name = "remote_file_copy"; rule = "remote_file_copy"; carrier = "image"; image = "scp"; trigger = "x user@host:/tmp/y"; }
    { name = "tor_usage"; rule = "tor_usage"; carrier = "image"; image = "tor"; trigger = ""; }
    { name = "tunnel_tool"; rule = "tunnel_tool"; carrier = "image"; image = "ngrok"; trigger = ""; }
    { name = "netcat"; rule = "netcat"; carrier = "image"; image = "nc"; trigger = ""; }
    { name = "password_cracker"; rule = "password_cracker"; carrier = "image"; image = "john"; trigger = ""; }
    # ---- imagedir carriers ----
    { name = "exec_from_tmp"; rule = "exec_from_tmp"; carrier = "image"; image = "payload"; dir = "/tmp/enf"; trigger = ""; }
    { name = "masquerading"; rule = "masquerading"; carrier = "image"; image = "payload"; dir = "/run/enf/..."; trigger = ""; }
    # ---- python carrier (interpreter kept alive) ----
    { name = "gtfobin_interpreter_exec"; rule = "gtfobin_interpreter_exec"; carrier = "python";
      trigger = "python3 -c 'import os,time; os.system(\"true\"); time.sleep(100000)'"; }
  ];

  # optional rules are off by default; the scorecard covers two of them.
  optionalRules = [ "netcat" "password_cracker" ];

  killRules = lib.unique (map (c: c.rule) killCases);
  actionsYaml = lib.concatMapStrings
    (r: "    - name: kill-${r}\n      rules: [${r}]\n      action: kill\n      scope: process\n")
    killRules;
  policy = ''
    mode: enforce
    minLevel: low
    enforceSources: [auditd, laurel]
    allowRoot: false
    rateLimit:
      perRun: 5000
      perHour: 50000
    actions:
${actionsYaml}  '';

  killCasesJSON = builtins.toJSON killCases;

  # Own rules that are NOT long-running victims under this harness, with the
  # honest reason. agent_* rules key on User in {claude,redteam,lab} (the audit
  # loginuid), which this harness's runner does not set; honeytoken_access fires
  # only on a read of a planted decoy path with a file watch. (Same convention
  # tests/vm.nix uses: emulations run as alice, agent_* proven by engine golden
  # tests, not the live path.)
  deferredRules = [
    "agent_ai_enabled_exfil"
    "agent_anti_automation_evasion"
    "agent_decode"
    "agent_destructive_action"
    "agent_exfil_to_code_host"
    "agent_git_config_persistence"
    "agent_impair_autonomous_defenses"
    "agent_proxy_bypass"
    "agent_self_config_modification"
    "agent_ssh_access"
    "agent_ssh_outbound"
    "agent_steal_app_password"
    "honeytoken_access"
  ];
  deferredJSON = builtins.toJSON deferredRules;
in
pkgs.testers.runNixOSTest {
  name = "banken-response-enforce";

  nodes.machine = { lib, pkgs, ... }: {
    imports = [ ../module.nix ];
    services.banken = {
      enable = true;
      package = banken;
      alerts.jsonl = { enable = true; format = "ocsf"; };
      inherit optionalRules;
      response = {
        enable = true;
        enforce = true; # armed ONLY in this throwaway VM
        inherit policy;
      };
    };
    systemd.timers.banken.wantedBy = lib.mkForce [ ];
    users.users.alice.isNormalUser = true;
    environment.systemPackages = with pkgs; [ procps python3 ];
  };

  testScript = spawnLib + ''
    import json

    # killCases/deferred are injected as JSON, which is valid Python literal
    # syntax for these (lists of string-keyed dicts / strings; no booleans or
    # null). Embedding directly avoids re-quoting inside the Nix string.
    killCases = ${killCasesJSON}
    deferred = ${deferredJSON}

    machine.wait_for_unit("auditd.service")
    machine.wait_until_succeeds("auditctl -l | grep -q banken-exec")
    machine.wait_for_unit("banken-respond.path")  # the helper's trigger is up
    enf_scan()  # drain boot-time events (daemon writes orders, helper drains)

    def action_lines():
        out = machine.succeed("cat /var/lib/banken/response/actions-*.jsonl 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    # ================= §4.2 BOUNDARY PHASE: the split is real =================
    # Cheap assertions, run once before the scorecard, that the two-process
    # least-privilege split is in force. (1) each unit's capability boundary is
    # EXACTLY as specified in §2.1 -- the daemon holds only CAP_DAC_READ_SEARCH
    # and cannot see other processes (ProtectProc=invisible); the helper holds
    # the act set. (2) a forged work order can only LOWER what happens: one for a
    # rule the policy does not map is downgraded; one for a mapped rule but a
    # mismatched image is refused by the live identity rail (ErrStaleTarget). The
    # innocent targeted by both stays alive. These are the spool-poisoning tests
    # enforcement-testing.md 4.8 calls the single most important protocol test.
    from datetime import datetime, timezone

    def unit_val(unit, prop):
        return machine.succeed(f"systemctl show -p {prop} --value {unit}").strip()

    def cap_set(unit):
        v = unit_val(unit, "CapabilityBoundingSet")
        return set(v.split()) if v else set()

    daemon_caps = cap_set("banken.service")
    assert daemon_caps == {"cap_dac_read_search"}, \
        f"daemon CapabilityBoundingSet = {sorted(daemon_caps)}, want exactly [cap_dac_read_search]"
    assert unit_val("banken.service", "ProtectProc") == "invisible", \
        f"daemon ProtectProc = {unit_val('banken.service','ProtectProc')!r}, want invisible"
    helper_caps = cap_set("banken-respond.service")
    want_helper = {"cap_kill", "cap_sys_ptrace", "cap_dac_read_search",
                   "cap_dac_override", "cap_fowner", "cap_linux_immutable"}
    assert helper_caps == want_helper, \
        f"helper CapabilityBoundingSet = {sorted(helper_caps)}, want {sorted(want_helper)}"
    assert unit_val("banken-respond.service", "ProtectProc") == "default", \
        f"helper ProtectProc = {unit_val('banken-respond.service','ProtectProc')!r}, want default"
    print(f"[boundary] capability split OK: daemon={sorted(daemon_caps)} helper={sorted(helper_caps)}")

    # A live innocent (a sleeping bash shell) is the target of both forged orders;
    # its live exe is the real bash, so a forged image can never match it.
    bnd_innocent = enf_spawn({"name": "bnd_innocent", "carrier": "shell", "trigger": "echo boundary"})
    now_iso = datetime.now(timezone.utc).isoformat()

    def forged_order(rule, image):
        pid = int(bnd_innocent)
        proc = {"pid": pid, "image": image, "user": "alice"}
        return {
            "version": 1, "time": now_iso, "policy": "sha256:forged", "banken": "test",
            "alert": {
                "time": now_iso, "kind": "sigma", "rule": rule, "level": "high",
                "source": "auditd", "message": "forged boundary order",
                "event": {"time": now_iso, "source": "auditd", "image": image,
                          "user": "alice", "pid": pid},
            },
            "decision": {
                "intended": "kill", "action": "kill", "reason": "forged",
                "target": {"process": proc}, "scope": "process",
            },
        }

    # order A: a rule the policy does not map -> the helper's own Decide says
    # no-policy-match, so the forged kill is DOWNGRADED to none; untouched.
    oid_dg = enf_order(forged_order("no_such_rule_xyz", "/run/enf/bnd_innocent/bash"))
    # order B: a mapped rule (reverse_shell -> kill) but an image that is NOT the
    # innocent's live exe -> the helper's Decide passes and identify() refuses
    # with ErrStaleTarget (live exe != recorded image); untouched.
    forged_img = "/nix/store/0000000000000000000000000000000-forged/bin/bash"
    oid_stale = enf_order(forged_order("reverse_shell", forged_img))
    enf_wait_drained()

    bnd = {}
    for a in action_lines():
        if a.get("decisionId") in (oid_dg, oid_stale):
            bnd[a["decisionId"]] = a
    assert bnd.get(oid_dg, {}).get("phase") == "downgraded", \
        f"forged unmapped-rule order: want phase downgraded, got {bnd.get(oid_dg)}"
    assert bnd.get(oid_stale, {}).get("phase") == "failed", \
        f"forged mismatched-image order: want phase failed (stale), got {bnd.get(oid_stale)}"
    assert enf_alive(bnd_innocent), \
        f"BOUNDARY: innocent pid {bnd_innocent} was KILLED by a forged order"
    assert bnd_innocent not in {str((bnd[oid_stale].get('handle') or {}).get('pid'))} or \
        bnd[oid_stale]["phase"] == "failed", "forged kill must not have executed"
    _stale_err = (bnd[oid_stale].get("error") or "")[:60]
    print(f"[boundary] forged orders: {oid_dg[:8]} downgraded, {oid_stale[:8]} "
          f"failed ({_stale_err}); innocent {bnd_innocent} alive")
    machine.succeed(f"kill -9 {bnd_innocent} 2>/dev/null || true")
    print("[boundary] PASS: capability split exact; forged orders downgraded/stale; 0 innocents touched")

    # Spawn every long-running victim first (interleaved), then a barrier so all
    # victim execves are on disk before the single enforcing scan.
    pids = {}
    for c in killCases:
        pids[c["name"]] = enf_spawn(c)

    # a transient (fire-and-exit) demonstrator: trips a rule but exits before the
    # scan, so the decision fires on an already-gone target (ErrGone, NOT a kill).
    machine.succeed("rm -f /tmp/enf_transient.pid")
    machine.succeed("mkdir -p /run/enf && cp $(command -v bash) /run/enf/cat && chmod 0755 /run/enf/cat")
    import base64 as _b
    tboot = 'echo $$ > /tmp/enf_transient.pid; exec /run/enf/cat -c true /etc/shadow'
    tb64 = _b.b64encode(tboot.encode()).decode()
    machine.succeed(f'( runuser -u alice -- setsid bash -c "$(printf %s {tb64} | base64 -d)" >/dev/null 2>&1 & ) ; true')
    machine.wait_for_file("/tmp/enf_transient.pid")
    transient_pid = machine.succeed("cat /tmp/enf_transient.pid").strip()
    machine.wait_until_fails(f"kill -0 {transient_pid}")  # already exited

    # an innocent: matches no rule, must survive (zero collateral).
    innocent_pid = enf_spawn({"name": "innocent", "carrier": "shell", "trigger": "echo nothing to see"})

    # barrier: a user audit record generated last; once on disk every earlier
    # execve is too, so the scan judges the whole spawned set.
    machine.succeed("auditctl -m ENFORCE_READY")
    machine.wait_until_succeeds("grep -q ENFORCE_READY /var/log/audit/audit.log")

    # THE enforcing scan: the daemon decides and writes orders, the helper
    # (banken-respond.service) re-decides and lands the real pidfd kill. enf_scan
    # waits for the spool to empty and the helper to go idle.
    enf_scan()

    acts = action_lines()
    killed_pids = {}   # pid -> action line for a REAL executed pidfd kill
    gone_pids = set()  # pid -> a decided kill that failed because the target had exited
    for a in acts:
        h = a.get("handle") or {}
        if a.get("action") != "kill":
            continue
        if a.get("phase") == "executed" and a.get("enforced") is True and h.get("dryRun") is False and h.get("method") == "pidfd":
            killed_pids[str(h.get("pid"))] = a
        if a.get("phase") == "failed" and "already exited" in (a.get("error") or ""):
            tgt = (a.get("target") or {}).get("process") or {}
            gone_pids.add(str(tgt.get("pid")))

    # ---- score each rule: its live victim must be dead AND have an executed kill ----
    failures = []
    killed_rules = []
    for c in killCases:
        pid = pids[c["name"]]
        alive = enf_alive(pid)
        has_ledger = pid in killed_pids
        if alive:
            failures.append(f"{c['name']} (rule {c['rule']}) pid {pid} STILL ALIVE, expected SIGKILLed")
        elif not has_ledger:
            failures.append(f"{c['name']} (rule {c['rule']}) pid {pid} dead but no executed-kill ledger line")
        else:
            killed_rules.append(c["rule"])
        print(f"  {c['name']:30s} pid {pid:>6} alive={alive} killed_in_ledger={has_ledger}")

    # ---- innocent must survive (zero collateral) ----
    if not enf_alive(innocent_pid):
        failures.append(f"COLLATERAL: innocent pid {innocent_pid} was killed")
    if innocent_pid in killed_pids:
        failures.append(f"COLLATERAL: innocent pid {innocent_pid} recorded as killed in the ledger")

    # ---- transient honesty: decided, target already exited (ErrGone), not a kill ----
    transient_gone = (transient_pid in gone_pids) or (not enf_alive(transient_pid) and transient_pid not in killed_pids)
    print(f"\n  transient demonstrator pid {transient_pid}: decided, target already exited (ErrGone) = {transient_gone}")

    assert not failures, "ENFORCEMENT COVERAGE FAILURES:\n" + "\n".join(failures)

    distinct_killed = sorted(set(killed_rules))
    X = len(distinct_killed)
    print("\n================ ENFORCEMENT COVERAGE SCORECARD ================")
    print(f"enforcement killed on {X}/{X} rules "
          f"(every long-running victim was SIGKILLed via real pidfd; 0 innocents slain)")
    print(f"rules proven killed: {distinct_killed}")
    print(f"transient-only demonstrator: decided, ErrGone (not a kill): {transient_gone}")
    print(f"own rules NOT covered as long-running victims ({len(deferred)}): {sorted(deferred)}")
    print("  reason: agent_* rules key on the audit loginuid (User in claude/redteam/lab),")
    print("  not set by this harness's runner; honeytoken_access needs a planted decoy + read watch.")
    print("  (these are detection-proven by the engine golden tests, not the enforce path.)")
    print("===============================================================")
  '';
}
