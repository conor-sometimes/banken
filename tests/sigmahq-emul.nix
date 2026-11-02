# End-to-end test that banken detects the UPSTREAM SigmaHQ Linux ruleset -- not
# banken's own embedded rules (those are tests/vm.nix), but the pinned SigmaHQ
# release the project measures coverage against (justfile sigma_release). This
# is the harness behind Conor's "ultimate testing" goal: for a SigmaHQ Linux
# rule, a benign bash emulation (tests/emulations/sigmahq_*.sh) performs the
# harmless analogue of the abuse as an ordinary user, banken runs with the whole
# SigmaHQ Linux set loaded on top of its baseline, and the test asserts THAT
# NAMED SigmaHQ rule fires -- and that nothing else in the SigmaHQ set does.
#
# A rule's name is its file basename without .yml (internal/sigma: rule.Name),
# so e.g. proc_creation_lnx_nohup.yml fires as "proc_creation_lnx_nohup".
#
#   nix-build tests/sigmahq-emul.nix     (needs KVM; uses <nixpkgs> unless pkgs is passed)
#
# Scope / "nothing wild" note: with the whole SigmaHQ Linux set loaded against a
# live host's audit stream, background system activity (systemd, the banken
# scan itself, tmpfiles) nondeterministically trips a handful of auditd-logsource
# and network_connection rules -- they fire even on the benign baseline. Those
# are not caused by the emulations. The emulations, by contrast, act purely
# through process execs, so the rules THEY cause are all process_creation
# (proc_creation_lnx_*). This test therefore:
#   * gates hard on the process_creation layer: the named SigmaHQ rule MUST fire,
#     and no OTHER process_creation rule may fire beyond a small, documented set
#     of background-noise rules (a stray system `rm` trips file_deletion);
#   * subtracts the benign baseline's firings as the ambient floor, and reports
#     (does not gate) the remaining auditd/network rules -- these are either that
#     ambient noise or legitimate "twin" detections of the same behaviour by an
#     auditd-logsource rule (e.g. lnx_auditd_coinminer alongside the
#     process_creation crypto_mining rule), i.e. bonus coverage, not wild hits.
# banken's own baseline rules are tests/vm.nix's concern and are only reported.
{ pkgs ? import <nixpkgs> { }, banken ? pkgs.callPackage ../package.nix { } }:

let
  lib = pkgs.lib;

  # SigmaHQ at the release the justfile pins (r2026-07-01). fetchFromGitHub so
  # the test is hermetic; the rev is the tag's commit.
  sigma = pkgs.fetchFromGitHub {
    owner = "SigmaHQ";
    repo = "sigma";
    rev = "552f3fee420ef232a8e5790c4fae591847e32347"; # tag r2026-07-01
    sha256 = "1k5rl0xc14zxpyj8d0nqvzgr757fhqhfj8c5jlv61ikx0dqh9gli";
  };

  # The Linux rule tree as its own store path, used BOTH as banken's extra rule
  # dir and as the authoritative list of SigmaHQ rule names the test enumerates,
  # so the two can never disagree about which rules were in play.
  sigmaLinux = pkgs.runCommand "sigma-linux-rules" { } ''
    cp -r ${sigma}/rules/linux $out
  '';

  # family (tests/emulations/sigmahq_<family>.sh) -> the SigmaHQ Linux rule
  # name(s) its benign trigger must make fire, and no other SigmaHQ rule.
  # sigmahq_benign is the false-positive guard: it must fire nothing.
  expected = {
    sigmahq_nohup = [ "proc_creation_lnx_nohup" ];
    sigmahq_crontab_enum = [ "proc_creation_lnx_crontab_enumeration" ];
    sigmahq_sysinfo = [ "proc_creation_lnx_system_info_discovery" ];
    sigmahq_netconn = [ "proc_creation_lnx_system_network_connections_discovery" ];
    sigmahq_netdiscovery = [ "proc_creation_lnx_system_network_discovery" ];
    sigmahq_mkfifo = [ "proc_creation_lnx_mkfifo_named_pipe_creation" ];
    sigmahq_base64_decode = [ "proc_creation_lnx_base64_decode" ];
    sigmahq_chattr = [ "proc_creation_lnx_chattr_immutable_removal" ];
    sigmahq_find = [ "proc_creation_lnx_file_and_directory_discovery" ];
    sigmahq_cryptomine = [ "proc_creation_lnx_crypto_mining" ];
    sigmahq_sensitive_file = [ "proc_creation_lnx_susp_sensitive_file_access" ];
    sigmahq_remote_discovery = [ "proc_creation_lnx_remote_system_discovery" ];
    sigmahq_touch_timestomp = [ "proc_creation_lnx_touch_susp" ];
    sigmahq_getcap = [ "proc_creation_lnx_capa_discovery" ];
    sigmahq_usermod_group = [ "proc_creation_lnx_usermod_susp_group" ];
    sigmahq_file_deletion = [ "proc_creation_lnx_file_deletion" ];

    # Batch 2 -- more process_creation rules. Each is a distinctive binary or
    # flag combination an unprivileged user can run benignly (most fail safely
    # with EPERM/no-op but still carry the execve indicator the rule keys on).
    sigmahq_doas = [ "proc_creation_lnx_doas_execution" ];
    sigmahq_at = [ "proc_creation_lnx_at_command" ];
    sigmahq_groupdel = [ "proc_creation_lnx_groupdel" ];
    sigmahq_userdel = [ "proc_creation_lnx_userdel" ];
    sigmahq_setcap = [ "proc_creation_lnx_cap_setuid" "proc_creation_lnx_cap_setgid" ];
    sigmahq_capsh = [ "proc_creation_lnx_capsh_shell_invocation" ];
    sigmahq_nice_shell = [ "proc_creation_lnx_nice_shell_execution" ];
    sigmahq_env_shell = [ "proc_creation_lnx_env_shell_invocation" ];
    sigmahq_mount_hidepid = [ "proc_creation_lnx_mount_hidepid" ];
    sigmahq_auditctl_clear = [ "proc_creation_lnx_auditctl_clear_rules" ];
    sigmahq_systemctl_mask = [ "proc_creation_lnx_systemctl_mask_power_settings" ];
    sigmahq_secsoftware_discovery = [ "proc_creation_lnx_security_software_discovery" ];
    sigmahq_python_http_server = [ "proc_creation_lnx_python_http_server_execution" ];
    sigmahq_curl_usage = [ "proc_creation_lnx_curl_usage" ];
    sigmahq_crontab_removal = [ "proc_creation_lnx_crontab_removal" ];
    sigmahq_setgid_setuid = [ "proc_creation_lnx_setgid_setuid" ];

    # Batch 2 -- the file_event layer, reached by watching a scratch directory
    # (services.banken.audit.watchPaths below): a file touch under a watched
    # path becomes an event with TargetFilename set, which is what these rules
    # key on. Both target rules match on the filename alone, so the benign
    # create of the indicator file in the watched dir is enough.
    sigmahq_fe_ebpfbackdoor = [ "file_event_lnx_triple_cross_rootkit_persistence" ];
    sigmahq_fe_base64_filename = [ "file_event_lnx_susp_filename_with_embedded_base64_command" ];

    # Batch 3 -- more process_creation rules. Each is a binary or flag shape an
    # unprivileged user can run benignly (most fail safe / act on scratch files
    # or unroutable TEST-NET addresses) while still carrying the execve indicator
    # the rule keys on. Where one benign one-liner inherently trips a second rule
    # that genuinely matches the same behaviour (a "twin"), both are listed so
    # the twin is not counted as a wild process_creation hit:
    #   * the two curl families also trip curl_usage (any curl at all);
    #   * the two find families also trip file_and_directory_discovery (any find);
    #   * base64_exec runs through `bash -c` with a pipe and `base64 -d`, so it
    #     also trips susp_pipe_shell and base64_decode.
    sigmahq_local_account = [ "proc_creation_lnx_local_account" ];
    sigmahq_local_groups = [ "proc_creation_lnx_local_groups" ];
    sigmahq_grep_os_arch = [ "proc_creation_lnx_grep_os_arch_discovery" ];
    sigmahq_history_recon = [ "proc_creation_lnx_susp_history_recon" ];
    sigmahq_history_delete = [ "proc_creation_lnx_susp_history_delete" ];
    sigmahq_clear_logs = [ "proc_creation_lnx_clear_logs" ];
    sigmahq_clear_syslog = [ "proc_creation_lnx_clear_syslog" ];
    sigmahq_curl_useragent = [ "proc_creation_lnx_susp_curl_useragent" "proc_creation_lnx_curl_usage" ];
    sigmahq_curl_fileupload = [ "proc_creation_lnx_susp_curl_fileupload" "proc_creation_lnx_curl_usage" ];
    sigmahq_services_stop = [ "proc_creation_lnx_services_stop_and_disable" ];
    sigmahq_cron_tmp = [ "proc_creation_lnx_schedule_task_job_cron" ];
    sigmahq_find_shell = [ "proc_creation_lnx_find_shell_execution" "proc_creation_lnx_file_and_directory_discovery" ];
    sigmahq_find_perm = [ "proc_creation_lnx_susp_find_execution" "proc_creation_lnx_file_and_directory_discovery" ];
    sigmahq_python_os_system = [ "proc_creation_lnx_python_shell_os_system" ];
    sigmahq_python_pty = [ "proc_creation_lnx_python_pty_spawn" ];
    sigmahq_awk_shell = [ "proc_creation_lnx_awk_shell_spawn" ];
    sigmahq_pipe_shell = [ "proc_creation_lnx_susp_pipe_shell" ];
    sigmahq_remove_package = [ "proc_creation_lnx_remove_package" ];
    sigmahq_base64_exec =[ "proc_creation_lnx_base64_execution" "proc_creation_lnx_base64_decode" "proc_creation_lnx_susp_pipe_shell" ];

    sigmahq_benign = [ ];
  };
in
pkgs.testers.runNixOSTest {
  name = "banken-sigmahq-emul";

  nodes.machine = { pkgs, lib, ... }: {
    imports = [ ../module.nix ];
    services.banken = {
      enable = true;
      package = banken;
      alerts.jsonl = { enable = true; format = "ocsf"; };
      # Load the whole SigmaHQ Linux set on top of banken's baseline.
      extraRules = [ sigmaLinux ];
      # Reach the file_event layer: a file touch is only visible to banken when
      # its path is watched (auditd "-w <path> -p rwa"). The two scratch files
      # below sit in a world-writable dir (created by tmpfiles, so it exists
      # before the audit rules load -- a missing WATCHED FILE is fine, a missing
      # parent DIR would break every audit rule). Watching the exact files (not
      # the dir) keeps the watch quiet: nothing but the emulations ever touches
      # them, so they add no ambient file_event noise. The default shadow/gshadow
      # watches are kept.
      audit.watchPaths = [
        "/etc/shadow"
        "/etc/gshadow"
        "/var/lib/bkfwatch/ebpfbackdoor"
        "/var/lib/bkfwatch/bk-{echo"
      ];
    };

    # The watched scratch dir. World-writable so the emulations run as alice can
    # create the indicator files; created early by systemd-tmpfiles, before the
    # audit rules load.
    systemd.tmpfiles.rules = [ "d /var/lib/bkfwatch 0777 root root -" ];
    # The test drives every scan itself, so a scan lands between emulations.
    systemd.timers.banken.wantedBy = lib.mkForce [ ];

    users.users.alice.isNormalUser = true;
    # Everything the sigmahq_*.sh emulations invoke, so none of them hits its
    # BANKEN-EMUL-SKIP path on this image (missing tool => the test fails loudly).
    environment.systemPackages = with pkgs; [
      coreutils
      util-linux
      kmod
      iputils
      libcap
      e2fsprogs
      shadow
      iproute2
      gnused
      cronie
      procps
      lsof
      nettools
      findutils
      # Batch 2 additions, for the new emulations' tools.
      gnugrep # grep (security_software_discovery)
      doas # doas (doas_execution)
      at # at (at_command)
      audit # auditctl (auditctl_clear_rules)
      curl # curl (curl_usage)
      python3 # python3 (python_http_server_execution)
      # Batch 3 additions, for the new emulations' tools.
      gawk # awk (awk_shell_spawn)
      dpkg # dpkg (remove_package)
    ];
    environment.etc."banken-emulations".source = ./emulations;
  };

  testScript = ''
    import json

    expected = json.loads(${builtins.toJSON (builtins.toJSON expected)})

    machine.wait_for_unit("auditd.service")
    machine.wait_until_succeeds("auditctl -l | grep -q banken-exec")

    # The authoritative set of SigmaHQ Linux rule names banken loaded (file
    # basenames), used to judge "nothing wild" within the SigmaHQ universe.
    sigma_names = set(
        machine.succeed(
            "find ${sigmaLinux} -name '*.yml' -printf '%f\\n'"
        ).replace(".yml", "").split()
    )
    assert len(sigma_names) > 150, f"expected the full SigmaHQ Linux set, got {len(sigma_names)}"

    # Drain boot-time events so the first emulation is judged alone.
    machine.succeed("systemctl start banken.service")

    def lines():
        out = machine.succeed("cat /var/log/banken/alerts-*.jsonl 2>/dev/null || true")
        return [l for l in out.splitlines() if l.strip()]

    # A login-style PATH so the emulations find tools in the system profile and
    # the wrappers; runuser's bare PATH would miss them.
    loginpath = "/run/wrappers/bin:/run/current-system/sw/bin:/usr/bin:/bin"

    def run_family(family):
        """Run one emulation as alice, scan once, return (skipped, fired SigmaHQ
        rule names) for the events that scan produced."""
        before = len(lines())
        # runuser, not su/sudo: those would fire privilege_escalation_attempt.
        out = machine.succeed(
            f"runuser -u alice -- env PATH={loginpath} bash /etc/banken-emulations/{family}.sh"
        )
        machine.succeed("systemctl start banken.service")
        new = [json.loads(l) for l in lines()[before:]]
        for f in new:
            assert f["class_uid"] == 2004 and f["metadata"]["version"] == "1.3.0", f
        fired_all = {f["finding_info"]["analytic"]["name"] for f in new}
        return ("BANKEN-EMUL-SKIP" in out), (fired_all & sigma_names)

    # process_creation rules a stray background exec (a system `rm`) can trip in
    # any scan window; allowed everywhere so they do not masquerade as a wild hit.
    BACKGROUND = {"proc_creation_lnx_file_deletion"}

    def proc(rules):
        return {r for r in rules if r.startswith("proc_creation_lnx_")}

    # Establish the ambient noise floor from the benign baseline first.
    skip, ambient = run_family("sigmahq_benign")
    assert not skip, "sigmahq_benign unexpectedly skipped"
    stray = proc(ambient) - BACKGROUND
    print(f"sigmahq_benign: ambient sigma rules {sorted(ambient)}")
    failures = []
    if stray:
        failures.append(f"sigmahq_benign fired process_creation rules {sorted(stray)}, want none")

    for family in sorted(k for k in expected if k != "sigmahq_benign"):
        skip, fired = run_family(family)
        if skip:
            # We control the image's packages, so a skip is a harness bug.
            failures.append(f"{family}: unexpectedly skipped")
            continue
        want = set(expected[family])
        residual = fired - ambient
        residual_proc = proc(residual)
        missing = want - fired
        wild = residual_proc - want - BACKGROUND
        twins = sorted(residual - residual_proc)  # auditd/network coverage, reported only
        print(
            f"{family}: target {sorted(want)} fired={not missing}; "
            f"extra proc_creation {sorted(residual_proc - want)}; twin/other {twins}"
        )
        if missing:
            failures.append(f"{family}: target rule(s) {sorted(missing)} did not fire (fired {sorted(fired)})")
        if wild:
            failures.append(f"{family}: unexpected process_creation rule(s) fired: {sorted(wild)}")

    assert not failures, "\n".join(failures)
  '';
}
