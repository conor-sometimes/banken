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

    # Batch 4 -- more process_creation rules plus four more file_event rules.
    # The process_creation ones are the same shape as earlier batches: a
    # distinctive binary/flag combination an unprivileged user runs benignly
    # (interpreter one-liners whose reverse-shell indicators sit in dead string
    # literals; reads that are denied or target nonexistent paths; payloads that
    # are the stock `true` binary copied into /tmp or /dev/shm). Twins, where one
    # benign one-liner inherently trips a second rule that genuinely matches the
    # same behaviour, are listed so they are not counted as wild hits:
    #   * nohup into /tmp also trips the base nohup rule;
    #   * mkfifo in /tmp also trips the base mkfifo rule.
    sigmahq_perl_reverse_shell = [ "proc_creation_lnx_perl_reverse_shell" ];
    sigmahq_php_reverse_shell = [ "proc_creation_lnx_php_reverse_shell" ];
    sigmahq_ruby_reverse_shell = [ "proc_creation_lnx_ruby_reverse_shell" ];
    sigmahq_python_reverse_shell = [ "proc_creation_lnx_python_reverse_shell" ];
    sigmahq_vim_shell_execution = [ "proc_creation_lnx_vim_shell_execution" ];
    sigmahq_flock_shell_execution = [ "proc_creation_lnx_flock_shell_execution" ];
    sigmahq_python_base64_encoded_execution = [ "proc_creation_lnx_python_base64_encoded_execution" ];
    sigmahq_chmod_targeting_sensitive_directories = [ "proc_creation_lnx_chmod_targeting_sensitive_directories" ];
    sigmahq_cp_passwd_or_shadow_tmp = [ "proc_creation_lnx_cp_passwd_or_shadow_tmp" ];
    # cat of /etc/sudoers also trips local_account (its selection_3 keys on a
    # reader of /etc/passwd|shadow|sudoers) -- a legitimate twin.
    sigmahq_susp_process_reading_sudoers = [ "proc_creation_lnx_susp_process_reading_sudoers" "proc_creation_lnx_local_account" ];
    sigmahq_nohup_susp_execution = [ "proc_creation_lnx_nohup_susp_execution" "proc_creation_lnx_nohup" ];
    sigmahq_mkfifo_named_pipe_creation_susp_location = [ "proc_creation_lnx_mkfifo_named_pipe_creation_susp_location" "proc_creation_lnx_mkfifo_named_pipe_creation" ];
    sigmahq_base64_shebang_cli = [ "proc_creation_lnx_base64_shebang_cli" ];
    sigmahq_bash_interactive_shell = [ "proc_creation_lnx_bash_interactive_shell" ];
    sigmahq_susp_container_residence_discovery = [ "proc_creation_lnx_susp_container_residence_discovery" ];
    sigmahq_susp_dockerenv_recon = [ "proc_creation_lnx_susp_dockerenv_recon" ];
    sigmahq_susp_inod_listing = [ "proc_creation_lnx_susp_inod_listing" ];
    sigmahq_susp_exec_from_dev_shm = [ "proc_creation_lnx_susp_exec_from_dev_shm" ];
    sigmahq_susp_execution_tmp_folder = [ "proc_creation_lnx_susp_execution_tmp_folder" ];
    sigmahq_proxy_connection = [ "proc_creation_lnx_proxy_connection" ];
    sigmahq_wget_download_suspicious_directory = [ "proc_creation_lnx_wget_download_suspicious_directory" ];

    # Batch 4 file_event rules. Three key on the filename alone (a path segment
    # or suffix), so creating the indicator file in a watched scratch path is
    # enough; the fourth (wget into /tmp) also keys on the writing process, so
    # the write is produced by wget and the proc_creation wget rule fires as its
    # twin. The watched scratch files/dirs are added to audit.watchPaths and
    # systemd.tmpfiles.rules below.
    sigmahq_fe_profile_script = [ "file_event_lnx_susp_shell_script_under_profile_directory" ];
    sigmahq_fe_triple_cross_lock = [ "file_event_lnx_triple_cross_rootkit_lock_file" ];
    sigmahq_fe_doas_conf = [ "file_event_lnx_doas_conf_creation" ];
    sigmahq_fe_wget_tmp = [ "file_event_lnx_wget_download_file_in_tmp_dir" "proc_creation_lnx_wget_download_suspicious_directory" ];

    # Batch 5 -- more process_creation rules. Same shape as earlier batches: a
    # distinctive binary/flag combination an unprivileged user runs benignly
    # (connects aimed at TEST-NET-1 so nothing is reached; sudo refused
    # non-interactively; reads/writes that fail safe; payloads that are the stock
    # `true` binary copied under the triggering name in a HOME scratch dir, used
    # where the real tool is a heavy closure or not in nixpkgs and the rule keys
    # only on the image name + flags). Twins, where one benign invocation inherently
    # trips a second rule that genuinely matches the same behaviour, are listed so
    # they are not counted as wild hits:
    #   * nc without a listen flag also trips susp_network_utilities_execution;
    #   * the curl/wget stager one-liner runs through `bash -c` carrying '/tmp/'
    #     and 'sh -c', so it also trips curl_usage (the inner curl) and
    #     susp_shell_script_exec_from_susp_location (shell -c referencing /tmp);
    #   * `systemctl stop firewalld` also trips services_stop_and_disable;
    #   * `find ... -name .htpasswd` also trips file_and_directory_discovery.
    sigmahq_netcat_reverse_shell = [ "proc_creation_lnx_netcat_reverse_shell" "proc_creation_lnx_susp_network_utilities_execution" ];
    sigmahq_ssh_shell_execution = [ "proc_creation_lnx_ssh_shell_execution" ];
    sigmahq_curl_wget_exec_tmp = [ "proc_creation_lnx_curl_wget_exec_tmp" "proc_creation_lnx_curl_usage" "proc_creation_lnx_susp_shell_script_exec_from_susp_location" ];
    sigmahq_install_root_certificate = [ "proc_creation_lnx_install_root_certificate" ];
    sigmahq_install_suspicious_packages = [ "proc_creation_lnx_install_suspicious_packages" ];
    sigmahq_security_tools_disabling = [ "proc_creation_lnx_security_tools_disabling" "proc_creation_lnx_services_stop_and_disable" ];
    sigmahq_clipboard_collection = [ "proc_creation_lnx_clipboard_collection" ];
    sigmahq_gobrat_grep = [ "proc_creation_lnx_malware_gobrat_grep_payload_discovery" ];
    sigmahq_pnscan = [ "proc_creation_lnx_pnscan_binary_cli_pattern" ];
    sigmahq_triple_cross_execve_hijack = [ "proc_creation_lnx_triple_cross_rootkit_execve_hijack" ];
    sigmahq_triple_cross_install = [ "proc_creation_lnx_triple_cross_rootkit_install" ];
    sigmahq_dd_process_injection = [ "proc_creation_lnx_dd_process_injection" ];
    sigmahq_xterm_reverse_shell = [ "proc_creation_lnx_xterm_reverse_shell" ];
    sigmahq_bpftrace_unsafe = [ "proc_creation_lnx_bpftrace_unsafe_option_usage" ];
    sigmahq_bpf_kprobe = [ "proc_creation_lnx_bpf_kprob_tracing_enabled" ];
    sigmahq_recon_indicators = [ "proc_creation_lnx_susp_recon_indicators" "proc_creation_lnx_file_and_directory_discovery" ];
    sigmahq_shell_script_susp_location = [ "proc_creation_lnx_susp_shell_script_exec_from_susp_location" ];

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
        # Batch 4 file_event scratch targets. Each is watched as an exact file so
        # nothing but its emulation ever touches it (no ambient file_event noise).
        # The rule each one feeds keys on the filename segment/suffix shown.
        "/var/lib/bkfwatch/etc/profile.d/bk.sh" # contains '/etc/profile.d/', ends '.sh'
        "/var/lib/bkfwatch/etc/doas.conf"       # ends with '/etc/doas.conf'
        "/tmp/rootlog"                          # exactly '/tmp/rootlog'
        "/tmp/bk-wget-fe"                        # starts with '/tmp/', written by wget
      ];
    };

    # The watched scratch dir. World-writable so the emulations run as alice can
    # create the indicator files; created early by systemd-tmpfiles, before the
    # audit rules load.
    systemd.tmpfiles.rules = [
      "d /var/lib/bkfwatch 0777 root root -"
      # Batch 4: scratch parents for the file_event watches. World-writable so
      # alice can create the indicator files; created before the audit rules load
      # (a missing watched FILE is fine, a missing parent DIR is not).
      "d /var/lib/bkfwatch/etc 0777 root root -"
      "d /var/lib/bkfwatch/etc/profile.d 0777 root root -"
    ];
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
      # Batch 4 additions, for the new emulations' interpreters and tools.
      perl # perl (perl_reverse_shell)
      php # php (php_reverse_shell)
      ruby # ruby (ruby_reverse_shell)
      vim # vim (vim_shell_execution)
      wget # wget (wget_download_suspicious_directory, fe_wget_tmp)
      # Batch 5 additions, for the new emulations' tools. (sudo, dd, grep, find,
      # dpkg, bash and systemctl are already present via the system or earlier
      # batches; xterm/bpftrace/update-ca-certificates are emulated with a copied
      # stock `true` under the triggering name, so no heavy closure is pulled in.)
      netcat-gnu # nc with -e (netcat_reverse_shell, susp_network_utilities_execution)
      openssh # ssh (ssh_shell_execution)
      xclip # xclip (clipboard_collection)
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
