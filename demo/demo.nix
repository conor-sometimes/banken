# The repo showcase as two runnable VM demos:
#
#   nix run .#demo        -- the auditd FLOOR (universal; needs only this repo + nixpkgs + KVM)
#   nix run .#demo-mimi   -- the eBPF SWITCH (the sub-second "wow"; also needs the mimi input)
#
# Both REUSE the existing end-to-end harness so the demo can never drift from the truth:
#   - flavour = "auditd" mirrors tests/vm.nix's node (services.banken.enable only) and runs the
#     repo's own benign tests/emulations/revshell.sh as an unprivileged user.
#   - flavour = "mimi"   mirrors tests/switch.nix's node VERBATIM (services.banken.mimi.enable,
#     audit OFF so mimi is the only source) and runs switch.nix's own benign unique-port
#     reverse-shell one-liner (the bash /dev/tcp TTP of revshell.sh), so the alert proves the full
#     eBPF path and the port ties the alert back to that exact exec in mimi's stream.
#
# ASSERTS (the SAME gate the real tests use -- a regression fails this build): the OCSF 1.3.0
# Detection Finding (class_uid 2004, metadata.version "1.3.0", finding_info.analytic.name
# "reverse_shell") fires off the correct source within the window, and (mimi) the exec is present
# in mimi's capture stream. These expressions are copied from tests/switch.nix lines 76-81 and
# tests/vm.nix lines 83-85; keep them in sync with those tests.
#
# SHOWS (display only, never a pass/fail gate): the measured exec->alert latency, the OCSF body
# arriving at a mock SIEM over HTTP, the `systemd-analyze security` exposure score, and the static
# `file` output of the binary. These illustrate the pitch; they do not newly prove anything, so
# they are wrapped to never abort the demo.
{ pkgs, banken, flavour, mimiModule ? null }:

assert flavour == "auditd" || flavour == "mimi";
assert flavour != "mimi" || mimiModule != null;

let
  isMimi = flavour == "mimi";
  siemPort = 8099;

  # A tiny OCSF-over-HTTP receiver standing in for the operator's SIEM, so "lands in your SIEM" is
  # literal rather than asserted. It appends each POSTed body to a file the demo then pretty-prints.
  siemScript = pkgs.writeText "mock-siem.py" ''
    import http.server, os, threading
    os.makedirs("/var/log/mock-siem", exist_ok=True)
    lock = threading.Lock()
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n)
            with lock, open("/var/log/mock-siem/received.jsonl", "ab") as f:
                f.write(body.rstrip() + b"\n")
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        def log_message(self, *a):
            pass
    # Threaded: banken --watch POSTs a burst of findings at boot (kernel_module_load, ...); a
    # single-threaded server would queue them and starve a later finding (the reverse_shell).
    http.server.ThreadingHTTPServer(("127.0.0.1", ${toString siemPort}), H).serve_forever()
  '';
in
pkgs.testers.runNixOSTest {
  name = "banken-demo-${flavour}";

  nodes.machine = { lib, pkgs, ... }: {
    imports = [ ../module.nix ] ++ lib.optional isMimi mimiModule;

    services.banken = {
      enable = true;
      package = banken;
      alerts.jsonl = { enable = true; format = "ocsf"; };
      # The mock-SIEM sink: a non-secret localhost receiver (inline url allowed per
      # docs/deployment.md). Enabling it also lets banken reach the loopback listener.
      alerts.webhook = {
        enable = true;
        url = "http://127.0.0.1:${toString siemPort}";
        style = "ocsf";
      };
    } // (if isMimi then {
      # tests/switch.nix's node verbatim: the switch brings up mimi and makes banken a --watch
      # daemon; audit OFF so the mimi stream is banken's ONLY source.
      mimi.enable = true;
      audit.enable = false;
    } else {
      # The auditd floor: short interval so the timer-driven scan lands on camera.
      interval = "5s";
    });

    # Mock SIEM up before banken, so the first finding is received.
    systemd.services.mock-siem = {
      description = "mock SIEM receiver (OCSF over HTTP) for the banken demo";
      wantedBy = [ "multi-user.target" ];
      before = [ "banken.service" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${siemScript}";
    };

    users.users.alice.isNormalUser = true;
    environment.systemPackages = with pkgs; [ python3 procps file ];
    environment.etc."banken-emulations".source = ../tests/emulations;
    # The eBPF loader needs headroom (ring buffer + BTF); give the guest room (switch.nix).
    virtualisation.memorySize = lib.mkIf isMimi 2048;
  };

  testScript = ''
    import json, time

    def beat(t, msg):
        print(f"\n===== [{t}] {msg}")

    def show(title, cmd):
        # Display-only: print a command's output, never abort the demo on it.
        st, out = machine.execute(cmd)
        print(f"----- {title}\n{out.strip()}")

    def alerts():
        out = machine.succeed("cat /var/log/banken/alerts-*.jsonl 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    flavour = ${builtins.toJSON flavour}
    is_mimi = flavour == "mimi"
    port = ""  # set by the mimi flavour below; bound here so the auditd script also type-checks

    beat("0:00", "banken -- one switch, a live reverse shell, an OCSF finding in your SIEM.")
    if is_mimi:
        print("This is the entire setup:\n"
              "    services.banken.enable      = true;\n"
              "    services.banken.mimi.enable = true;   # the eBPF sensor; audit is OFF")
    else:
        print("This is the entire setup:\n"
              "    services.banken.enable = true;        # auditd floor, no eBPF")

    beat("boot", "bringing up the VM and the banken units ...")
    ${if isMimi then ''
    # tests/switch.nix: both units up, banken ordered after mimi, mimi streaming OCSF events.
    machine.wait_for_unit("mimi.service")
    machine.wait_for_unit("banken.service")
    machine.wait_for_file("/var/log/mimi/events.jsonl")
    machine.wait_until_succeeds("test -s /var/log/mimi/events.jsonl")
    print("mimi (the eBPF sensor) and banken are up. Audit is OFF -- mimi is the only source,\n"
          "so any alert proves the eBPF path end to end.")
    # banken is the continuous --watch daemon, not the oneshot + timer floor (switch.nix line 43).
    machine.succeed("systemctl show -p ExecStart banken.service | grep -- --watch")
    machine.fail("systemctl is-active --quiet banken.timer")
    show("banken is the continuous watcher",
         "systemctl show -p ExecStart banken.service | sed 's/.*argv\\[\\]=//; s/ ;.*//'")
    '' else ''
    machine.wait_for_unit("auditd.service")
    machine.wait_until_succeeds("auditctl -l | grep -q banken-exec")
    machine.wait_for_unit("banken.timer")
    print("auditd floor is up with banken's audit rules; banken scans every 5s (demo interval).")
    # Drain boot-time events so the emulation is judged alone (vm.nix pattern).
    machine.succeed("systemctl start banken.service")
    ''}

    beat("run", "as unprivileged user 'alice', run a benign reverse-shell-shaped exec.")
    ${if isMimi then ''
    # switch.nix lines 54-60: a unique port ties the alert back to exactly this exec; 192.0.2.1 is
    # TEST-NET-1 (RFC5737) and routes nowhere, so nothing leaves the box -- the SHAPE fires the rule.
    port = "47123"
    print(f"    runuser -u alice -- timeout 3 bash -c 'exec 3<>/dev/tcp/192.0.2.1/{port}'")
    print("    192.0.2.1 is TEST-NET-1; it routes nowhere. The command SHAPE is what fires the rule.")
    before = len(alerts())
    t0 = time.monotonic()
    machine.succeed(
        f"(runuser -u alice -- timeout 3 bash -c 'exec 3<>/dev/tcp/192.0.2.1/{port}' "
        f">/dev/null 2>&1 &) ; true"
    )
    hit = None
    for _ in range(400):  # up to ~20s
        for a in alerts()[before:]:
            if port in json.dumps(a):
                hit = a
                break
        if hit:
            break
        time.sleep(0.05)
    latency_ms = (time.monotonic() - t0) * 1000
    assert hit, f"no alert referencing port {port} within 20s"
    '' else ''
    # Reuse the repo's own benign emulation unchanged (tests/emulations/revshell.sh). A login-style
    # PATH so it finds its tools, exactly as vm.nix / the distro matrix run it.
    loginpath = "/run/wrappers/bin:/run/current-system/sw/bin:/usr/bin:/bin"
    print("    runuser -u alice -- bash /etc/banken-emulations/revshell.sh")
    print("    (bash /dev/tcp, python socket, nc -e against unroutable TEST-NET; all time out.)")
    before = len(alerts())
    t0 = time.monotonic()
    machine.succeed(f"runuser -u alice -- env PATH={loginpath} bash /etc/banken-emulations/revshell.sh")
    hit = None
    for _ in range(120):  # up to ~24s; covers the 5s scan interval with margin
        for a in alerts()[before:]:
            if a["finding_info"]["analytic"]["name"] == "reverse_shell":
                hit = a
                break
        if hit:
            break
        time.sleep(0.2)
    latency_ms = (time.monotonic() - t0) * 1000
    assert hit, "no reverse_shell finding within the scan window"
    ''}

    beat("alert", "the alert lands -- and it is already a standards finding, not a log line.")
    # The SAME assertions the real test gates on (switch.nix 76-78 / vm.nix 83-85): a regression here
    # fails this build.
    assert hit["class_uid"] == 2004 and hit["metadata"]["version"] == "1.3.0", hit
    name = hit["finding_info"]["analytic"]["name"]
    assert name == "reverse_shell", f"fired {name!r}, expected reverse_shell"
    print("OCSF 1.3.0 Detection Finding:")
    print(json.dumps({
        "class_uid": hit["class_uid"],
        "metadata.version": hit["metadata"]["version"],
        "finding_info.analytic.name": name,
        "attacks": hit.get("attacks") or hit.get("finding_info", {}).get("attacks"),
    }, indent=2))
    if is_mimi:
        print(f"\n    exec -> alert: {latency_ms:.0f} ms   (off the mimi eBPF stream)")
    else:
        print(f"\n    exec -> alert: {latency_ms:.0f} ms   (within the 5s demo scan interval)")

    ${pkgs.lib.optionalString isMimi ''
    beat("stream", "provenance: the very same exec is in mimi's raw capture stream.")
    # switch.nix line 81 -- with audit off, the alert could only have come off this stream.
    machine.succeed(f"grep -q {port} /var/log/mimi/events.jsonl")
    show(f"mimi stream line for port {port}",
         f"grep {port} /var/log/mimi/events.jsonl | head -1")
    ''}

    beat("siem", "banken's findings reach your SIEM as OCSF over HTTP -- making \"lands in your SIEM\" literal.")
    # banken --watch POSTs each finding to the webhook sink; the mock SIEM appends every body it
    # receives. Prefer to show the reverse_shell body when it is among them; otherwise show one that
    # did arrive, so this step proves OCSF-over-HTTP delivery either way. Bounded poll, display-only:
    # it must never hang the demo.
    for _ in range(150):  # up to ~15s for the first body to arrive
        st, _o = machine.execute("test -s /var/log/mock-siem/received.jsonl")
        if st == 0:
            break
        time.sleep(0.1)
    st, raw = machine.execute("cat /var/log/mock-siem/received.jsonl 2>/dev/null || true")
    bodies = []
    for l in raw.splitlines():
        if not l.strip():
            continue
        try:
            bodies.append(json.loads(l))
        except Exception:
            continue
    names = sorted({b.get("finding_info", {}).get("analytic", {}).get("name") for b in bodies} - {None})
    rev = next((b for b in bodies if b.get("finding_info", {}).get("analytic", {}).get("name") == "reverse_shell"), None)
    one = rev or (bodies[0] if bodies else None)
    print(f"mock SIEM received {len(bodies)} OCSF Detection Finding(s) over HTTP; analytic names: {names}")
    if one:
        label = "the reverse_shell finding" if one is rev else "one received finding"
        print(f"POSTed OCSF body ({label}, as your SIEM would ingest it):")
        print(json.dumps({
            "class_uid": one.get("class_uid"),
            "metadata": {"version": one.get("metadata", {}).get("version")},
            "finding_info": {"analytic": {"name": one.get("finding_info", {}).get("analytic", {}).get("name")}},
        }, indent=2))
    else:
        print("(no OCSF body received at the mock SIEM within the window; display-only)")

    beat("quiet", "no alert fatigue: on a normal day's work, banken says NOTHING.")
    # The flip side of the catch: a benign admin workload (ordinary file and text commands, none of
    # which match any rule's image/commandline) must raise ZERO alerts. This shows "no false
    # positives ON A NORMAL DAY'S WORK" -- not a claim of zero false positives forever.
    quiet = ("ls -la /home/alice >/dev/null; pwd >/dev/null; echo working >/dev/null; "
             "cat /etc/os-release >/dev/null; date >/dev/null; wc -l /etc/os-release >/dev/null; "
             "head -n2 /etc/os-release >/dev/null; sort /etc/os-release >/dev/null; true")
    before_q = len(alerts())
    machine.succeed("runuser -u alice -- bash -c " + json.dumps(quiet))
    ${if isMimi then ''
    time.sleep(3)  # let the mimi stream flush the benign execs through banken
    '' else ''
    machine.succeed("systemctl start banken.service")  # drive the scan over the benign window
    time.sleep(1)
    ''}
    new_q = alerts()[before_q:]
    names_q = sorted({a["finding_info"]["analytic"]["name"] for a in new_q})
    assert not new_q, f"expected silence on a benign workload; banken raised {names_q}"
    print("ran 9 ordinary commands (ls, pwd, echo, cat, date, wc, head, sort, true) as alice --")
    print("banken raised 0 new alerts. Nothing for the SOC to wade through on a normal day.")

    beat("binary", "one static binary. no kernel module. cannot blue-screen your host.")
    show("systemd-analyze security banken.service (exposure)",
         "systemd-analyze security banken.service 2>/dev/null | tail -1")
    show("file $(command -v banken)",
         "file -L $(command -v banken)")

    tier = "eBPF switch (mimi stream)" if is_mimi else "auditd floor (universal)"
    print(f"\n===== DEMO PASS [{tier}]: services.banken"
          + (".mimi.enable" if is_mimi else ".enable")
          + f" -> OCSF reverse_shell finding in {latency_ms:.0f} ms. See demo/pitch.md for the scorecard.")
  '';
}
