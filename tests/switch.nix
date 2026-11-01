# End-to-end proof of the ONE SWITCH: a VM with services.banken.mimi.enable = true. The switch
# brings up the hardened mimi eBPF sensor, points banken at its OCSF stream, and runs banken as a
# continuous --watch daemon. Audit is turned OFF here on purpose, so the mimi stream is banken's
# ONLY source: a reverse-shell-shaped exec can then be detected only if mimi captured it via CO-RE
# (resolving task_struct offsets from the VM kernel's own BTF, a different kernel than 6.18.59) and
# banken matched it off the live stream. That isolates the integration -- an alert is proof the
# bytes travelled mimi -> stream -> banken -- and the script reports the measured exec->alert
# latency.
#
# Driven by a small flake that supplies banken's package and mimi's NixOS module (packaged
# hermetically by mimi's own flake); needs KVM. See tests/README or the lane notes for the runner.
{ pkgs, banken, mimiModule }:
pkgs.testers.runNixOSTest {
  name = "banken-mimi-switch";

  nodes.machine = { lib, pkgs, ... }: {
    imports = [ ../module.nix mimiModule ];
    services.banken = {
      enable = true;
      package = banken;
      alerts.jsonl = { enable = true; format = "ocsf"; };
      mimi.enable = true; # THE switch: brings up services.mimi and makes banken a --watch daemon
      audit.enable = false; # mimi is then banken's only source, so an alert proves the mimi path
    };
    users.users.alice.isNormalUser = true;
    environment.systemPackages = with pkgs; [ python3 procps ];
    # The eBPF loader needs a little headroom (ring buffer + BTF); give the guest room.
    virtualisation.memorySize = 2048;
  };

  testScript = ''
    import json, time

    # The switch must have brought up both units, with banken ordered after mimi.
    machine.wait_for_unit("mimi.service")
    machine.wait_for_unit("banken.service")

    # mimi loaded its probe (CO-RE off the VM kernel's BTF) and is streaming OCSF events.
    machine.wait_for_file("/var/log/mimi/events.jsonl")
    machine.wait_until_succeeds("test -s /var/log/mimi/events.jsonl")

    # banken is the continuous --watch daemon, not the oneshot + timer floor.
    machine.succeed("systemctl show -p ExecStart banken.service | grep -- --watch")
    machine.fail("systemctl is-active --quiet banken.timer")

    def alerts():
        out = machine.succeed("cat /var/log/banken/alerts-*.jsonl 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    # A benign reverse-shell-shaped exec as an unprivileged user. 192.0.2.1 is TEST-NET-1
    # (RFC5737): it routes nowhere, so nothing leaves the box; the command SHAPE is what fires
    # reverse_shell. A unique port ties the resulting alert back to exactly this exec. Launched in
    # the background so the measurement starts at exec time, not after the connect times out.
    port = "47123"
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

    # It is a reverse_shell Detection Finding, OCSF 1.3.0; with audit off it can only have come
    # off the mimi stream.
    assert hit["class_uid"] == 2004 and hit["metadata"]["version"] == "1.3.0", hit
    name = hit["finding_info"]["analytic"]["name"]
    assert name == "reverse_shell", f"fired {name!r}, expected reverse_shell"

    # And the very same exec is in mimi's capture stream -- the provenance of the alert.
    machine.succeed(f"grep -q {port} /var/log/mimi/events.jsonl")

    print(f"SWITCH PROOF PASS: services.banken.mimi.enable -> reverse_shell detected off the "
          f"mimi-only source; exec->alert {latency_ms:.0f} ms")
  '';
}
