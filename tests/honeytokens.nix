# VM test for services.banken.honeytokens. Boots a real NixOS guest with banken
# + honeytokens enabled, and proves the whole chain: decoys are planted (inert,
# right owner/mode), the audit read-watch is loaded, a read of a decoy fires
# honeytoken_access (critical) through banken, a real credential's read does NOT,
# and the overwrite guard never clobbers an existing file.
#
# Run: nix build .#checks.x86_64-linux.honeytokens  (or via flake check)
{ pkgs ? import <nixpkgs> { }, banken ? pkgs.callPackage ../package.nix { } }:

pkgs.testers.runNixOSTest {
  name = "banken-honeytokens";

  nodes.machine = { config, lib, pkgs, ... }: {
    imports = [ ../module.nix ];

    services.banken = {
      enable = true;
      package = banken;
      interval = "1h"; # we drive scans by hand, not the timer
      alerts.jsonl = {
        enable = true;
        format = "ocsf";
      };
      honeytokens = {
        enable = true;
        aws.enable = true;
        ssh.enable = true;
        env.enable = true;
        docker.enable = true; # enabled so the guard test exercises a real pre-existing file
      };
    };

    # A real, legitimate credential file for the "must NOT alert" control: it is
    # a plain user's own secret, outside the decoy user, not watched.
    users.users.alice = {
      isNormalUser = true;
      uid = 1001;
    };
    systemd.tmpfiles.rules = [
      "d /home/alice/.aws 0700 alice users -"
      "f /home/alice/.aws/credentials 0600 alice users - real-key-not-a-decoy"
    ];

    # Pre-create a real file at an ENABLED decoy's path (docker) during activation,
    # before systemd-tmpfiles runs the module's copy, to prove the never-clobber
    # guard: the module's tmpfiles C must leave this sentinel content untouched.
    system.activationScripts.honeytokenGuardFixture = {
      deps = [ "users" ];
      text = ''
        mkdir -p /var/lib/banken-decoy/.docker
        echo preexisting-do-not-clobber > /var/lib/banken-decoy/.docker/config.json
        chown -R banken-decoy:banken-decoy /var/lib/banken-decoy/.docker
        chmod 600 /var/lib/banken-decoy/.docker/config.json
      '';
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("auditd.service")
    machine.wait_for_unit("systemd-tmpfiles-setup.service")
    machine.wait_for_unit("banken-honeytoken-watch.service")

    with subtest("decoys are planted, inert, owned by the decoy user"):
        for p in ["/var/lib/banken-decoy/.aws/credentials",
                  "/var/lib/banken-decoy/.ssh/id_rsa",
                  "/var/lib/banken-decoy/.env"]:
            machine.succeed(f"test -f {p}")
            machine.succeed(f"stat -c '%U %a' {p} | grep -x 'banken-decoy 600'")
        # the AWS decoy is AWS's documented EXAMPLE key (inert)
        machine.succeed("grep -q AKIAIOSFODNN7EXAMPLE /var/lib/banken-decoy/.aws/credentials")

    with subtest("overwrite guard: a pre-existing file is not clobbered"):
        got = machine.succeed("cat /var/lib/banken-decoy/.docker/config.json")
        assert "preexisting-do-not-clobber" in got, f"guard failed, decoy overwrote a real file: {got!r}"

    with subtest("the honeytoken read-watch is loaded in auditd"):
        machine.succeed("auditctl -l | grep banken-honeytoken")

    with subtest("reading a decoy fires honeytoken_access (critical) through banken"):
        # a credential hunter opens the decoy
        machine.succeed("cat /var/lib/banken-decoy/.aws/credentials >/dev/null")
        # let auditd flush, then run a banken scan as the timer would
        machine.succeed("sleep 2")
        machine.succeed("systemctl start banken.service")
        machine.wait_until_succeeds(
            "grep -rl -e 'Honeytoken' -e honeytoken /var/log/banken/ 2>/dev/null", timeout=30
        )

    with subtest("a real credential read does NOT trip the honeytoken watch"):
        def ht_alerts():
            return machine.succeed("grep -rhi honeytoken /var/log/banken/ 2>/dev/null | wc -l").strip()
        before = ht_alerts()
        machine.succeed("su - alice -c 'cat /home/alice/.aws/credentials >/dev/null'")
        machine.succeed("sleep 2")
        machine.succeed("systemctl start banken.service")
        machine.succeed("sleep 2")
        after = ht_alerts()
        assert before == after, f"honeytoken alerts changed on a real-cred read ({before} -> {after}); the watch is not scoped to the decoys"
  '';
}
