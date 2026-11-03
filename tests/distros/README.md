# Live distro matrix

banken, tested live on each distro's own kernel and auditd. Installed the way an operator would.

```sh
nix run .#distro-matrix                                   # every distro, every objective
nix run .#distro-matrix -- -test.run 'TestMatrix/rocky-9' # one distro
```

One command. No manual steps. Needs KVM and network access for the guests' package installs.

Containers can't do this. The Linux audit subsystem isn't namespaced. A container shares the host's one audit stream. So each distro here is a real VM.

## How it works

Three parts, each a standard tool:

- **Nix** ([`default.nix`](default.nix)) fetches every image in [`distros.json`](distros.json) by its pinned vendor checksum. It builds banken, the in-guest checker, and the test.
- **cloud-init** boots each image. The seed is a one-line NoCloud ISO: run the checker.
- **Go** ([`matrix_test.go`](matrix_test.go)) runs the test. It boots every distro in parallel as a copy-on-write overlay. Each distro is a subtest; each objective a subtest of that.

[`distrocheck`](distrocheck/main.go) runs inside the guest as root. It installs banken per [docs/deployment.md](../../docs/deployment.md). It checks every objective. It writes one JSON report to the serial console. It powers the VM off.

Output is plain `go test`:

```
--- FAIL: TestMatrix/alma-10/D2
```

A failing distro prints the tail of its serial console. `-keep` saves every VM's serial log.

banken supports systemd hosts only. NixOS is tested through its own module by `tests/vm.nix` (`nix flake check`).

## Objectives

Every built objective passes on every distro it applies to. Status 2026-11-01.

| Distro | Install | Detect | Output | Security | Go suite | mimi | Sysmon |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Rocky 9 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| AlmaLinux 10 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Fedora 44 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | n/a |
| Amazon Linux 2023 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | n/a |
| Debian 13 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ubuntu 24.04 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| openSUSE Leap 16 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | n/a |
| Arch | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | n/a |

Sysmon is `n/a` where Microsoft does not serve `sysmonforlinux`. The stage is skipped, not failed. NixOS is covered separately by `tests/vm.nix`.

What each column checks:

- **Install** - packages, audit rules and the unit install per the docs. Zero-config run. The timer fires on its own. Clean logs.
- **Detect** - every malware look-alike fires exactly its rules. A normal day fires nothing.
- **Output** - every alert is a valid OCSF finding. High and critical reach the journal.
- **Security** - the unit's sandbox takes effect. The distro's own SELinux/AppArmor denies banken nothing.
- **Go suite** - banken's whole Go test suite passes inside the guest.
- **mimi** - the eBPF sensor loads against the distro's own kernel BTF. banken detects off its stream.
- **Sysmon** - Microsoft's real `sysmonforlinux`, where it is served. banken detects off it.

Not yet in the matrix: reboot persistence, alert timing, abuse recovery, footprint budget, the full Atomic Red Team range, the SigmaHQ false-positive count, live OCSF validation.

## Recorded per distro

Each report captures this for context. None of it is scored:

- OS, kernel, systemd version
- LSM and SELinux mode
- packages the install needed
- audit rule count and status
- whether the distro ships a `-a task,never` rule (it turns syscall auditing off)
- the exposure score

## banken + mimi

The base matrix tests banken on the plain auditd floor. The mimi stage adds its eBPF sensor on top.

On each distro:

- mimi loads its probe against that distro's own kernel BTF (CO-RE).
- banken reads mimi's OCSF stream as a `--watch` daemon.

This proves the sensor-to-brain integration on real vendor kernels. Not just the nixpkgs kernels of mimi's own CO-RE matrix.

banken's flake stays decoupled from mimi:

- `nix run .#distro-matrix` runs the auditd floor only, no sensors.
- Set [`default.nix`](default.nix)'s optional `mimiBundle`, and the mimi stage runs.

A small throwaway flake supplies the bundle and calls `default.nix`:

```nix
mimiBundle = pkgs.runCommand "mimi-bundle" { } ''
  mkdir -p $out
  cp ${mimi.packages.x86_64-linux.default}/bin/mimi $out/mimi
  cp ${pkgs.glibc}/lib/ld-linux-x86-64.so.2 $out/ld.so
  cp ${pkgs.glibc}/lib/libc.so.6 $out/libc.so.6
  cp ${pkgs.stdenv.cc.cc.lib}/lib/libgcc_s.so.1 $out/libgcc_s.so.1
  chmod -R u+w $out
'';
distro-matrix = pkgs.callPackage (banken + "/tests/distros/default.nix") {
  banken = pkgs.callPackage (banken + "/package.nix") { };
  inherit mimiBundle;
};
```

mimi is built dynamically. A fully static glibc build isn't possible with proc-macro crates on one triple. So the bundle ships its interpreter and libraries beside the binary. The guest runs mimi as root, so it has the capabilities and DAC access the probe needs.

## banken + Sysmon-for-Linux

The Sysmon stage proves the other sensor: Microsoft's own `sysmonforlinux`, installed the real way in the guest.

[`sysmoncheck.sh`](sysmoncheck.sh):

- adds Microsoft's package repo (`packages.microsoft.com`, via the host proxy like every other repo)
- installs the genuine `sysmonforlinux` package
- applies a minimal ProcessCreate config and runs Sysmon
- triggers a reverse-shell-shaped `/dev/tcp` exec as the test user
- checks banken detects `reverse_shell` off the `sysmon` source

Sysmon's log reaches banken in a few hops:

- Sysmon logs via syslog.
- journald captures it under the identifier `sysmon`.
- a `journalctl -o cat -t sysmon -f` bridge appends those lines to a file.
- banken tails that file.

Same shape as `module.nix`'s `services.banken.sysmon`.

The stage is conditional on where Microsoft ships `sysmonforlinux`:

- **Served:** apt distros (Ubuntu, Debian) and the RHEL family via the MS yum repo (Rocky, Alma).
- **Skipped, recorded, never a red check:** Fedora, Amazon Linux, openSUSE, Arch.

If a served package manager still lacks the repo, `sysmoncheck.sh` prints `SYSMON-SKIP <reason>` and skips the same clean way.

It rides with the sensor matrix:

- `nix run .#distro-matrix-mimi` ships `sysmoncheck.sh` and the mimi bundle.
- `nix run .#distro-matrix` carries neither. It runs the auditd floor only.

Sysmon loads its own eBPF probe off the kernel's BTF, like mimi. A kernel with no BTF fails that stage honestly.

## Network

With no proxy, the guests use QEMU's user network directly. A CI runner or a workstation needs nothing more.

Behind an egress allow-list (a firewall that only lets named hosts out), set `http_proxy`/`https_proxy` to the loopback proxy. The checker then:

- points each guest's package manager at the proxy (`10.0.2.2`)
- pins the repos to each vendor's own host, so every hostname is known ahead of time

The pinned hosts live in [`distrocheck`](distrocheck/main.go).

## Adding a distro

Add one entry to [`distros.json`](distros.json). No code. The harness picks it up, boots it, and runs every objective against it.

The entry needs four things:

- a versioned image URL the vendor serves directly (not a `latest` link: it moves and breaks the checksum)
- the vendor's checksum (`sha256` or `sha512`)
- the package manager (`dnf`, `apt`, `zypper`, `pacman`)
- the package that provides each command the test needs
