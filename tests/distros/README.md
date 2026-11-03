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

- **Install** - packages, audit rules and the unit install per the docs. Zero-config run. The timer fires on its own. Clean logs. (A1-A4)
- **Detect** - every malware look-alike fires exactly its rules. A normal day fires nothing. (B1-B2)
- **Output** - every alert is a valid OCSF finding. High and critical reach the journal. (C1-C2)
- **Security** - the unit's sandbox takes effect. The distro's own SELinux/AppArmor denies banken nothing. (D1-D2)
- **Go suite** - banken's whole Go test suite passes inside the guest. (E1)
- **mimi** - the eBPF sensor loads against the distro's own kernel BTF. banken detects off its stream. (M1-M5)
- **Sysmon** - Microsoft's real `sysmonforlinux`, where it is served. banken detects off it. (S1-S5)

Not yet in the matrix: reboot persistence (A5), alert timing (B3), abuse recovery (D3), footprint budget (D4), the full ART range (E2), the SigmaHQ false-positive count (E3), live OCSF validation (E4).

## Recorded per distro

Logged, not judged:

- OS, kernel, systemd version
- LSM and SELinux mode
- packages the install needed
- audit rule count and status
- whether the distro ships a `-a task,never` rule (it turns syscall auditing off)
- the exposure score

## banken + mimi (M1-M5)

The A-E objectives test banken on the auditd floor. The M objectives add the mimi eBPF sensor on top.

On each distro:

- mimi loads its probe against that distro's own kernel BTF (CO-RE).
- banken reads mimi's OCSF stream as a `--watch` daemon.

This proves the sensor-to-brain integration on real vendor kernels. Not just the nixpkgs kernels of mimi's own CO-RE matrix.

banken's flake stays decoupled from mimi:

- `nix run .#distro-matrix` is banken-raw (A-E only).
- [`default.nix`](default.nix) takes an optional `mimiBundle`. Set it, and the payload carries the mimi bundle and [`mimicheck.sh`](mimicheck.sh). Then `distrocheck` runs M1-M5.

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

## banken + Sysmon-for-Linux (S1-S5)

The S objectives prove the other sensor: Microsoft's own `sysmonforlinux`, installed the real way in the guest.

[`sysmoncheck.sh`](sysmoncheck.sh):

- adds Microsoft's package repo (`packages.microsoft.com`, via the host proxy like every other repo)
- installs the genuine `sysmonforlinux` package
- applies a minimal ProcessCreate config and runs Sysmon
- triggers a reverse-shell-shaped `/dev/tcp` exec as the test user
- checks banken detects `reverse_shell` off the `sysmon` source

Sysmon logs via syslog. journald captures it under the identifier `sysmon`. A small bridge runs `journalctl -o cat -t sysmon -f`, appending those entries to a file banken tails. Same shape as `module.nix`'s `services.banken.sysmon`.

The stage is conditional on where Microsoft ships `sysmonforlinux`:

- **Served:** apt distros (Ubuntu, Debian) and the RHEL family via the MS yum repo (Rocky, Alma).
- **Skipped, recorded, never a red check:** Fedora, Amazon Linux, openSUSE, Arch.

If a served package manager still lacks the repo, `sysmoncheck.sh` prints `SYSMON-SKIP <reason>` and skips the same clean way.

It rides with the sensor matrix:

- `nix run .#distro-matrix-mimi` ships `sysmoncheck.sh` and the mimi bundle.
- `nix run .#distro-matrix` carries neither. It stays banken-raw (A-E only).

Sysmon loads its own eBPF probe off the kernel's BTF, like mimi. A kernel with no BTF fails S2 honestly.

## Network

With no proxy (a CI runner, a workstation), the guests use QEMU's user network directly.

With `http_proxy`/`https_proxy` set to a proxy on the host's loopback:

- the guests reach it at `10.0.2.2`
- the checker configures the package manager for it

The default mirror list redirects to random third-party mirrors. An allow-list can't name those ahead of time. So the checker pins dnf and zypper to the vendor's own host: `dl.rockylinux.org`, `repo.almalinux.org`, `dl.fedoraproject.org`, `downloadcontent.opensuse.org`.

`cloud.debian.org` serves images only by redirect to `acc.umu.se`. The allow-list needs that host too.

## Adding a distro

Add an entry to `distros.json`:

- a versioned image URL the vendor serves directly (not a `latest` link: it moves and breaks the checksum)
- the vendor's checksum (`sha256` or `sha512`)
- the package manager (`dnf`, `apt`, `zypper`, `pacman`)
- the package that provides each command the test needs
