# Live distro matrix

banken tested live on each distro's own kernel and auditd, as an operator would install it.

```sh
nix run .#distro-matrix                                   # every distro, every objective
nix run .#distro-matrix -- -test.run 'TestMatrix/rocky-9' # one distro
```

One command, no manual steps. It needs KVM, and network for the guests' package installs.

Containers cannot do this job: the Linux audit subsystem is not namespaced, so a container
shares the host's one audit stream. Each distro here is a real VM.

## How it works

Three parts, each a standard tool doing what it is for:

- **Nix** ([`default.nix`](default.nix)) fetches every image listed in
  [`distros.json`](distros.json) by the vendor checksum pinned there. It builds banken, the
  in-guest checker and the test, and runs the test with QEMU and xorriso.
- **cloud-init** boots each image. The seed is a NoCloud ISO whose whole config is one line:
  run the checker from the seed.
- **Go** does the testing. [`matrix_test.go`](matrix_test.go) is an ordinary `go test` (build
  tag `distros`): it boots every distro in parallel as a copy-on-write overlay (the image is
  never written), and reports each distro as a subtest and each objective as a subtest of that.
  [`distrocheck`](distrocheck/main.go) runs inside the guest as root. It installs banken the way
  [docs/deployment.md](../../docs/deployment.md) says, checks every objective below, writes one
  JSON report ([`report`](report/report.go)) to the serial console, and powers the VM off.

So the output is plain test output, which CI and `gotestsum` render as they are:

```
--- FAIL: TestMatrix/alma-10/D2
```

A distro that fails prints the tail of its serial console in the test log; `-keep` saves every
VM's serial log to the current directory.

Every distro is a systemd distro: banken supports systemd hosts only, because its security model
is that unit's sandbox (see [docs/deployment.md](../../docs/deployment.md#supported-platforms)).
NixOS is tested through its own module by `tests/vm.nix` (`nix flake check`).

## Objectives

The matrix's contract: every objective passes on every distro. Each has a stable ID and is one
subtest. Status as of 2026-11-01.

| ID | Objective | Checked by | Status |
| --- | --- | --- | --- |
| **A. Install is smooth** | | | |
| A1 | Installing per the docs works: packages from the distro's repos, the audit rules, the unit | every install step succeeds and banken's audit rules are loaded | built |
| A2 | Zero config: with no config file, the unit runs, finds the audit log and journals an attack | a reverse shell is journalled with no `banken.yml` | built |
| A3 | The timer fires on its own; nobody starts the unit | an attack is journalled within one interval (200 s), unit never started by hand | built |
| A4 | Clean logs: every run succeeds and banken logs nothing unexpected | banken's journal holds only alerts, summaries, source detection | built |
| A5 | Survives a reboot: timer resumes, cursor persists, no duplicate alerts | reboot mid-run, compare alert counts | to build |
| **B. Detection** | | | |
| B1 | Each malware look-alike fires exactly its rules (no miss, no false positive) | per family, set equality with its fixtures | built |
| B2 | No false positives on a normal day: user and admin work | a benign workload fires nothing | built |
| B3 | An attack is alerted within one timer interval | event time vs alert time | to build |
| **C. Output** | | | |
| C1 | Every alert line is a valid OCSF 1.3.0 Detection Finding from this host | decoded with banken's own OCSF type | built |
| C2 | High and critical alerts reach the journal at their priority | each one appears under `journalctl -p err` | built |
| **D. Security posture** | | | |
| D1 | The unit's sandbox takes effect on that distro's systemd | `systemd-analyze security` level SAFE or OK | built |
| D2 | The distro's MAC as shipped (SELinux, AppArmor) denies banken nothing | no AVC or AppArmor denial naming banken | built |
| D3 | Recovers from abuse: corrupt cursor, audit log rotation, truncated log | each, then the next run recovers without losing events | to build |
| D4 | Footprint: peak memory and CPU per scan under a budget | systemd's `MemoryPeak` / `CPUUsageNSec` | to build |
| **E. Full conformance on this distro** | | | |
| E1 | banken's whole Go test suite (every package, fixture and golden) passes on this distro | each package's test binary runs in the guest | built |
| E2 | The full Atomic Red Team range, scored per technique on this distro's telemetry | every Linux atomic run live | to build |
| E3 | SigmaHQ's Linux rules on the normal-day workload: the false-positive count | measured per distro | to build |
| E4 | Every live alert passes the official OCSF validator | ocsf-toolkit over the distro's own alerts | to build |
| **M. banken + mimi (the eBPF sensor on this distro's kernel)** | | | |
| M1 | The portable mimi bundle deploys and runs with no `/nix` in the guest | bundle (sensor + loader + glibc) copied from the seed, executable | built |
| M2 | The distro's own kernel exposes BTF (CO-RE prerequisite) | `/sys/kernel/btf/vmlinux` present (M3-M5 skipped, and recorded, if not) | built |
| M3 | mimi loads its probe, resolving `task_struct` offsets from THIS kernel's BTF | probe attaches and the OCSF stream starts | built |
| M4 | mimi captures a real exec into its stream | a canary exec appears in the mimi stream | built |
| M5 | banken `--watch` on the mimi stream detects a reverse shell | an alert fires with `data_sources=["mimi"]` | built |

Recorded per distro (logged, not judged): OS, kernel, systemd version, the LSM and SELinux mode,
packages the install needed, audit rule count and status, whether the distro ships a
`-a task,never` audit rule (which turns syscall auditing off), and the exposure score.

## banken + mimi (Test B: M1-M5)

The A-E objectives test banken on the auditd floor. The M objectives add banken's eBPF sensor
(mimi) on top: on each distro, mimi loads its probe against that distro's own kernel BTF (CO-RE),
and banken reads mimi's OCSF stream as a `--watch` daemon. This proves the sensor-to-brain
integration on real vendor kernels, not just the nixpkgs kernels of mimi's own CO-RE matrix.

banken's flake stays decoupled from mimi: `nix run .#distro-matrix` is banken-raw (A-E only).
[`default.nix`](default.nix) takes an optional `mimiBundle` argument; when it is set, the payload
carries the portable mimi bundle and [`mimicheck.sh`](mimicheck.sh), and `distrocheck` runs M1-M5.
A small throwaway flake supplies the bundle (built from mimi's package plus the glibc loader) and
calls `default.nix` with it:

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

mimi is built dynamically (a fully static glibc build is not possible with proc-macro crates on
one triple), so the bundle ships its interpreter and libraries alongside the binary. The guest
runs mimi as root, so it has the capabilities and the DAC access the probe needs with no extra
hardening to work around.

## Network

With no proxy in the environment (a CI runner, a workstation) the guests use QEMU's user network
directly. If `http_proxy`/`https_proxy` point at a proxy on the host's loopback (an egress
allow-list, as on the project's build host), guests reach it at `10.0.2.2` and the checker
configures the package manager for it. It also pins dnf and zypper repos to the vendor's own
host (`dl.rockylinux.org`, `repo.almalinux.org`, `dl.fedoraproject.org`,
`downloadcontent.opensuse.org`), since a mirror list hands out third-party mirrors that an
allow-list cannot name in advance. `cloud.debian.org` serves images only by redirect to
`acc.umu.se`, so an allow-list needs that host too.

## Adding a distro

Add an entry to `distros.json`:

- a versioned image URL that the vendor serves directly (not a `latest` link: it moves, and the
  checksum would break);
- the vendor's checksum (`sha256` or `sha512`);
- the package manager (`dnf`, `apt`, `zypper`, `pacman`);
- the package that provides each command the test needs on that distro.
