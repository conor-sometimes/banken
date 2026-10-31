# Live distro matrix

banken's detections, tested live on each distro's own kernel and auditd. Containers
cannot do this: the Linux audit subsystem is not namespaced, so a container shares the
host's one audit stream. Each distro here is a real VM.

For every distro in [`distros.json`](distros.json), [`run.py`](run.py):

1. fetches the vendor's official cloud image once and checks the vendor's published
   checksum (pinned in the manifest);
2. boots a throwaway copy-on-write overlay of it under KVM, with a cloud-init seed ISO;
3. inside, [`guest.sh`](guest.sh) does what [docs/deployment.md](../../docs/deployment.md)
   tells an operator to do: installs auditd and friends from the distro's own repos, loads
   banken's audit rules the documented way (`augenrules --load`), and installs banken with
   the canonical portable unit (`packaging/systemd/banken.service`). It then runs each
   `tests/emulations/<family>.sh` as an ordinary user (`runuser`, since `su`/`sudo` would
   fire a rule) and scans after each one;
4. reads the results off the serial console and compares each family with the rules its
   fixtures name (`tests/fixtures/<family>.expect-<rule>.json`), exactly as the NixOS VM
   test (`tests/vm.nix`) does. A miss and a false positive both fail.

It prints a distro × family matrix and exits non-zero on any mismatch, any error, or a
portable unit that does not start. If the unit fails, the guest reports that and still
runs banken directly, so one problem cannot hide the detection results.

Every distro is a systemd distro: banken supports systemd hosts only, because its security
model is that unit's sandbox (see [docs/deployment.md](../../docs/deployment.md#supported-platforms)).
NixOS is covered by `tests/vm.nix` (`nix flake check`), which tests the NixOS module itself.

## Run

Needs KVM, `qemu-system-x86_64`, `qemu-img`, `xorriso`, Python 3, and a static
linux/amd64 banken:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o output/banken-linux-amd64 .
python3 tests/distros/run.py --banken output/banken-linux-amd64              # all distros
python3 tests/distros/run.py --banken output/banken-linux-amd64 --only rocky-9 debian-13
```

`--keep` keeps every VM's work directory (serial log included); a failing distro's is
always kept and printed. `--jobs` sets how many VMs boot at once (default 3).

## Network

The guests install packages from their distro's repos. With no proxy in the environment
(a CI runner, a workstation) they use QEMU's user network directly. If `http_proxy` /
`https_proxy` point at a proxy on the host's loopback (an egress allow-list, as on the
project's build host), guests reach it at `10.0.2.2` and `guest.sh` configures the package
manager for it. It also pins each repo to the vendor's own host (`dl.rockylinux.org`,
`repo.almalinux.org`, `dl.fedoraproject.org`, `downloadcontent.opensuse.org`, ...), since a
mirror list hands out third-party mirrors that an allow-list cannot name in advance.

`cloud.debian.org` only redirects to mirrors, so behind an allow-list that does not name
them, put Debian's image in the cache (`--cache`, default `~/.cache/banken-distros`)
yourself; `run.py` only downloads what is missing, and always checks the checksum.

## Adding a distro

Add an entry to `distros.json`: a versioned image URL that the vendor serves directly
(not a `latest` link: it moves, and the checksum would break), the vendor's checksum
(`sha256` or `sha512`), the package manager (`dnf`, `apt`, `zypper`, `pacman`), and the
package that provides each command the test needs on that distro.
