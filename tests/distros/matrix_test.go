//go:build distros

// Package distros is the live distro matrix (README.md): every distro in
// distros.json booted from its official cloud image under KVM, banken installed
// the way the docs say, and every objective checked by distrocheck inside the
// guest. Each distro is a subtest and each objective a subtest of that, so the
// matrix is ordinary `go test` output:
//
//	--- FAIL: TestMatrix/alma-10/D2
//
// Run it with `nix run .#distro-matrix`, which builds banken and distrocheck,
// fetches and verifies the images, and passes -payload and -images.
package distros

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/tests/distros/report"
)

var (
	payload = flag.String("payload", "", "dir holding distros.json, banken, distrocheck, the units, emulations and fixtures (set by the Nix app)")
	images  = flag.String("images", "", "JSON map of distro name to its verified image (set by the Nix app)")
	keep    = flag.Bool("keep", false, "keep every VM's work dir (disk overlay, serial log, report) and print where, pass or fail")
	// bootTimeout bounds one distro end to end: boot, package installs, every objective.
	bootTimeout = flag.Duration("boot-timeout", 30*time.Minute, "longest one distro may take, boot to report")
)

type distro struct {
	Name     string            `json:"name"`
	PM       string            `json:"pm"`
	Packages map[string]string `json:"packages"`
}

func TestMatrix(t *testing.T) {
	if *payload == "" || *images == "" {
		t.Skip("run through: nix run .#distro-matrix")
	}
	var distros []distro
	readJSON(t, filepath.Join(*payload, "distros.json"), &distros)
	var imgs map[string]string
	readJSON(t, *images, &imgs)
	expected := expectedRules(t)

	for _, d := range distros {
		t.Run(d.Name, func(t *testing.T) {
			t.Parallel()
			image, ok := imgs[d.Name]
			if !ok {
				t.Fatalf("no image for %s", d.Name)
			}
			rep := boot(t, d, image, expected)
			for _, k := range sortedKeys(rep.Info) {
				t.Logf("%s: %s", k, rep.Info[k])
			}
			for _, c := range rep.Checks {
				t.Run(c.ID, func(t *testing.T) {
					if !c.Pass {
						t.Error(c.Detail)
					}
				})
			}
		})
	}
}

// boot runs one distro to completion and returns distrocheck's report. The
// report arrives on a small raw virtio disk (see report.Disk); the serial
// console is kept only to show when something goes wrong. The guest powers
// itself off after reporting, so the VM's exit is the end.
func boot(t *testing.T, d distro, image string, expected map[string][]string) report.Report {
	t.Helper()
	dir := t.TempDir()
	if *keep {
		var err error
		dir, err = os.MkdirTemp("", "banken-"+d.Name+"-")
		must(t, err)
		t.Logf("work dir kept: %s", dir)
	}
	// Copy-on-write: the image is never written. The overlay is the image's own
	// size or minDisk, whichever is larger: smaller than the partition table
	// describes and the guest kernel rejects the disk (Amazon Linux's image is
	// 25 GiB); too small and installs and the audit log fill it (openSUSE's
	// minimal image is a few GiB). cloud-init grows the root partition to fit.
	overlay := filepath.Join(dir, "overlay.qcow2")
	size := max(imageSize(t, image), minDisk)
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, strconv.FormatInt(size, 10))
	seed := writeSeed(t, dir, d, expected)
	serial := filepath.Join(dir, "serial.log")
	reportFile := filepath.Join(dir, "report.img")
	must(t, os.WriteFile(reportFile, make([]byte, 1<<20), 0o600))

	ctx, cancel := context.WithTimeout(context.Background(), *bootTimeout)
	defer cancel()
	var stderr bytes.Buffer
	qemu := exec.CommandContext(ctx, "qemu-system-x86_64",
		"-enable-kvm", "-cpu", "host", "-m", "2048", "-smp", "2",
		"-display", "none", "-monitor", "none", "-no-reboot",
		// Explicit devices so the root disk is booted first: left to itself the
		// firmware may try the blank report disk and stop there, silently.
		"-drive", "file="+overlay+",if=none,id=root,format=qcow2",
		"-device", "virtio-blk-pci,drive=root,bootindex=0",
		"-drive", "file="+seed+",media=cdrom,readonly=on",
		"-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
		"-drive", "file="+reportFile+",if=none,id=report,format=raw",
		"-device", "virtio-blk-pci,drive=report,serial="+report.Disk,
		"-serial", "file:"+serial)
	qemu.Stderr = &stderr
	err := qemu.Run()

	log, _ := os.ReadFile(serial)
	var rep report.Report
	data, _ := os.ReadFile(reportFile)
	if end := bytes.IndexByte(data, 0); end >= 0 {
		data = data[:end]
	}
	if json.Unmarshal(data, &rep) != nil {
		reason := fmt.Sprintf("qemu: %v %s", err, strings.TrimSpace(stderr.String()))
		if ctx.Err() != nil {
			reason = fmt.Sprintf("no report within %s", *bootTimeout)
		}
		t.Fatalf("%s; last serial lines:\n%s", reason, tail(string(log), 40))
	}
	return rep
}

// writeSeed builds the NoCloud seed ISO (label cidata): distrocheck, what it
// needs, and a cloud-init config that starts it. The config uses bootcmd,
// cloud-init's first stage, which every distro runs, to install a systemd unit
// that runs distrocheck once the network is online. (runcmd, in cloud-init's
// last stage, never runs on images where that stage waits on a target that is
// not reached, as on Arch.) distrocheck is copied off the ISO into
// /usr/local/sbin first: SELinux will not let systemd execute a file labelled
// for an ISO, and the copy takes the directory's ordinary binary label.
func writeSeed(t *testing.T, dir string, d distro, expected map[string][]string) string {
	t.Helper()
	root := filepath.Join(dir, "seed")
	must(t, os.MkdirAll(filepath.Join(root, "emulations"), 0o755))
	for _, f := range []string{"banken", "distrocheck", "banken.service", "banken.timer"} {
		copyFile(t, filepath.Join(*payload, f), filepath.Join(root, f))
	}
	scripts, _ := filepath.Glob(filepath.Join(*payload, "emulations", "*.sh"))
	for _, s := range scripts {
		copyFile(t, s, filepath.Join(root, "emulations", filepath.Base(s)))
	}
	// E1: every package's test binary and the source tree they read fixtures from.
	must(t, os.MkdirAll(filepath.Join(root, "suite"), 0o755))
	bins, _ := filepath.Glob(filepath.Join(*payload, "suite", "*.test"))
	for _, b := range bins {
		copyFile(t, b, filepath.Join(root, "suite", filepath.Base(b)))
	}
	copyFile(t, filepath.Join(*payload, "src.tar"), filepath.Join(root, "src.tar"))
	// Test B (banken + mimi): the portable mimi bundle and its in-guest driver, present only when
	// the matrix was built with a mimi bundle (default.nix mimiBundle). Absent -> distrocheck sees no
	// mimicheck.sh and skips the M1-M5 objectives, so banken's own banken-raw matrix is unchanged.
	if _, err := os.Stat(filepath.Join(*payload, "mimicheck.sh")); err == nil {
		copyFile(t, filepath.Join(*payload, "mimicheck.sh"), filepath.Join(root, "mimicheck.sh"))
		must(t, os.MkdirAll(filepath.Join(root, "mimi-bundle"), 0o755))
		bundle, _ := filepath.Glob(filepath.Join(*payload, "mimi-bundle", "*"))
		for _, b := range bundle {
			copyFile(t, b, filepath.Join(root, "mimi-bundle", filepath.Base(b)))
		}
	}
	cfg, err := json.Marshal(report.Config{
		Distro: d.Name, PM: d.PM, Packages: d.Packages, Proxy: guestProxy(), Expected: expected,
	})
	must(t, err)
	must(t, os.WriteFile(filepath.Join(root, "config.json"), cfg, 0o600))
	must(t, os.WriteFile(filepath.Join(root, "meta-data"),
		[]byte("instance-id: banken-"+d.Name+"\nlocal-hostname: banken-"+d.Name+"\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(root, "distrocheck.service"), []byte(`[Unit]
Description=banken distro matrix checker (test VM only)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/distrocheck -seed /mnt/seed
`), 0o600))
	must(t, os.WriteFile(filepath.Join(root, "user-data"), []byte(`#cloud-config
bootcmd:
  - [sh, -c, "mkdir -p /mnt/seed && (mount -o ro LABEL=cidata /mnt/seed || mount -o ro /dev/sr0 /mnt/seed) && install -D -m0755 /mnt/seed/distrocheck /usr/local/sbin/distrocheck && cp /mnt/seed/distrocheck.service /run/systemd/system/ && systemctl daemon-reload && systemctl start --no-block distrocheck.service"]
`), 0o600))
	iso := filepath.Join(dir, "seed.iso")
	run(t, "xorriso", "-as", "mkisofs", "-quiet", "-output", iso, "-volid", "cidata", "-joliet", "-rock", root)
	return iso
}

// guestProxy is the host's proxy as a guest sees it: QEMU's user network
// reaches the host's loopback at 10.0.2.2. Empty when the host has no proxy.
func guestProxy() string {
	p := os.Getenv("https_proxy")
	if p == "" {
		p = os.Getenv("http_proxy")
	}
	u, err := url.Parse(p)
	if p == "" || err != nil || u.Hostname() == "" {
		return ""
	}
	host := u.Hostname()
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		host = "10.0.2.2"
	}
	port := u.Port()
	if port == "" {
		port = "3128"
	}
	return u.Scheme + "://" + host + ":" + port
}

// expectedRules maps each emulation family to the rules its fixtures name
// (tests/fixtures/<family>.expect-<rule>.json), as tests/vm.nix does.
func expectedRules(t *testing.T) map[string][]string {
	t.Helper()
	want := map[string][]string{}
	scripts, _ := filepath.Glob(filepath.Join(*payload, "emulations", "*.sh"))
	for _, s := range scripts {
		want[strings.TrimSuffix(filepath.Base(s), ".sh")] = []string{}
	}
	fixtures, _ := filepath.Glob(filepath.Join(*payload, "fixtures", "*.expect-*.json"))
	for _, f := range fixtures {
		family, rule, _ := strings.Cut(strings.TrimSuffix(filepath.Base(f), ".json"), ".expect-")
		if _, ok := want[family]; ok && rule != "none" {
			want[family] = append(want[family], rule)
		}
	}
	// The live matrix proves banken's default, distro-portable detections. Three classes of rule
	// cannot be proven here, so their emulation families are dropped (each is proven instead by the
	// engine golden tests, whose fixtures carry the right user and paths):
	//   - account-scoped agent rules (rules/agent/, keyed on an agent User): the emulations run under
	//     a cloud-init service with no agent login, so the audit auid never matches the User branch;
	//   - honeytoken_access: keys on decoy files plus audit watches that exist only on a containment
	//     host, not a stock cloud image;
	//   - the optional rules (netcat, password_cracker): opt-in and off by default, so the default
	//     posture under test never loads them, and enabling netcat would cross-fire into the
	//     revshell and portscan emulations.
	for family, rules := range want {
		for _, r := range rules {
			if strings.HasPrefix(r, "agent_") || r == "honeytoken_access" || r == "netcat" || r == "password_cracker" {
				delete(want, family)
				break
			}
		}
	}
	for _, rules := range want {
		sort.Strings(rules)
	}
	return want
}

// minDisk is the smallest disk a guest gets: room for package installs, the
// test suite and a day of audit log.
const minDisk = 20 << 30

// imageSize is an image's virtual size in bytes.
func imageSize(t *testing.T, image string) int64 {
	t.Helper()
	out, err := exec.Command("qemu-img", "info", "--output=json", image).Output()
	must(t, err)
	var info struct {
		VirtualSize int64 `json:"virtual-size"`
	}
	must(t, json.Unmarshal(out, &info))
	return info.VirtualSize
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", name, err, out)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	must(t, err)
	must(t, json.Unmarshal(data, v))
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	fi, err := os.Stat(src)
	must(t, err)
	data, err := os.ReadFile(src)
	must(t, err)
	must(t, os.WriteFile(dst, data, fi.Mode().Perm()))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
