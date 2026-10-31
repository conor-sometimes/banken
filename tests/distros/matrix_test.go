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
	"strings"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/tests/distros/report"
)

var (
	payload = flag.String("payload", "", "dir holding distros.json, banken, distrocheck, the units, emulations and fixtures (set by the Nix app)")
	images  = flag.String("images", "", "JSON map of distro name to its verified image (set by the Nix app)")
	keep    = flag.Bool("keep", false, "copy every VM's serial log to the current directory, pass or fail")
)

// bootTimeout bounds one distro end to end: boot, package installs, every objective.
const bootTimeout = 30 * time.Minute

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
// guest powers itself off after reporting, so the VM's exit is the end.
func boot(t *testing.T, d distro, image string, expected map[string][]string) report.Report {
	t.Helper()
	dir := t.TempDir()
	overlay := filepath.Join(dir, "overlay.qcow2") // copy-on-write: the image is never written
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "20G")
	seed := writeSeed(t, dir, d, expected)
	serial := filepath.Join(dir, "serial.log")

	ctx, cancel := context.WithTimeout(context.Background(), bootTimeout)
	defer cancel()
	var stderr bytes.Buffer
	qemu := exec.CommandContext(ctx, "qemu-system-x86_64",
		"-enable-kvm", "-cpu", "host", "-m", "2048", "-smp", "2",
		"-display", "none", "-monitor", "none", "-no-reboot",
		"-drive", "file="+overlay+",if=virtio,format=qcow2",
		"-drive", "file="+seed+",media=cdrom,readonly=on",
		"-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
		"-serial", "file:"+serial)
	qemu.Stderr = &stderr
	err := qemu.Run()

	log, _ := os.ReadFile(serial)
	if *keep {
		_ = os.WriteFile(d.Name+"-serial.log", log, 0o600)
	}
	rep, found := findReport(log)
	if !found {
		reason := fmt.Sprintf("qemu: %v %s", err, strings.TrimSpace(stderr.String()))
		if ctx.Err() != nil {
			reason = fmt.Sprintf("no report within %s", bootTimeout)
		}
		t.Fatalf("%s; last serial lines:\n%s", reason, tail(string(log), 40))
	}
	return rep
}

// writeSeed builds the NoCloud seed ISO (label cidata): a one-line cloud-init
// config that runs distrocheck from the seed, plus everything it needs.
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
	cfg, err := json.Marshal(report.Config{
		Distro: d.Name, PM: d.PM, Packages: d.Packages, Proxy: guestProxy(), Expected: expected,
	})
	must(t, err)
	must(t, os.WriteFile(filepath.Join(root, "config.json"), cfg, 0o600))
	must(t, os.WriteFile(filepath.Join(root, "meta-data"),
		[]byte("instance-id: banken-"+d.Name+"\nlocal-hostname: banken-"+d.Name+"\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(root, "user-data"), []byte(`#cloud-config
runcmd:
  - [sh, -c, "mkdir -p /mnt/seed && (mount -o ro LABEL=cidata /mnt/seed || mount -o ro /dev/sr0 /mnt/seed) && /mnt/seed/distrocheck"]
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
	for _, rules := range want {
		sort.Strings(rules)
	}
	return want
}

func findReport(serial []byte) (report.Report, bool) {
	var rep report.Report
	for _, line := range strings.Split(string(serial), "\n") {
		if i := strings.Index(line, report.Marker); i >= 0 &&
			json.Unmarshal([]byte(strings.TrimSpace(line[i+len(report.Marker):])), &rep) == nil {
			return rep, true
		}
	}
	return rep, false
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
