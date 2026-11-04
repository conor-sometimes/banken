// Package report is the distro matrix's wire format: the JSON report the guest
// program (distrocheck) writes when it is done, and the host test
// (matrix_test.go) reads back. Typed both ways, so neither side scrapes text.
package report

// Disk is the serial of the small raw virtio disk the report travels on: the
// guest writes the JSON to /dev/disk/by-id/virtio-<Disk>, the host reads the
// disk's file. virtio-blk is what every image boots from, so the channel needs
// no driver, console setting or udev rule the root disk does not already need.
const Disk = "banken-report"

// DiskSize is the raw report disk's size in bytes. The guest's JSON report must
// fit in it: a report that overruns is written without a trailing NUL, so the
// host reads a truncated, unparseable blob and loses the whole distro's result.
// The host allocates the disk at this size; the guest shrinks a too-large report
// to fit (keeping every verdict). Both sides use this one constant.
const DiskSize = 1 << 20

// Report is one distro's result.
type Report struct {
	Distro string            `json:"distro"`
	Info   map[string]string `json:"info"`   // recorded, not judged: versions, LSM mode, quirks
	Checks []Check           `json:"checks"` // one per objective (B1 one per emulation family)
}

// Check is one objective's verdict on one distro. ID is the objective's ID from
// tests/distros/README.md ("A2", "B1/revshell").
type Check struct {
	ID     string `json:"id"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// Config is what the host hands the guest on the seed: the distro, how to
// install on it, and what each emulation family must fire.
type Config struct {
	Distro   string              `json:"distro"`
	PM       string              `json:"pm"`       // dnf | apt | zypper | pacman
	Packages map[string]string   `json:"packages"` // command the test needs -> package providing it
	Proxy    string              `json:"proxy"`    // the host's proxy as the guest reaches it; "" for direct
	Expected map[string][]string `json:"expected"` // emulation family -> rules it must fire, sorted
}
