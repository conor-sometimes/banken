// Package report is the distro matrix's wire format: the one line the guest
// program (distrocheck) writes to the serial console when it is done, and the
// host test (matrix_test.go) reads back. Typed JSON both ways, so neither side
// scrapes text.
package report

// Marker starts the report line on the serial console. Everything else the
// guest's console prints (kernel, cloud-init) is ignored.
const Marker = "DISTROCHECK "

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
