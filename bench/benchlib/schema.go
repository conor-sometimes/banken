package benchlib

import (
	"encoding/json"
	"io"
	"os"
	"runtime"
	"strings"
	"time"
)

// SchemaVersion identifies the raw-JSON shape so a consumer (a trend dashboard,
// a README generator) can refuse a file it does not understand. Bump it on an
// incompatible change to Run/Section/Metric.
const SchemaVersion = "banken-bench/1"

// Run is one invocation of the bench tool on one platform: the metadata needed
// to make the numbers credible (the spec's method rule -- pin hardware and
// kernel) plus a section per benchmark category. The matrix harness writes one
// Run per distro, so a reader can line them up as one row per platform.
type Run struct {
	Schema    string    `json:"schema"`
	Tool      string    `json:"tool"`
	Generated time.Time `json:"generated"`
	// Platform is the matrix row this run belongs to: the distro name under the
	// VM harness ("rocky-9"), or empty for a direct run on the host named in Host.
	Platform string    `json:"platform,omitempty"`
	Host     Host      `json:"host"`
	Sections []Section `json:"sections"`
}

// Host pins where the numbers came from. CPU and Kernel are read from /proc on
// Linux and left empty elsewhere (the benches that matter run on Linux).
type Host struct {
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	NumCPU    int    `json:"numCpu"`
	CPU       string `json:"cpu"`
	Kernel    string `json:"kernel"`
	GoVersion string `json:"goVersion"`
}

// Status is whether a section holds real measurements or is wired but awaiting
// a run the current environment cannot do (a 24h soak, a VM reboot, the live
// mimi sensor, a fork bomb). The honesty rule: a pending section carries no
// invented numbers, only the note saying what it needs.
type Status string

const (
	StatusMeasured Status = "measured"
	StatusPending  Status = "pending"
)

// Section is one benchmark category from the spec.
type Section struct {
	Category string   `json:"category"`
	Status   Status   `json:"status"`
	Note     string   `json:"note,omitempty"`
	Metrics  []Metric `json:"metrics,omitempty"`
}

// Metric is one number (or one distribution). Stat carries a latency
// distribution (p50/p99/max); Value carries a scalar (events/sec, bytes, a
// count). Exactly one is set. Extra holds dimension labels and secondary
// numbers (rule count, allocs/op, drops) that belong with the metric.
type Metric struct {
	Name  string         `json:"name"`
	Unit  string         `json:"unit"`
	Stat  *Stats         `json:"stat,omitempty"`
	Value *float64       `json:"value,omitempty"`
	Extra map[string]any `json:"extra,omitempty"`
}

// Scalar is a convenience constructor for a single-value metric.
func Scalar(name, unit string, v float64, extra map[string]any) Metric {
	return Metric{Name: name, Unit: unit, Value: &v, Extra: extra}
}

// Dist is a convenience constructor for a distribution metric.
func Dist(name, unit string, s Stats, extra map[string]any) Metric {
	return Metric{Name: name, Unit: unit, Stat: &s, Extra: extra}
}

// DetectHost fills Host from the running machine. It never fails: a field it
// cannot read is left empty rather than aborting a benchmark run.
func DetectHost() Host {
	h := Host{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		NumCPU:    runtime.NumCPU(),
		GoVersion: runtime.Version(),
	}
	h.Hostname, _ = os.Hostname()
	if runtime.GOOS == "linux" {
		h.Kernel = strings.TrimSpace(readFile("/proc/sys/kernel/osrelease"))
		h.CPU = cpuModel()
	}
	return h
}

func cpuModel() string {
	for _, line := range strings.Split(readFile("/proc/cpuinfo"), "\n") {
		if name, ok := strings.CutPrefix(line, "model name"); ok {
			if _, v, found := strings.Cut(name, ":"); found {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// Write emits the Run as indented JSON (the raw artifact published beside the
// script, the same way the ATT&CK loop publishes results.ndjson).
func (r Run) Write(w io.Writer) error {
	r.Schema = SchemaVersion
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
