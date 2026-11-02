//go:build !linux

package view

// SysProber off Linux observes nothing: there is no /proc, no cgroup v2 and no
// FS_IOC_GETFLAGS here. Every Probe returns an unobserved LiveFacts, so list
// and explain still run on a Mac (over a fixture, state computation is driven
// by a MapProber instead) and a live state simply reads as unknown. This keeps
// `go test ./...` and a developer's `respond explain` working off Linux without
// pretending to see a live host.
type SysProber struct {
	QuarantineDir string
	MaxFileBytes  int64
}

// NewSysProber mirrors the Linux signature so the CLI wiring is one shape.
func NewSysProber(quarantineDir string, maxFileBytes int64) SysProber {
	return SysProber{QuarantineDir: quarantineDir, MaxFileBytes: maxFileBytes}
}

// Probe returns an unobserved fact set (Known false): ComputeState then reports
// StateUnknown rather than inventing a loss.
func (SysProber) Probe(Entry) LiveFacts { return LiveFacts{} }
