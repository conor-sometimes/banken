package view

import (
	"fmt"

	"github.com/conor-sometimes/banken/internal/response"
)

// LiveFacts is everything ComputeState needs to know about the live system for
// one store entry. A Prober gathers it (SysProber from the real system on
// Linux, MapProber from a committed fixture in a test); ComputeState is pure
// over it, so a state string is reproducible from a fixture and the same code
// runs on a host. Zero values mean "not observed": an unpopulated freeze or a
// vanished file reads as lost, never as healthy.
type LiveFacts struct {
	// Known is false when the Prober could not observe this entry at all (e.g.
	// the non-Linux stub). ComputeState then returns StateUnknown rather than
	// inventing a loss.
	Known bool `json:"known"`

	// BootID is the current kernel boot id, for the freeze reboot check.
	BootID string `json:"bootId,omitempty"`

	// Freeze: the live cgroup.
	CgroupExists bool  `json:"cgroupExists,omitempty"`
	CgroupFrozen bool  `json:"cgroupFrozen,omitempty"`
	CgroupPIDs   []int `json:"cgroupPids,omitempty"`

	// Quarantine: the live inode (the stored file for rename, origPath for
	// neuter) and its current protection.
	TargetExists bool   `json:"targetExists,omitempty"`
	Dev          uint64 `json:"dev,omitempty"`
	Ino          uint64 `json:"ino,omitempty"`
	Mode         uint32 `json:"mode,omitempty"` // st_mode & 07777
	Immutable    bool   `json:"immutable,omitempty"`
	SHA256       string `json:"sha256,omitempty"` // re-hash of the stored file (rename), "" when not hashed
}

// Prober gathers the live facts for one store entry. It is the view's single
// seam to the live system; everything else is pure over the fs.FS.
type Prober interface {
	Probe(e Entry) LiveFacts
}

// State is the computed state string of §3.1. It is the human column and the
// `-json` "state" field; a Classification groups states for the -state filter.
type State string

const (
	StateUnknown State = "unknown"
)

// stateKind buckets a State for the list -state filter (held|frozen|thawed|
// restored|lost). It reads the leading word, so "held sha256 ok", "held
// neuter-weak" and "held" all bucket as held, and "frozen (2 pids)" as frozen.
func stateKind(s State) string {
	str := string(s)
	for i := 0; i < len(str); i++ {
		if str[i] == ' ' {
			return str[:i]
		}
	}
	return str
}

// ComputeState turns a store entry plus the live facts into the §3.1 state
// string. It branches structurally over manifest and live fields -- never over
// another layer's error string -- so the mapping is exactly the table in §3.1:
//
//   - freeze: tombstone -> thawed; boot id differs -> lost (reboot); cgroup
//     gone -> lost (cgroup gone); every pid present and frozen -> frozen (N
//     pids); a pid missing -> frozen (pid X escaped).
//   - quarantine rename: tombstone -> restored; inode differs -> lost (inode
//     replaced); re-hash -> held sha256 ok | held CHANGED | held unhashed.
//   - quarantine neuter: tombstone -> restored; inode differs -> lost (inode
//     replaced); mode 0 + immutable -> held; weak bit -> held neuter-weak;
//     mode restored or immutable cleared -> TAMPERED.
//   - collect: collected.
func ComputeState(e Entry, f LiveFacts) State {
	switch e.Kind {
	case response.ActionFreeze:
		return freezeState(e, f)
	case response.ActionQuarantine:
		return quarantineState(e, f)
	case response.ActionCollect:
		return State("collected")
	default:
		return StateUnknown
	}
}

func freezeState(e Entry, f LiveFacts) State {
	if e.Thawed {
		return State("thawed " + clock(e.ThawedAt))
	}
	m := e.Freeze
	if m == nil {
		return StateUnknown
	}
	// The sigstop fallback has no cgroup to read; the store entry is the only
	// record, so a non-thawed sigstop handle reads as frozen from the manifest.
	if m.Method == methodSigstop {
		return State(fmt.Sprintf("frozen (%d pids, sigstop)", len(m.PIDs)))
	}
	if !f.Known {
		return StateUnknown
	}
	if m.BootID != "" && f.BootID != "" && m.BootID != f.BootID {
		return State("lost (reboot)")
	}
	if !f.CgroupExists {
		return State("lost (cgroup gone)")
	}
	present := make(map[int]bool, len(f.CgroupPIDs))
	for _, p := range f.CgroupPIDs {
		present[p] = true
	}
	for _, p := range m.PIDs {
		if !present[p] {
			return State(fmt.Sprintf("frozen (pid %d escaped)", p))
		}
	}
	if !f.CgroupFrozen {
		return State(fmt.Sprintf("running (%d pids, freeze released)", len(m.PIDs)))
	}
	return State(fmt.Sprintf("frozen (%d pids)", len(m.PIDs)))
}

func quarantineState(e Entry, f LiveFacts) State {
	if e.Restored {
		s := "restored " + clock(e.RestoredAt)
		if e.RestoreDest != "" {
			s += " -> " + e.RestoreDest
		}
		return State(s)
	}
	m := e.Quar
	if m == nil {
		return StateUnknown
	}
	if !f.Known {
		return StateUnknown
	}
	if !f.TargetExists || f.Dev != m.Stat.Dev || f.Ino != m.Stat.Ino {
		return State("lost (inode replaced)")
	}
	switch m.Method {
	case methodRename:
		switch {
		case isUnhashed(m.SHA256):
			return State("held unhashed")
		case f.SHA256 == m.SHA256:
			return State("held sha256 ok")
		default:
			return State(fmt.Sprintf("held CHANGED (was %s, now %s)", shortHash(m.SHA256), shortHash(f.SHA256)))
		}
	case methodNeuter:
		neutered := f.Mode&0o7777 == 0
		switch {
		case neutered && f.Immutable:
			return State("held")
		case neutered && !m.Immutable:
			// The immutable bit never took (a non-root-owned file, Q3.3): the
			// file is still mode 0 but an owner could chmod it back.
			return State("held neuter-weak")
		default:
			return State(fmt.Sprintf("TAMPERED (mode %04o, immutable %s)", f.Mode&0o7777, boolDigit(f.Immutable)))
		}
	default:
		return StateUnknown
	}
}

// boolDigit renders a bool as the 1/0 the §3.1 TAMPERED line shows.
func boolDigit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// shortHash is the first 8 hex of a digest for the CHANGED line, or the whole
// value when it is already short (a sentinel, or empty).
func shortHash(sum string) string {
	if len(sum) <= 8 {
		return sum
	}
	return sum[:8]
}
