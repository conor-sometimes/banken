package view

import (
	"encoding/json"
	"errors"
	"io/fs"
	"time"
)

// MapProber is a Prober backed by a committed map of live facts keyed by handle
// id. It is how the golden tests drive state computation end to end from a
// fixture tree with no live host: the fixture's live.json records what the
// system would show for each handle (the cgroup state, the live inode, the
// re-hash, the current boot id), and MapProber hands it to ComputeState exactly
// as SysProber would on a real host.
type MapProber map[string]LiveFacts

// Probe returns the recorded facts for an entry, or an unobserved LiveFacts
// (Known false) when the fixture has none, so a missing fixture entry reads as
// StateUnknown rather than a loss.
func (m MapProber) Probe(e Entry) LiveFacts {
	if f, ok := m[e.ID]; ok {
		return f
	}
	return LiveFacts{}
}

// LoadMapProber reads a MapProber from a JSON object file (handle id ->
// LiveFacts) at the given root-relative path. A missing file yields an empty
// prober, not an error (a fixture or a host may simply have no live snapshot).
func LoadMapProber(root fs.FS, name string) (MapProber, error) {
	b, err := fs.ReadFile(root, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return MapProber{}, nil
		}
		return nil, err
	}
	var m MapProber
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = MapProber{}
	}
	return m, nil
}

// clock renders a time as HH:MM:SS in UTC for the compact state column
// ("thawed 06:40:12"); a zero time renders empty.
func clock(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("15:04:05")
}

// stamp renders a time as the full ledger timestamp for the WHEN column and the
// explain header.
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}
