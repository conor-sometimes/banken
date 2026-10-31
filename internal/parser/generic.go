package parser

import (
	"encoding/json"
	"io"

	"github.com/conor-sometimes/banken/internal/event"
)

const genericName = "generic"

// Generic ingests one already-normalised event.Event per JSON line, verbatim.
// It is the universal adapter: any external collector that cannot (or should
// not) live inside banken -- an eBPF/Falco exporter, a macOS Endpoint Security
// helper, a Windows Sysmon/ETW shipper -- emits the common event as JSON lines
// and plugs in through this one parser, with no bespoke Go parser per source.
// See docs/log-sources.md.
//
// The line format is exactly event.Event's JSON shape (camelCase fields:
// image, commandLine, parentImage, targetFilename, user, currentDirectory,
// time, source, raw). A line that is not valid JSON is skipped, like every
// other parser, so one bad line never fails the batch.
type Generic struct{}

// Name implements Parser.
func (Generic) Name() string { return genericName }

// Parse implements Parser.
func (p Generic) Parse(r io.Reader) ([]event.Event, error) {
	var events []event.Event
	err := scanLines(r, func(line []byte) {
		var ev event.Event
		if json.Unmarshal(line, &ev) != nil {
			return // not valid JSON -- skip, keep going
		}
		if ev.Source == "" {
			ev.Source = genericName
		}
		events = append(events, ev)
	})
	return events, err
}
