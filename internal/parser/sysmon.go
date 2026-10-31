package parser

import (
	"encoding/xml"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
)

const sysmonName = "sysmon"

// Sysmon parses Windows Sysmon events in Windows Event Log XML -- the native
// render of `wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml`, of
// PowerShell `Get-WinEvent ... | ForEach { $_.ToXml() }`, and of what a
// shipper (Vector's windows_event_log, winlogbeat) forwards. It is banken's
// first Windows source: a process-creation event (Sysmon EventID 1) maps
// onto the same fields a Linux exec does, so SigmaHQ's Windows
// process_creation rules match it with no translation, and every other Sysmon
// field is carried in Raw under its own name, so a rule keying on a
// Windows-specific field (Hashes, IntegrityLevel, TargetObject, ...) works
// through Event.Field's Raw fallback with no code change here.
//
// Scaffold status (docs/windows.md): the field mapping below is complete for
// process_creation and covers the common fields of the file/registry/network
// Sysmon events; logsource-aware rule routing (so Windows rules run only on
// Windows events) is the next piece. The parser holds the usual contract:
// never panics, skips a record it cannot read, and returns an error only for
// an I/O failure of the reader.
type Sysmon struct{}

// Name implements Parser.
func (Sysmon) Name() string { return sysmonName }

// winEvent is one <Event> of Windows Event Log XML: the System envelope and
// the flat Name=Value list every Sysmon event carries in EventData.
type winEvent struct {
	System struct {
		EventID  int `xml:"EventID"`
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// Parse reads a stream of <Event> elements and normalises each into an
// event.Event. Malformed XML is content, not an I/O failure, so a decode
// problem ends the usable stream and returns what was read so far with a nil
// error -- a bad record never fails the batch, exactly as the line-based
// parsers treat a bad line.
func (Sysmon) Parse(r io.Reader) ([]event.Event, error) {
	dec := xml.NewDecoder(r)
	var events []event.Event
	for {
		tok, err := dec.Token()
		if err != nil {
			return events, nil // EOF or a syntax error: stop, keep what parsed
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var we winEvent
		if dec.DecodeElement(&we, &se) != nil {
			continue // skip this record, resume at the next token
		}
		events = append(events, sysmonEvent(we))
	}
}

// sysmonEvent maps one parsed Windows event to the common Event. The named
// fields that line up with a Linux exec are set directly (so Sigma's
// process_creation field names match); everything else is kept in Raw under
// its Sysmon name.
func sysmonEvent(we winEvent) event.Event {
	ev := event.Event{Source: sysmonName, Time: sysmonTime(we)}
	for _, d := range we.EventData.Data {
		if d.Name == "" {
			continue
		}
		v := strings.TrimSpace(d.Value)
		switch d.Name {
		case "Image":
			ev.Image = v
		case "CommandLine":
			ev.CommandLine = v
		case "ParentImage":
			ev.ParentImage = v
		case "CurrentDirectory":
			ev.CurrentDirectory = v
		case "User":
			ev.User = v
		case "TargetFilename":
			ev.TargetFilename = v
		case "ProcessId":
			if n, err := strconv.Atoi(v); err == nil {
				ev.PID = n
			}
		case "ParentProcessId":
			if n, err := strconv.Atoi(v); err == nil {
				ev.PPID = n
			}
		default:
			if v != "" {
				if ev.Raw == nil {
					ev.Raw = map[string]string{}
				}
				ev.Raw[d.Name] = v
			}
		}
	}
	// The Windows Sigma field EventID is how many rules select the event
	// type; keep it alongside the computer name for provenance.
	if ev.Raw == nil {
		ev.Raw = map[string]string{}
	}
	ev.Raw["EventID"] = strconv.Itoa(we.System.EventID)
	if we.System.Computer != "" {
		ev.Raw["Computer"] = we.System.Computer
	}
	return ev
}

// sysmonTime reads the event time: the System TimeCreated SystemTime
// (RFC 3339, high-precision), falling back to the EventData UtcTime Sysmon
// writes ("2006-01-02 15:04:05.000", UTC). Zero if neither parses.
func sysmonTime(we winEvent) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, we.System.TimeCreated.SystemTime); err == nil {
		return t.UTC()
	}
	for _, d := range we.EventData.Data {
		if d.Name == "UtcTime" {
			if t, err := time.Parse("2006-01-02 15:04:05.000", strings.TrimSpace(d.Value)); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}
