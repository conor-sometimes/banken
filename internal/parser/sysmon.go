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

// Sysmon ingests Sysmon-for-Linux events. Microsoft's sysmonforlinux logs the same XML event shape
// as Windows Sysmon (<Event><System><EventID>..</System><EventData><Data Name="..">..</Data>..),
// one per syslog line, and its EventData field names (Image, CommandLine, ParentImage, User,
// TargetFilename, ...) are exactly banken's own event fields. So this parser both gives a Linux host
// a Sysmon source and makes banken's Windows Sysmon source half-written: the huge body of Windows
// Sigma rules was authored against these very field names. A line that is not a parseable Sysmon
// event is skipped, like every parser, so a syslog stream carrying other lines is fine.
type Sysmon struct{}

// Name implements Parser.
func (Sysmon) Name() string { return sysmonName }

type sysmonXMLEvent struct {
	System struct {
		EventID int `xml:"EventID"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// Parse implements Parser.
func (p Sysmon) Parse(r io.Reader) ([]event.Event, error) {
	var events []event.Event
	err := scanLines(r, func(line []byte) {
		// Strip any syslog prefix: take from the first "<Event" to the last "</Event>".
		s := string(line)
		i := strings.Index(s, "<Event")
		j := strings.LastIndex(s, "</Event>")
		if i < 0 || j < 0 || j < i {
			return
		}
		var x sysmonXMLEvent
		if xml.Unmarshal([]byte(s[i:j+len("</Event>")]), &x) != nil {
			return // not a Sysmon event -- skip, keep going
		}
		events = append(events, sysmonToEvent(&x))
	})
	return events, err
}

// sysmonToEvent maps a Sysmon event's EventData onto the common event. The well-known names map to
// the typed fields banken's rules key on; everything else (ParentCommandLine, Hashes,
// OriginalFileName, DestinationIp, ...) is preserved in Raw so a rule can still reach it, and the
// EventID is recorded there too.
func sysmonToEvent(x *sysmonXMLEvent) event.Event {
	ev := event.Event{Source: sysmonName, Raw: map[string]string{"EventID": strconv.Itoa(x.System.EventID)}}
	for _, d := range x.Data {
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
		case "UtcTime":
			// Sysmon's timestamp, e.g. "2026-11-01 14:33:22.279".
			if t, err := time.Parse("2006-01-02 15:04:05.000", v); err == nil {
				ev.Time = t.UTC()
			}
		default:
			if v != "" {
				ev.Raw[d.Name] = v
			}
		}
	}
	return ev
}
