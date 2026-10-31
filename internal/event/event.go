// Package event defines the one normalised event every parser produces
// and every rule matches against. A new log source is a new parser (see
// the parser package) that fills this struct -- nothing downstream knows
// or cares which source a given Event came from, except through the
// Source tag it carries for provenance.
package event

import "time"

// Event is a single normalised host event -- one process execution, one
// file access -- flattened out of whatever multi-record shape its source
// log used. The field names deliberately mirror the Sigma field names the
// rules reference (Image, CommandLine, ParentImage, TargetFilename, User,
// CurrentDirectory) so the matcher can look a field up by its rule name
// without a translation table.
//
// Every field is best-effort: a source that does not carry a given datum
// leaves it the zero value, and the matcher treats an empty field as "no
// value to match" rather than an error. A parser must never fail an event
// just because one field was missing or malformed -- a dropped event is a
// dropped detection.
type Event struct {
	// Time is when the event occurred, as recorded by the source. Zero
	// if the source gave no parseable timestamp.
	Time time.Time `json:"time"`

	// Source tags which parser produced this event ("laurel", "auditd",
	// "journald", "syslog"). Provenance only; never matched on.
	Source string `json:"source"`

	// Image is the absolute path of the executed program (auditd
	// SYSCALL.exe, Laurel's SYSCALL exe).
	Image string `json:"image"`

	// CommandLine is the full command line, argv joined by single spaces
	// (from EXECVE argv, falling back to PROCTITLE).
	CommandLine string `json:"commandLine"`

	// ParentImage is the parent process's executable path, when the
	// source enriches the event with it (often empty for raw auditd,
	// which carries only ppid).
	ParentImage string `json:"parentImage"`

	// TargetFilename is the path a file-touching syscall acted on (auditd
	// PATH record name). Empty for a pure exec with no PATH record of
	// interest.
	TargetFilename string `json:"targetFilename"`

	// User is the acting user: a name if the source translated the uid,
	// otherwise the numeric uid as a string.
	User string `json:"user"`

	// CurrentDirectory is the process working directory (auditd CWD.cwd).
	CurrentDirectory string `json:"currentDirectory"`

	// Raw holds any additional source fields a parser chose to keep for
	// matching or IOC lookup but that have no dedicated field above. Keyed
	// by Sigma field name. May be nil.
	Raw map[string]string `json:"raw,omitempty"`
}

// Field returns the value of the named Sigma field, resolving the common
// named fields first and then Raw. An unknown field returns "" and false
// so the matcher can tell "field absent" from "field present but empty".
func (e Event) Field(name string) (string, bool) {
	switch name {
	case "Image":
		return e.Image, e.Image != ""
	case "CommandLine":
		return e.CommandLine, e.CommandLine != ""
	case "ParentImage":
		return e.ParentImage, e.ParentImage != ""
	case "TargetFilename":
		return e.TargetFilename, e.TargetFilename != ""
	case "User":
		return e.User, e.User != ""
	case "CurrentDirectory":
		return e.CurrentDirectory, e.CurrentDirectory != ""
	}
	if e.Raw != nil {
		v, ok := e.Raw[name]
		return v, ok
	}
	return "", false
}

// AllText returns every matchable text value on the event: the named string
// fields plus the Raw values, skipping empties. It is the single definition
// of "the fields banken searches", used both by a field-less (keyword) match
// and by the matcher's literal prefilter scan, so the two can never disagree
// about which text an event exposes. Source and Time are deliberately excluded
// (provenance, not content). The order is stable for the named fields; Raw
// values follow in map order.
func (e Event) AllText() []string {
	out := make([]string, 0, 6+len(e.Raw))
	for _, v := range []string{e.Image, e.CommandLine, e.ParentImage, e.TargetFilename, e.User, e.CurrentDirectory} {
		if v != "" {
			out = append(out, v)
		}
	}
	for _, v := range e.Raw {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
