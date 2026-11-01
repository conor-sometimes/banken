package alert

import (
	"strings"
	"time"
)

// ecsVersion is the Elastic Common Schema version banken's documents declare. Pinned, like the OCSF
// schema version: a consumer keys field semantics off it.
const ecsVersion = "8.11.0"

// EncodeECS returns an Encoder that renders one alert as a single Elastic Common Schema document,
// so Elastic -- and anything that speaks ECS -- ingests banken's findings natively. Like EncodeOCSF
// it is a pure Encoder over the same Alert (no new sink, stdlib only): nested ECS objects with
// omitempty, so an absent field is absent rather than a zero value. Half the SOCs run Elastic; this
// is the output they expect, with no Logstash pipeline in between.
func EncodeECS(o OCSFOptions) Encoder {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return func(a Alert) ([]byte, error) {
		return marshalNoHTMLEscape(toECS(a, o, now))
	}
}

type ecsDoc struct {
	Timestamp string      `json:"@timestamp"`
	Message   string      `json:"message,omitempty"`
	Tags      []string    `json:"tags,omitempty"`
	ECS       ecsMeta     `json:"ecs"`
	Event     ecsEvent    `json:"event"`
	Rule      ecsRule     `json:"rule"`
	Observer  ecsObserver `json:"observer"`
	Process   *ecsProcess `json:"process,omitempty"`
	User      *ecsUser    `json:"user,omitempty"`
	Host      *ecsHost    `json:"host,omitempty"`
	File      *ecsFile    `json:"file,omitempty"`
	Threat    *ecsThreat  `json:"threat,omitempty"`
}

type ecsMeta struct {
	Version string `json:"version"`
}

type ecsObserver struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Type    string `json:"type"`
	Version string `json:"version,omitempty"`
}

type ecsEvent struct {
	Kind     string   `json:"kind"`
	Category []string `json:"category"`
	Type     []string `json:"type"`
	Action   string   `json:"action,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Severity int      `json:"severity"`
	Dataset  string   `json:"dataset"`
	Module   string   `json:"module"`
	Provider string   `json:"provider,omitempty"`
}

type ecsRule struct {
	Name        string `json:"name,omitempty"`
	ID          string `json:"id,omitempty"`
	Description string `json:"description,omitempty"`
	Ruleset     string `json:"ruleset,omitempty"`
}

type ecsProcess struct {
	Executable       string     `json:"executable,omitempty"`
	CommandLine      string     `json:"command_line,omitempty"`
	PID              int        `json:"pid,omitempty"`
	WorkingDirectory string     `json:"working_directory,omitempty"`
	Start            string     `json:"start,omitempty"`
	Parent           *ecsParent `json:"parent,omitempty"`
}

type ecsParent struct {
	Executable string `json:"executable,omitempty"`
	PID        int    `json:"pid,omitempty"`
}

type ecsUser struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}

type ecsHost struct {
	Name string `json:"name,omitempty"`
}

type ecsFile struct {
	Path string `json:"path,omitempty"`
}

type ecsThreat struct {
	Framework string         `json:"framework,omitempty"`
	Technique []ecsTechnique `json:"technique,omitempty"`
	Tactic    []ecsTactic    `json:"tactic,omitempty"`
}

type ecsTechnique struct {
	ID string `json:"id"`
}

type ecsTactic struct {
	Name string `json:"name"`
}

func toECS(a Alert, o OCSFOptions, now func() time.Time) ecsDoc {
	ev := a.Event
	ts := a.Time
	if ts.IsZero() {
		ts = ev.Time
	}
	if ts.IsZero() {
		ts = now()
	}
	d := ecsDoc{
		Timestamp: ts.UTC().Format(time.RFC3339Nano),
		Message:   a.Message,
		ECS:       ecsMeta{Version: ecsVersion},
		Observer:  ecsObserver{Vendor: "banken", Product: "banken", Type: "hids", Version: o.ProductVersion},
		Event: ecsEvent{
			Kind:     "alert",
			Category: []string{"intrusion_detection"},
			Type:     []string{"info"},
			Action:   a.Rule,
			Reason:   a.Title,
			Severity: ecsSeverity(a.Level),
			Dataset:  "banken.alerts",
			Module:   "banken",
			Provider: a.Source,
		},
		Rule: ecsRule{Name: a.Rule, ID: a.RuleID, Description: a.Desc, Ruleset: a.Kind},
	}
	if a.Observed {
		d.Tags = append(d.Tags, "observed")
	}
	// The process object, when the event carries exec detail. Its presence adds "process" to the
	// categories (ECS allows several), so an Elastic query on event.category:process finds it.
	if ev.Image != "" || ev.CommandLine != "" || ev.PID != 0 {
		p := &ecsProcess{
			Executable:       ev.Image,
			CommandLine:      ev.CommandLine,
			PID:              ev.PID,
			WorkingDirectory: ev.CurrentDirectory,
		}
		if !ev.ProcessStart.IsZero() {
			p.Start = ev.ProcessStart.UTC().Format(time.RFC3339Nano)
		}
		if ev.ParentImage != "" || ev.PPID != 0 {
			p.Parent = &ecsParent{Executable: ev.ParentImage, PID: ev.PPID}
		}
		d.Process = p
		d.Event.Category = append(d.Event.Category, "process")
	}
	// User is a name if the source translated the uid, else the numeric uid as a string: map the
	// numeric form to user.id (an identifier) and a name to user.name, as ECS intends.
	if ev.User != "" {
		if isAllDigits(ev.User) {
			d.User = &ecsUser{ID: ev.User}
		} else {
			d.User = &ecsUser{Name: ev.User}
		}
	}
	if o.Hostname != "" {
		d.Host = &ecsHost{Name: o.Hostname}
	}
	if ev.TargetFilename != "" {
		d.File = &ecsFile{Path: ev.TargetFilename}
		d.Event.Category = append(d.Event.Category, "file")
	}
	if t := ecsThreatFromTags(a.Tags); t != nil {
		d.Threat = t
	}
	// Carry the rule's own tags through as ECS tags too, so they are searchable alongside the
	// mapped threat object.
	d.Tags = append(d.Tags, a.Tags...)
	return d
}

// ecsSeverity maps banken's level to an ECS event.severity (a long where higher is worse; ECS fixes
// no scale, so this is banken's own monotonic mapping, documented for the consumer).
func ecsSeverity(level string) int {
	switch level {
	case "critical":
		return 99
	case "high":
		return 73
	case "medium":
		return 47
	case "low":
		return 21
	default:
		return 0
	}
}

// ecsThreatFromTags turns banken's attack.* tags into an ECS threat object: an "attack.tNNNN[.MMM]"
// tag is a technique id, any other "attack.<x>" tag is read as a tactic name. Returns nil when there
// are no ATT&CK tags, so the threat object is omitted rather than empty.
func ecsThreatFromTags(tags []string) *ecsThreat {
	var techs []ecsTechnique
	var tactics []ecsTactic
	for _, t := range tags {
		rest, ok := strings.CutPrefix(t, "attack.")
		if !ok {
			continue
		}
		if len(rest) > 1 && (rest[0] == 't' || rest[0] == 'T') && rest[1] >= '0' && rest[1] <= '9' {
			techs = append(techs, ecsTechnique{ID: strings.ToUpper(rest)})
		} else if rest != "" {
			tactics = append(tactics, ecsTactic{Name: rest})
		}
	}
	if techs == nil && tactics == nil {
		return nil
	}
	return &ecsThreat{Framework: "MITRE ATT&CK", Technique: techs, Tactic: tactics}
}
