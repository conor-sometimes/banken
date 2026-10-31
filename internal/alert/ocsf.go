package alert

// OCSF (Open Cybersecurity Schema Framework) output. banken emits each alert
// as an OCSF Detection Finding (class 2004) so any OCSF-aware SIEM --
// Security Lake, Splunk, Datadog, Google SecOps -- ingests it without a
// per-product mapping on the operator's side. The mapping is a pure function
// of (Alert, OCSFOptions); see docs/design/ocsf-output.md for the field-by-
// field rationale and the version pin.
//
// Design notes that bind this file:
//   - Version is pinned (OCSFVersion); bumping it is a deliberate change.
//   - Nothing here is reflective or generated: ~15 small hand-written structs
//     against the 1.3.0 schema, snake_case tags (OCSF's spelling, hence the
//     tagliatelle exclusion in .golangci.yml).
//   - omit means "not emitted": a value banken does not have is never written
//     as "", null or a meaningless 0. Captions sit beside their id; an id
//     whose 0 is meaningful (timezone_offset, status_id, type_id, severity_id)
//     is not omitempty, everything optional is a pointer or omitempty.
//   - Never-die: the one caller is a sink's Emit; an encode error degrades one
//     output and the scan goes on. There is no path here that panics on a
//     weird Alert (see FuzzOCSF).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/ioc"
)

// OCSFVersion is the OCSF schema version every finding declares. Bumping it
// is a deliberate change: see docs/design/ocsf-output.md §3.2 (the pin is the
// highest version every target consumer accepts while still containing
// everything banken emits).
const OCSFVersion = "1.3.0"

// Product identity, as it appears in every SIEM's vendor/product columns.
const (
	ocsfProductName   = "banken"
	ocsfProductVendor = "conor-sometimes" // the author/org; product is "banken" (vendor = who makes it)
	ocsfProductURL    = "https://github.com/conor-sometimes/banken"
)

// OCSFOptions is the per-deployment context a finding needs that an Alert
// does not carry. main fills it once at startup; tests inject fixed values.
type OCSFOptions struct {
	// ProductVersion is main.version (the git-describe stamp, or "dev").
	ProductVersion string
	// Hostname is os.Hostname() at startup; "" omits the device object
	// entirely (OCSF's device has an at-least-one-identifier constraint).
	Hostname string
	// Now supplies a time for an Alert whose Time is zero (the same fallback
	// the jsonl sink uses for its file name). Nil means time.Now.
	Now func() time.Time
}

// Encoder renders one alert as one JSON document (no trailing newline). The
// jsonl and webhook sinks are parameterised by it, so OCSF is a choice of
// encoding inside the sinks that already carry JSON, never a fourth sink.
type Encoder func(a Alert) ([]byte, error)

// EncodeAlert is banken's native shape: json.Marshal(a). It is the default
// encoder for every sink.
func EncodeAlert(a Alert) ([]byte, error) { return json.Marshal(a) }

// EncodeOCSF returns an Encoder that renders a Detection Finding against the
// pinned schema version.
func EncodeOCSF(o OCSFOptions) Encoder {
	return func(a Alert) ([]byte, error) { return marshalNoHTMLEscape(ToOCSF(a, o)) }
}

// marshalNoHTMLEscape is json.Marshal without HTML escaping. Command lines are
// the substance of a finding; `bash -i >& /dev/tcp/...` must stay greppable
// as written in the file a SIEM shipper tails, not become >&.
func marshalNoHTMLEscape(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil // Encode appends one
}

// --- the finding struct tree (one Go type per OCSF object banken emits) ---

// OCSFFinding is an OCSF 1.3.0 Detection Finding (class_uid 2004).
type OCSFFinding struct {
	ActivityID     int              `json:"activity_id"`
	ActivityName   string           `json:"activity_name,omitempty"`
	CategoryUID    int              `json:"category_uid"`
	CategoryName   string           `json:"category_name,omitempty"`
	ClassUID       int              `json:"class_uid"`
	ClassName      string           `json:"class_name,omitempty"`
	TypeUID        int              `json:"type_uid"`
	TypeName       string           `json:"type_name,omitempty"`
	Time           int64            `json:"time"`
	TimezoneOffset int              `json:"timezone_offset"`
	SeverityID     int              `json:"severity_id"`
	Severity       string           `json:"severity,omitempty"`
	StatusID       int              `json:"status_id"`
	Status         string           `json:"status,omitempty"`
	Message        string           `json:"message,omitempty"`
	Metadata       ocsfMetadata     `json:"metadata"`
	FindingInfo    ocsfFindingInfo  `json:"finding_info"`
	Evidences      []ocsfEvidence   `json:"evidences,omitempty"`
	Device         *ocsfDevice      `json:"device,omitempty"`
	Observables    []ocsfObservable `json:"observables,omitempty"`
	Osint          []ocsfOsint      `json:"osint,omitempty"`
	RawData        string           `json:"raw_data,omitempty"`
	Unmapped       map[string]any   `json:"unmapped,omitempty"`
}

type ocsfMetadata struct {
	Version      string      `json:"version"`
	Profiles     []string    `json:"profiles,omitempty"`
	Product      ocsfProduct `json:"product"`
	UID          string      `json:"uid,omitempty"`
	LogProvider  string      `json:"log_provider,omitempty"`
	OriginalTime string      `json:"original_time,omitempty"`
}

type ocsfProduct struct {
	Name       string `json:"name,omitempty"`
	VendorName string `json:"vendor_name,omitempty"`
	Version    string `json:"version,omitempty"`
	URLString  string `json:"url_string,omitempty"`
}

type ocsfFindingInfo struct {
	UID         string       `json:"uid"`
	Title       string       `json:"title"`
	Desc        string       `json:"desc,omitempty"`
	Analytic    ocsfAnalytic `json:"analytic"`
	Attacks     []ocsfAttack `json:"attacks,omitempty"`
	DataSources []string     `json:"data_sources,omitempty"`
}

type ocsfAnalytic struct {
	TypeID int    `json:"type_id"`
	Type   string `json:"type,omitempty"`
	Name   string `json:"name,omitempty"`
	UID    string `json:"uid,omitempty"`
}

type ocsfAttack struct {
	Tactic       *ocsfIDName `json:"tactic,omitempty"`
	Technique    *ocsfIDName `json:"technique,omitempty"`
	SubTechnique *ocsfIDName `json:"sub_technique,omitempty"`
}

// ocsfIDName is OCSF's recurring {uid, name} shape (tactic, technique,
// sub_technique). banken emits uid alone for techniques -- the names need the
// versioned ATT&CK dataset -- and uid+name for the 14 known tactics.
type ocsfIDName struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
}

type ocsfEvidence struct {
	Process *ocsfProcess `json:"process,omitempty"`
	File    *ocsfFile    `json:"file,omitempty"`
}

type ocsfProcess struct {
	PID           int          `json:"pid,omitempty"`
	Name          string       `json:"name,omitempty"`
	CmdLine       string       `json:"cmd_line,omitempty"`
	File          *ocsfFile    `json:"file,omitempty"`
	User          *ocsfUser    `json:"user,omitempty"`
	ParentProcess *ocsfProcess `json:"parent_process,omitempty"`
}

type ocsfFile struct {
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	TypeID int    `json:"type_id"`
	Type   string `json:"type,omitempty"`
}

type ocsfUser struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

type ocsfDevice struct {
	TypeID   int    `json:"type_id"`
	Type     string `json:"type,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// ocsfObservable is one pivotable value. Name is required (1.3.0) and is the
// path to the attribute in this same finding that holds Value -- validators
// resolve it and compare values, so it must point at a real attribute.
type ocsfObservable struct {
	Name   string `json:"name"`
	TypeID int    `json:"type_id"`
	Type   string `json:"type,omitempty"`
	Value  string `json:"value,omitempty"`
}

// ocsfOsint is one indicator from threat intelligence (the osint profile):
// for an IOC alert, the indicator the feed matched. Name is the feed it came
// from (osint extends _entity, which needs a name or uid).
type ocsfOsint struct {
	Name   string `json:"name"`
	TypeID int    `json:"type_id"`
	Type   string `json:"type,omitempty"`
	Value  string `json:"value"`
}

// ToOCSF maps one alert to a Detection Finding. Pure: the same (Alert,
// OCSFOptions) always yields the same struct (and thus the same bytes),
// which is what makes the golden tests deterministic.
func ToOCSF(a Alert, o OCSFOptions) OCSFFinding {
	ev := a.Event
	sevID, sev := ocsfSeverity(a.Level)
	uid := ocsfUID(a)

	t := a.Time
	var originalTime string
	if t.IsZero() {
		now := o.Now
		if now == nil {
			now = time.Now
		}
		t = now()
	} else {
		originalTime = a.Time.UTC().Format(time.RFC3339)
	}

	f := OCSFFinding{
		ActivityID:     1,
		ActivityName:   "Create",
		CategoryUID:    2,
		CategoryName:   "Findings",
		ClassUID:       2004,
		ClassName:      "Detection Finding",
		TypeUID:        200401,
		TypeName:       "Detection Finding: Create",
		Time:           t.UTC().UnixMilli(),
		TimezoneOffset: 0,
		SeverityID:     sevID,
		Severity:       sev,
		StatusID:       1,
		Status:         "New",
		Message:        a.Message,
		Metadata: ocsfMetadata{
			Version:      OCSFVersion,
			Profiles:     []string{"host"},
			Product:      ocsfProduct{Name: ocsfProductName, VendorName: ocsfProductVendor, Version: o.ProductVersion, URLString: ocsfProductURL},
			UID:          uid,
			LogProvider:  ev.Source,
			OriginalTime: originalTime,
		},
		FindingInfo: ocsfFindingInfo{
			UID:      uid,
			Title:    a.Title,
			Desc:     a.Desc,
			Analytic: ocsfAnalyticFor(a),
			Attacks:  ocsfAttacks(a.Tags),
		},
		Evidences:   ocsfEvidences(ev),
		Device:      ocsfDeviceFor(o.Hostname),
		Observables: ocsfObservables(a, o.Hostname),
		Osint:       ocsfOsintFor(a),
		Unmapped:    ocsfUnmapped(a),
	}
	if f.Osint != nil {
		f.Metadata.Profiles = append(f.Metadata.Profiles, "osint")
	}
	if ev.Source != "" {
		f.FindingInfo.DataSources = []string{ev.Source}
	}
	if raw, err := marshalNoHTMLEscape(ev); err == nil {
		f.RawData = string(raw)
	}
	return f
}

// ocsfSeverity maps Sigma's level to OCSF severity_id + caption. Total:
// an unmappable level goes to 99 Other with the raw string as the caption,
// so a rule that wrote level: severe is still legible, never dropped.
func ocsfSeverity(level string) (id int, caption string) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 5, "Critical"
	case "high":
		return 4, "High"
	case "medium":
		return 3, "Medium"
	case "low":
		return 2, "Low"
	case "informational":
		return 1, "Informational"
	case "":
		return 0, "Unknown"
	default:
		return 99, level
	}
}

// ocsfAnalyticFor describes the detector: a Sigma rule, or an exact-match
// indicator feed.
func ocsfAnalyticFor(a Alert) ocsfAnalytic {
	if a.Kind == KindIOC {
		// Exact Data Match (type_id 9): a flat indicator list matched by set
		// membership is exactly that. A feed has no stable id, so no uid.
		return ocsfAnalytic{TypeID: 9, Type: "Exact Data Match", Name: a.Rule}
	}
	return ocsfAnalytic{TypeID: 1, Type: "Rule", Name: a.Rule, UID: a.RuleID}
}

// ocsfTactics maps Sigma's attack.<tactic> tag to the ATT&CK tactic id+name.
// A typo'd tactic is absent from the map and contributes nothing.
var ocsfTactics = map[string]ocsfIDName{
	"reconnaissance":       {UID: "TA0043", Name: "Reconnaissance"},
	"resource-development": {UID: "TA0042", Name: "Resource Development"},
	"initial-access":       {UID: "TA0001", Name: "Initial Access"},
	"execution":            {UID: "TA0002", Name: "Execution"},
	"persistence":          {UID: "TA0003", Name: "Persistence"},
	"privilege-escalation": {UID: "TA0004", Name: "Privilege Escalation"},
	"defense-evasion":      {UID: "TA0005", Name: "Defense Evasion"},
	"credential-access":    {UID: "TA0006", Name: "Credential Access"},
	"discovery":            {UID: "TA0007", Name: "Discovery"},
	"lateral-movement":     {UID: "TA0008", Name: "Lateral Movement"},
	"collection":           {UID: "TA0009", Name: "Collection"},
	"command-and-control":  {UID: "TA0011", Name: "Command and Control"},
	"exfiltration":         {UID: "TA0010", Name: "Exfiltration"},
	"impact":               {UID: "TA0040", Name: "Impact"},
}

// ocsfAttacks turns a rule's Sigma tags into OCSF attack objects. Sigma's
// convention: attack.<tactic>, attack.tNNNN (technique), attack.tNNNN.NNN
// (sub-technique); other namespaces (groups, software, cve.*, car.*, tlp.*)
// are ignored. One attack object per technique, each carrying the rule's
// tactic; a rule with a tactic but no technique emits one tactic-only object;
// a rule with no attack.* tags emits nothing (nothing is guessed). Technique
// names are not emitted (they need the versioned ATT&CK dataset); the uid
// alone satisfies the object and is what SIEMs key on.
func ocsfAttacks(tags []string) []ocsfAttack {
	var tactic *ocsfIDName
	type tech struct{ technique, sub string }
	var techs []tech
	for _, raw := range tags {
		tag := strings.ToLower(strings.TrimSpace(raw))
		name, ok := strings.CutPrefix(tag, "attack.")
		if !ok {
			continue
		}
		if strings.HasPrefix(name, "t") && len(name) > 1 && name[1] >= '0' && name[1] <= '9' {
			// technique or sub-technique: tNNNN or tNNNN.NNN
			up := strings.ToUpper(name)
			if base, _, isSub := strings.Cut(up, "."); isSub {
				techs = append(techs, tech{technique: base, sub: up})
			} else {
				techs = append(techs, tech{technique: up})
			}
			continue
		}
		if tactic == nil {
			if t, known := ocsfTactics[name]; known {
				tt := t // copy; take address of the local
				tactic = &tt
			}
		}
	}

	if len(techs) == 0 {
		if tactic != nil {
			return []ocsfAttack{{Tactic: tactic}}
		}
		return nil
	}
	out := make([]ocsfAttack, 0, len(techs))
	for _, t := range techs {
		att := ocsfAttack{Tactic: tactic, Technique: &ocsfIDName{UID: t.technique}}
		if t.sub != "" {
			att.SubTechnique = &ocsfIDName{UID: t.sub}
		}
		out = append(out, att)
	}
	return out
}

// ocsfEvidences builds the single evidence element: the triggering process,
// and the acted-on file if the event carried one. The process object is
// emitted whenever it has anything (pid, image, command line or user); it is
// kept even without a pid rather than dropping the command line, which is the
// most valuable thing in the finding (a validator warning beats no evidence).
func ocsfEvidences(ev event.Event) []ocsfEvidence {
	var e ocsfEvidence
	p := ocsfProcess{
		PID:     ev.PID,
		CmdLine: ev.CommandLine,
	}
	if ev.Image != "" {
		p.Name = baseName(ev.Image)
		p.File = &ocsfFile{Name: baseName(ev.Image), Path: ev.Image, TypeID: 1, Type: "Regular File"}
	}
	p.User = ocsfUserFor(ev.User)
	if ev.ParentImage != "" || ev.PPID > 0 {
		pp := &ocsfProcess{PID: ev.PPID}
		if ev.ParentImage != "" {
			pp.Name = baseName(ev.ParentImage)
			pp.File = &ocsfFile{Name: baseName(ev.ParentImage), Path: ev.ParentImage, TypeID: 1, Type: "Regular File"}
		}
		p.ParentProcess = pp
	}
	if p.PID > 0 || p.Name != "" || p.CmdLine != "" || p.User != nil || p.ParentProcess != nil {
		e.Process = &p
	}
	if ev.TargetFilename != "" {
		// 0 Unknown: banken does not know whether the acted-on path is a
		// regular file, a dir or a device.
		e.File = &ocsfFile{Name: baseName(ev.TargetFilename), Path: ev.TargetFilename, TypeID: 0, Type: "Unknown"}
	}
	if e.Process == nil && e.File == nil {
		return nil
	}
	return []ocsfEvidence{e}
}

// ocsfUserFor splits banken's User (a name if the source translated the uid,
// else the numeric uid) into the right OCSF user field. Empty -> no object.
func ocsfUserFor(user string) *ocsfUser {
	if user == "" {
		return nil
	}
	if isAllDigits(user) {
		return &ocsfUser{UID: user}
	}
	return &ocsfUser{Name: user}
}

func ocsfDeviceFor(hostname string) *ocsfDevice {
	if hostname == "" {
		return nil
	}
	// 0 Unknown: banken cannot tell a server from a VM from a laptop; the
	// operator's SIEM inventory can.
	return &ocsfDevice{TypeID: 0, Type: "Unknown", Hostname: hostname}
}

// ocsfObservables are flat, typed, pivotable copies of the values a SOC
// searches on, in a fixed order so goldens are byte-stable. Each names the
// attribute that holds it (bare array notation: evidences.process.cmd_line).
func ocsfObservables(a Alert, hostname string) []ocsfObservable {
	ev := a.Event
	var out []ocsfObservable
	add := func(name string, typeID int, typ, val string) {
		if val != "" {
			out = append(out, ocsfObservable{Name: name, TypeID: typeID, Type: typ, Value: val})
		}
	}
	add("evidences.process.cmd_line", 13, "Command Line", ev.CommandLine)
	if ev.Image != "" {
		add("evidences.process.name", 9, "Process Name", baseName(ev.Image))
		add("evidences.process.file.path", 7, "File Name", ev.Image) // 45 File Path is not in 1.3.0
	}
	if ev.User != "" && !isAllDigits(ev.User) {
		add("evidences.process.user.name", 4, "User Name", ev.User)
	}
	add("evidences.file.path", 7, "File Name", ev.TargetFilename)
	add("device.hostname", 1, "Hostname", hostname)
	if o := ocsfOsintFor(a); o != nil {
		typeID, typ := 7, "File Name"
		switch o[0].TypeID {
		case 1:
			typeID, typ = 2, "IP Address"
		case 2:
			typeID, typ = 1, "Hostname"
		}
		add("osint.value", typeID, typ, a.IOC)
	}
	return out
}

// ocsfOsintFor is the matched indicator of an IOC alert, typed by its shape
// with the loader's own classifier. OSINT has no File Name type, so a path
// indicator is 99 Other with the caption saying what it is.
func ocsfOsintFor(a Alert) []ocsfOsint {
	if a.Kind != KindIOC || a.IOC == "" {
		return nil
	}
	name := a.Rule // the feed, e.g. evil-c2.txt
	if name == "" {
		name = a.IOC
	}
	o := ocsfOsint{Name: name, TypeID: 99, Type: "File Name", Value: a.IOC}
	switch ioc.Classify(a.IOC) {
	case ioc.KindIP:
		o.TypeID, o.Type = 1, "IP Address"
	case ioc.KindDomain:
		o.TypeID, o.Type = 2, "Domain"
	}
	return []ocsfOsint{o}
}

// ocsfUnmapped carries everything banken knows that has no clean 1.3.0 home,
// under stable snake_case keys. encoding/json sorts the map keys, so the
// output is byte-stable. Omitted when empty (never, for a real alert: kind
// is always set).
func ocsfUnmapped(a Alert) map[string]any {
	m := map[string]any{}
	put := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	put("kind", a.Kind)
	put("rule", a.Rule)
	put("source", a.Event.Source)
	put("current_directory", a.Event.CurrentDirectory)
	put("ioc_field", a.Field)
	// Raw entries, each prefixed so a SIEM field extractor can find them; the
	// keys are sorted here too so the (already map-sorted) output is stable
	// regardless of how the extractor walks them.
	if len(a.Event.Raw) > 0 {
		keys := make([]string, 0, len(a.Event.Raw))
		for k := range a.Event.Raw {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			put("raw."+k, a.Event.Raw[k])
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// ocsfUID is finding_info.uid: a deterministic digest of the finding's
// identity, so a re-read of a source (banken's cursor is self-healing and may
// re-emit) produces the SAME uid and a SIEM de-duplicates it, where a random
// UUID would show two findings. The leading constant versions the scheme so
// it can change without colliding with ids already stored. 32 hex chars.
func ocsfUID(a Alert) string {
	var pid string
	if a.Event.PID > 0 {
		pid = strconv.Itoa(a.Event.PID)
	}
	var t string
	if !a.Time.IsZero() {
		t = a.Time.UTC().Format(time.RFC3339Nano)
	}
	h := sha256.Sum256([]byte("banken-ocsf-uid-v1\n" +
		a.Kind + "\n" + a.Rule + "\n" + a.RuleID + "\n" +
		t + "\n" + a.Event.Source + "\n" + pid + "\n" +
		a.Event.Image + "\n" + a.Event.CommandLine + "\n" +
		a.Event.User + "\n" + a.IOC + "\n" + a.Field + "\n"))
	return hex.EncodeToString(h[:])[:32]
}

// baseName is the final element of a file path, understanding both the Unix
// separator and the Windows backslash, so an OCSF finding from a Sysmon event
// gets "powershell.exe" and not the whole C:\... path. For a pure forward-slash
// path it equals path.Base, so Linux output is unchanged.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
