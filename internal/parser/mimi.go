package parser

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
)

const mimiName = "mimi"

// mimiSchema is the one wire schema version this parser understands. mimi stamps every event with
// its own version (mimi-types SCHEMA); banken skips a line whose schema it does not know rather
// than misreading newer bytes, so the sensor and the brain can evolve without silent drift. The
// shape is frozen by a shared fixture tested on both sides (testdata/mimi_event.golden.jsonl is a
// byte-for-byte copy of mimi's render_mimi output; `just contract` checks the two repos agree).
const mimiSchema = "mimi/2"

// Mimi parses the mimi eBPF sensor's JSON events: one object per line, mimi's own OCSF-shaped
// schema. The bytes are untrusted, so every field is read defensively and a line banken cannot
// read, or whose schema it does not know, is skipped rather than failing the batch.
//
// The process object is OCSF-shaped, identical to banken's own ocsfProcess (pid / name / cmd_line /
// file{path,name} / user{uid} / parent_process), so it maps with no translation; ancestry is mimi's
// extension (the full chain):
//
//	{"schema":"mimi/2","kind":"exec","time":"...","capture_ns":123,"activity_id":1,"cmdline_truncated":false,
//	 "process":{"pid":213541,"name":"ping","cmd_line":"ping 8.8.8.8",
//	            "file":{"path":"/usr/bin/ping","name":"ping"},"user":{"uid":"1000","gid":"1000"},
//	            "parent_process":{"pid":210139,"name":"fish"}},
//	 "ancestry":[{"pid":213541,"name":"ping"},{"pid":210139,"name":"fish"},{"pid":1,"name":"systemd"}]}
type Mimi struct{}

// Name implements Parser.
func (Mimi) Name() string { return mimiName }

// Parse implements Parser.
func (p Mimi) Parse(r io.Reader) ([]event.Event, error) {
	var events []event.Event
	err := scanLines(r, func(line []byte) {
		var obj map[string]json.RawMessage
		if json.Unmarshal(line, &obj) != nil {
			return // not valid JSON: skip, keep going
		}
		// Version skew: an unknown schema is skipped, never guessed at. An empty schema is
		// tolerated (an older sensor or a hand-written line) and parsed best-effort.
		if s := rawString(obj["schema"]); s != "" && s != mimiSchema {
			return
		}
		events = append(events, mimiEvent(obj))
	})
	return events, err
}

func mimiEvent(obj map[string]json.RawMessage) event.Event {
	// Provenance is stamped by the parser, never read from the line: a line cannot claim to be
	// "auditd" and inherit auditd's trust (the enforceSources rail the response design relies on).
	ev := event.Event{Source: mimiName}

	if t := rawString(obj["time"]); t != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, t); err == nil {
			ev.Time = parsed
		}
	}

	// The process object is OCSF-shaped: image is file.path, user is user.uid, the parent is nested
	// in process.parent_process (not top level).
	proc := rawObject(obj["process"])
	ev.CommandLine = rawString(proc["cmd_line"])
	ev.PID, _ = strconv.Atoi(rawString(proc["pid"]))
	ev.Image = rawString(rawObject(proc["file"])["path"])
	user := rawObject(proc["user"])
	// Numeric uid; banken's cross-source User normalisation resolves it to a login name where it
	// can, keeping the number otherwise (so the account-scoped agent rules fire on either form).
	ev.User = rawString(user["uid"])

	// argv[0] drives multicall resolution, the same as the auditd/Laurel path (a NixOS coreutils
	// multicall binary reports exe=coreutils; what argv[0] names is what ran).
	argv0, _, _ := strings.Cut(ev.CommandLine, " ")
	ev.Image = resolveMulticall(ev.Image, argv0)

	parent := rawObject(proc["parent_process"])
	ev.PPID, _ = strconv.Atoi(rawString(parent["pid"]))

	// mimi's parent is a comm (a 15-byte name), not a path, so it goes in Raw rather than
	// ParentImage (which rules match as an absolute path). The full ancestry chain -- mimi's
	// headline feature -- goes in Raw["Ancestry"], where Event.Field and AllText match it, so a
	// rule can key on "a shell whose ancestry contains nginx" with no schema change.
	ev.Raw = map[string]string{}
	if pn := rawString(parent["name"]); pn != "" {
		ev.Raw["ParentName"] = pn
	}
	if anc := mimiAncestry(obj["ancestry"]); anc != "" {
		ev.Raw["Ancestry"] = anc
	}
	var truncated bool
	if json.Unmarshal(obj["cmdline_truncated"], &truncated) == nil && truncated {
		ev.Raw["CmdlineTruncated"] = "true"
	}
	if g := rawString(user["gid"]); g != "" {
		ev.Raw["Gid"] = g
	}

	return ev
}

// mimiAncestry renders the chain as "name(pid) < name(pid) < ...", the same text render_text emits,
// so the chain is one matchable string.
func mimiAncestry(raw json.RawMessage) string {
	entries := rawObjectSlice(raw)
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		name := rawString(e["name"])
		if name == "" {
			continue
		}
		parts = append(parts, name+"("+rawString(e["pid"])+")")
	}
	return strings.Join(parts, " < ")
}
