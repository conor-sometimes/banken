package parser

import (
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/conor-sometimes/banken/internal/event"
)

const laurelName = "laurel"

// Laurel parses Laurel's JSON audit output: one JSON object per line, each
// a complete, already-reassembled audit event with the hex decoding and
// uid->name translation Laurel does for us. That makes it the easy source
// relative to raw auditd -- but the bytes are still untrusted, so the
// parser decodes every field defensively and skips a line it cannot read
// rather than failing the batch.
//
// Laurel's shape (the fields banken reads). The id-to-name translations and the
// enriched parent live INSIDE the SYSCALL record -- SYSCALL.UID is the resolved
// login name (a string), SYSCALL.PPID the enriched parent -- not at the top
// level (captured from real Laurel output, 2026-11-01):
//
//	{"ID":"1626611363.720:348",
//	 "SYSCALL":{"exe":"/usr/bin/cat","uid":0,"ppid":1234,
//	            "UID":"root","PPID":{"comm":"bash","exe":"/usr/bin/bash"}, ...},
//	 "EXECVE":{"argc":2,"ARGV":["cat","/etc/shadow"],"ARGV_STR":"cat /etc/shadow"},
//	 "CWD":{"cwd":"/home/user"},
//	 "PATH":[{"name":"/etc/shadow","nametype":"NORMAL"}],
//	 "PROCTITLE":{"ARGV":["cat","/etc/shadow"]}}
//
// Every one of those keys is optional and every type is checked, so a line
// missing or mistyping any of them still yields whatever else it carried.
type Laurel struct{}

// Name implements Parser.
func (Laurel) Name() string { return laurelName }

// Parse implements Parser. Each non-empty line is one JSON event; a line
// that is not valid JSON, or is JSON of the wrong shape, is skipped. An
// over-long line is skipped by scanLines, never failing the batch.
func (p Laurel) Parse(r io.Reader) ([]event.Event, error) {
	var events []event.Event
	err := scanLines(r, func(line []byte) {
		var obj map[string]json.RawMessage
		if json.Unmarshal(line, &obj) != nil {
			return // not valid JSON -- skip, keep going
		}
		events = append(events, laurelEvent(obj))
	})
	return events, err
}

func laurelEvent(obj map[string]json.RawMessage) event.Event {
	ev := event.Event{Source: laurelName}

	if id := rawString(obj["ID"]); id != "" {
		ev.Time = auditTime(id)
	}

	syscall := rawObject(obj["SYSCALL"])
	ev.Image = rawString(syscall["exe"])
	ev.PID, _ = strconv.Atoi(rawString(syscall["pid"]))
	ev.PPID, _ = strconv.Atoi(rawString(syscall["ppid"]))
	ev.CurrentDirectory = rawString(rawObject(obj["CWD"])["cwd"])

	// User: Laurel resolves the numeric uid to a login name inside the SYSCALL
	// record (SYSCALL.UID, a plain string), so prefer that; fall back to the
	// numeric uid when the name is absent. The account-scoped rules match the
	// name, so reading this from the right place is what makes them fire.
	ev.User = rawString(syscall["uid"])
	if name := rawString(syscall["UID"]); name != "" {
		ev.User = name
	}

	// Parent image: Laurel enriches the parent inside the SYSCALL record
	// (SYSCALL.PPID.exe), not at the top level.
	ev.ParentImage = rawString(rawObject(syscall["PPID"])["exe"])

	// Command line: decoded EXECVE argv first, then proctitle.
	ev.CommandLine = laurelCommandLine(obj)
	argv0, _, _ := strings.Cut(ev.CommandLine, " ")
	if argv := rawStringSlice(rawObject(obj["EXECVE"])["ARGV"]); len(argv) > 0 {
		argv0 = argv[0] // exact, even if argv[0] itself contains a space
	}
	ev.Image = resolveMulticall(ev.Image, argv0)

	// Target filename: the acted-on PATH entry -- except for an exec, whose
	// PATH entries are the program being loaded and its interpreter, not a
	// file it acted on (see foldAuditGroup).
	if _, isExec := obj["EXECVE"]; !isExec {
		ev.TargetFilename = laurelTarget(obj)
	}

	laurelRawFields(&ev, obj, syscall)
	return ev
}

// laurelRawFields exposes the raw auditd field names to Sigma matching, the
// same contract as the raw-auditd parser's foldAuditGroup: SigmaHQ's
// service:auditd rules key on type, syscall, comm, exe, key, a0..aN, name,
// nametype, uid, euid, ... which Laurel carries inside its per-record objects.
// Single-valued fields go in Raw; the record `type` set and the per-PATH
// name/nametype go in Multi.
func laurelRawFields(ev *event.Event, obj map[string]json.RawMessage, syscall map[string]json.RawMessage) {
	raw := map[string]string{}
	// SYSCALL's scalar fields (uid, euid, exe, comm, syscall, key, ...) verbatim.
	// Nested objects (Laurel's enriched PPID) and arrays are not scalar audit
	// fields, so rawString returns "" for them and they are skipped.
	for k, v := range syscall {
		if s := rawString(v); s != "" {
			raw[k] = s
		}
	}
	// EXECVE argv as a0..aN (plus argc), so the aN-indexed rules fire even when
	// Laurel emitted argv as an array rather than numbered keys.
	execve := rawObject(obj["EXECVE"])
	argv := rawStringSlice(execve["ARGV"])
	if len(argv) == 0 {
		argv = rawStringSlice(execve["argv"])
	}
	for i, a := range argv {
		raw["a"+strconv.Itoa(i)] = a
	}
	if argc := rawString(execve["argc"]); argc != "" {
		raw["argc"] = argc
	}
	if cwd := rawString(rawObject(obj["CWD"])["cwd"]); cwd != "" {
		raw["cwd"] = cwd
	}

	multi := map[string][]string{}
	// Record types present are Laurel's top-level record keys: an uppercase
	// name (not the ID) whose value is a record object or array. The value
	// check keeps a stray scalar from being mistaken for a record type.
	var types []string
	for k, v := range obj {
		if k == "ID" || k != strings.ToUpper(k) {
			continue
		}
		if rawObject(v) == nil && rawObjectSlice(v) == nil {
			continue
		}
		types = append(types, k)
	}
	sort.Strings(types) // map order is random; keep a stable set
	if len(types) > 0 {
		multi["type"] = types
	}
	var names, nametypes []string
	for _, pi := range rawObjectSlice(obj["PATH"]) {
		if name := rawString(pi["name"]); name != "" {
			names = append(names, name)
			nametypes = append(nametypes, rawString(pi["nametype"]))
		}
	}
	if len(names) > 0 {
		multi["name"] = names
		multi["nametype"] = nametypes
	}

	if len(raw) > 0 {
		ev.Raw = raw
	}
	if len(multi) > 0 {
		ev.Multi = multi
	}
}

func laurelCommandLine(obj map[string]json.RawMessage) string {
	execve := rawObject(obj["EXECVE"])
	if argv := rawStringSlice(execve["ARGV"]); len(argv) > 0 {
		return strings.Join(argv, " ")
	}
	// Some Laurel configs keep argv under lowercase or numbered keys.
	if argv := rawStringSlice(execve["argv"]); len(argv) > 0 {
		return strings.Join(argv, " ")
	}
	if argc, err := strconv.Atoi(rawString(execve["argc"])); err == nil && argc > 0 {
		var argv []string
		for i := 0; i < argc; i++ {
			v, ok := execve["a"+strconv.Itoa(i)]
			if !ok {
				break
			}
			argv = append(argv, rawString(v))
		}
		if len(argv) > 0 {
			return strings.Join(argv, " ")
		}
	}
	proc := rawObject(obj["PROCTITLE"])
	if s := rawString(proc["ARGV_STR"]); s != "" {
		return s
	}
	return strings.TrimSpace(decodeHexField(rawString(proc["proctitle"])))
}

func laurelTarget(obj map[string]json.RawMessage) string {
	paths := rawObjectSlice(obj["PATH"])
	target := ""
	for _, pi := range paths {
		name := rawString(pi["name"])
		if name == "" {
			continue
		}
		if target == "" || isActedOn(rawString(pi["nametype"])) {
			target = name
		}
	}
	return target
}

// --- defensive JSON helpers: every one tolerates the wrong type and
// returns a usable zero value, so a mistyped field never panics. ---

// rawString reads a JSON value as a string. A JSON number is rendered as
// its literal text (auditd fields are strings in Laurel, but a config
// might emit a bare number); any other type yields "".
func rawString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return ""
}

func rawObject(raw json.RawMessage) map[string]json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

func rawObjectSlice(raw json.RawMessage) []map[string]json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var s []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// A single object where an array was expected: treat it as a
	// one-element slice rather than dropping it.
	if one := rawObject(raw); one != nil {
		return []map[string]json.RawMessage{one}
	}
	return nil
}

func rawStringSlice(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(raw, &raws); err != nil {
		return nil
	}
	out := make([]string, 0, len(raws))
	for _, r := range raws {
		out = append(out, rawString(r))
	}
	return out
}
