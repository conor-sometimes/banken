package parser

import (
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
)

const auditdName = "auditd"

// Auditd parses the raw Linux audit log: the multi-line
// SYSCALL/EXECVE/PATH/CWD/PROCTITLE records that auditd writes, where the
// records making up one logical event share an audit id and have to be
// stitched back together. This is the gnarly source -- hex-encoded argv
// and proctitle, quoted and bare values on the same line, interleaved
// events, truncated tails -- so it is also the one most carefully written
// to never panic on any of it.
type Auditd struct{}

// Name implements Parser.
func (Auditd) Name() string { return auditdName }

// record is one parsed `type=... msg=audit(ID): k=v k=v ...` line.
type record struct {
	rtype  string
	id     string
	fields map[string]string
	// argv holds a0,a1,... in order for an EXECVE record, already decoded.
	argv []string
	// paths holds each PATH record's (name, nametype) in item order.
	paths []pathItem
}

type pathItem struct {
	name     string
	nametype string
}

// Parse implements Parser. It groups records by audit id (keeping
// first-seen order), then folds each group into one event. An I/O error
// reading r is returned; malformed lines are skipped.
func (p Auditd) Parse(r io.Reader) ([]event.Event, error) {
	order := []string{}
	groups := map[string][]record{}

	// scanLines gives us each line defensively: an over-long line is skipped,
	// not failed, and only a real read error is returned.
	err := scanLines(r, func(line []byte) {
		rec, ok := parseAuditLine(string(line))
		if !ok {
			return // unparseable line -- skip, keep going
		}
		if _, seen := groups[rec.id]; !seen {
			order = append(order, rec.id)
		}
		groups[rec.id] = append(groups[rec.id], rec)
	})
	if err != nil {
		return nil, err
	}

	events := make([]event.Event, 0, len(order))
	for _, id := range order {
		ev, ok := foldAuditGroup(id, groups[id])
		if ok {
			events = append(events, ev)
		}
	}
	return events, nil
}

// parseAuditLine parses one audit line into a record. It returns false for
// a line with no recognisable `type=` and `msg=audit(...)` header, which
// is how a truncated or garbage line is skipped.
func parseAuditLine(line string) (record, bool) {
	rec := record{fields: map[string]string{}}

	rest := line
	// type= may be prefixed by a timestamp/hostname from some log
	// shippers; find the token rather than assuming column 0.
	if i := strings.Index(rest, "type="); i >= 0 {
		rest = rest[i:]
	} else {
		return record{}, false
	}
	rec.rtype = cutToken(&rest, "type=")
	if rec.rtype == "" {
		return record{}, false
	}

	// msg=audit(TS:SEQ): -- the id is the (TS:SEQ) inside the parens.
	mi := strings.Index(rest, "msg=audit(")
	if mi < 0 {
		return record{}, false
	}
	rest = rest[mi+len("msg=audit("):]
	id, after, ok := strings.Cut(rest, ")")
	if !ok {
		return record{}, false
	}
	rec.id = id
	rest = after
	rest = strings.TrimPrefix(rest, ":")
	rest = strings.TrimSpace(rest)

	// Remaining key=value pairs.
	pairs := splitAuditFields(rest)
	for _, kv := range pairs {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		key := kv[:eq]
		val := kv[eq+1:]
		val = normaliseAuditValue(key, val)
		rec.fields[key] = val
	}

	switch rec.rtype {
	case "EXECVE":
		rec.argv = collectArgv(rec.fields)
	case "PATH":
		rec.paths = append(rec.paths, pathItem{
			name:     rec.fields["name"],
			nametype: rec.fields["nametype"],
		})
	}
	return rec, true
}

// cutToken reads the value of a `prefix` token at the start of *s, up to
// the next space, and advances *s past it.
func cutToken(s *string, prefix string) string {
	v := strings.TrimPrefix(*s, prefix)
	if sp := strings.IndexByte(v, ' '); sp >= 0 {
		*s = v[sp+1:]
		return v[:sp]
	}
	*s = ""
	return v
}

// splitAuditFields splits a run of `k=v k="quoted v" k=hex` pairs on
// spaces, keeping a double-quoted value (which may contain spaces) whole.
func splitAuditFields(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case c == ' ' && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// normaliseAuditValue strips quotes, maps (null) to empty, and hex-decodes
// the stringy fields auditd encodes when they hold a space or special
// char. Numeric/flag fields (arch, syscall, pid, ...) are left verbatim
// even though some look like hex.
func normaliseAuditValue(key, val string) string {
	if val == "(null)" || val == "?" {
		return ""
	}
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		return val[1 : len(val)-1]
	}
	switch key {
	case "proctitle", "name", "cwd", "exe", "comm", "cmd":
		return decodeHexField(val)
	}
	if strings.HasPrefix(key, "a") && len(key) > 1 && isDigits(key[1:]) {
		// EXECVE argv element aN.
		return decodeHexField(val)
	}
	return val
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// collectArgv pulls a0,a1,... out of an EXECVE record's fields in order,
// up to argc (or until a gap), each already quote-stripped/hex-decoded by
// normaliseAuditValue.
func collectArgv(fields map[string]string) []string {
	n := len(fields)
	if argc, err := strconv.Atoi(fields["argc"]); err == nil && argc >= 0 {
		n = argc
	}
	var argv []string
	for i := 0; i < n; i++ {
		v, ok := fields["a"+strconv.Itoa(i)]
		if !ok {
			break
		}
		argv = append(argv, v)
	}
	return argv
}

// foldAuditGroup turns all records sharing one audit id into one event.
// It returns false only if the group carries nothing useful at all (no
// SYSCALL, EXECVE or PROCTITLE), which keeps noise like a lone EOE record
// out of the stream.
func foldAuditGroup(id string, recs []record) (event.Event, bool) {
	ev := event.Event{Source: auditdName, Time: auditTime(id)}
	var execveArgv []string
	var proctitle, pathTarget string
	useful, isExec := false, false

	// Expose the raw auditd fields to Sigma matching. SigmaHQ's service:auditd
	// rules key on the raw record field names (type, syscall, comm, exe, key,
	// a0..aN, name, nametype, uid, euid, unit, ...), which the fold above
	// collapses into the normalised fields. Carry them through verbatim so
	// those rules can fire: single-valued fields in Raw, and the fields a fold
	// makes multi-valued (the record `type` set, and `name`/`nametype` per
	// touched PATH) in Multi.
	raw := map[string]string{}
	var recTypes, pathNames, pathTypes []string
	seenType := map[string]bool{}

	for _, rec := range recs {
		// EOE is auditd's end-of-event marker, not a matchable record type.
		if rec.rtype != "" && rec.rtype != "EOE" && !seenType[rec.rtype] {
			seenType[rec.rtype] = true
			recTypes = append(recTypes, rec.rtype)
		}
		for k, v := range rec.fields {
			// name/nametype are per-PATH and multi-valued (handled below);
			// everything else is single per group, last record wins.
			if v == "" || k == "name" || k == "nametype" {
				continue
			}
			raw[k] = v
		}
		switch rec.rtype {
		case "SYSCALL":
			useful = true
			if exe := rec.fields["exe"]; exe != "" {
				ev.Image = exe
			}
			ev.CurrentDirectory = firstNonEmpty(ev.CurrentDirectory, rec.fields["cwd"])
			ev.User = firstNonEmpty(rec.fields["auid"], rec.fields["uid"], ev.User)
			if n, err := strconv.Atoi(rec.fields["pid"]); err == nil {
				ev.PID = n
			}
			if n, err := strconv.Atoi(rec.fields["ppid"]); err == nil {
				ev.PPID = n
			}
		case "EXECVE":
			useful, isExec = true, true
			execveArgv = rec.argv
		case "PROCTITLE":
			useful = true
			proctitle = rec.fields["proctitle"]
		case "CWD":
			ev.CurrentDirectory = firstNonEmpty(ev.CurrentDirectory, rec.fields["cwd"])
		case "PATH":
			for _, pi := range rec.paths {
				if pi.name == "" {
					continue
				}
				pathNames = append(pathNames, pi.name)
				pathTypes = append(pathTypes, pi.nametype)
				// Prefer a target that is acted on over a PARENT entry.
				if pathTarget == "" || isActedOn(pi.nametype) {
					pathTarget = pi.name
				}
			}
		}
	}

	// A group with no SYSCALL/EXECVE/PROCTITLE is still a real detection target
	// when it is one of auditd's standalone event records (a service state
	// change, an account action, an anomaly) that Sigma rules match directly --
	// otherwise it would be a dropped event, i.e. a dropped detection.
	if !useful {
		useful = hasStandaloneRecord(recTypes)
	}

	if len(raw) > 0 {
		ev.Raw = raw
	}
	multi := map[string][]string{}
	if len(recTypes) > 0 {
		multi["type"] = recTypes
	}
	if len(pathNames) > 0 {
		multi["name"] = pathNames
		multi["nametype"] = pathTypes
	}
	if len(multi) > 0 {
		ev.Multi = multi
	}

	// An exec's PATH records name the program being loaded and its
	// interpreter, never a file it acted on (the reads and writes it goes on
	// to make are their own events). So an exec has no TargetFilename -- else
	// every program would "touch" its own binary.
	if !isExec {
		ev.TargetFilename = pathTarget
	}
	var argv0 string
	switch {
	case len(execveArgv) > 0:
		ev.CommandLine = strings.Join(execveArgv, " ")
		argv0 = execveArgv[0]
	case proctitle != "":
		ev.CommandLine = strings.TrimSpace(proctitle)
		argv0, _, _ = strings.Cut(ev.CommandLine, " ")
	}
	ev.Image = resolveMulticall(ev.Image, argv0)
	return ev, useful
}

// hasStandaloneRecord reports whether the group carries an auditd record type
// that is a complete event on its own -- it has no SYSCALL to anchor it, but
// Sigma rules match on it (service state changes, account/credential actions,
// anomalies). The set is the record types SigmaHQ's linux/auditd rules target.
func hasStandaloneRecord(types []string) bool {
	for _, t := range types {
		switch t {
		case "SERVICE_START", "SERVICE_STOP",
			"ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP", "GRP_MGMT",
			"USER_CMD", "USER_ACCT", "USER_AUTH", "USER_MGMT", "USER_CHAUTHTOK",
			"CRED_ACQ", "CRED_REFR", "CRED_DISP",
			"ANOM_ABEND", "ANOM_PROMISCUOUS", "ANOM_LINK":
			return true
		}
	}
	return false
}

func isActedOn(nametype string) bool {
	switch nametype {
	case "CREATE", "DELETE", "NORMAL", "WRITE":
		return true
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// auditTime parses the TS from an audit id of the form "1626611363.720:348"
// (epoch seconds.millis : sequence). A malformed id yields the zero time,
// never a panic.
func auditTime(id string) time.Time {
	colon := strings.IndexByte(id, ':')
	tsPart := id
	if colon >= 0 {
		tsPart = id[:colon]
	}
	dot := strings.IndexByte(tsPart, '.')
	secStr := tsPart
	msStr := ""
	if dot >= 0 {
		secStr = tsPart[:dot]
		msStr = tsPart[dot+1:]
	}
	sec, err := strconv.ParseInt(secStr, 10, 64)
	if err != nil {
		return time.Time{}
	}
	var ns int64
	if msStr != "" {
		if ms, err := strconv.ParseInt(msStr, 10, 64); err == nil {
			ns = ms * int64(time.Millisecond)
		}
	}
	return time.Unix(sec, ns).UTC()
}
