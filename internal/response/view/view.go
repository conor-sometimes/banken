// Package view is the read-only operator surface over the response ledger and
// the freeze/quarantine/evidence stores: it backs `banken respond list` and
// `banken respond explain`. It reads, re-hashes and classifies; it never acts,
// never signals, never needs the privileged helper, and runs as any user.
//
// Everything here is PURE over an fs.FS root plus a Prober. The Reader decodes
// the ledger lines and the store manifests from files; ComputeState turns a
// store entry plus the facts a Prober gathered about the live system into the
// §3.1 state string. The one impure seam is the Prober: on Linux SysProber
// stats the real system (cgroup.events, the stored inode, the immutable bit,
// the boot id); in a test a MapProber reads those same facts from a committed
// live.json. So the whole surface - readers, state computation and chain
// reconstruction - is driven end to end by a fixture tree on a Mac, no root and
// no live host, which is how the golden tests run.
//
// The view defines its OWN copies of the on-disk manifest shapes rather than
// importing internal/response/exec: that package is Linux-only (it holds the
// pidfd and cgroup primitives) and this one must compile and test everywhere.
// The manifests are data files with a stable schema (store manifestVersion 1);
// the view reads the fields §3.1/§3.2 classify over and keeps the raw bytes for
// `-json` so nothing is lost. See docs/design/response-architecture.md
// sections 2.7, 3.1 and 3.2.
package view

import (
	"io/fs"
	"strings"

	"github.com/conor-sometimes/banken/internal/response"
)

// minIDPrefix is the shortest id prefix list/explain accept. The stores and
// the ledger use the 24-hex handle/decision ids; a unique prefix of at least
// this many characters resolves to one record, matching the 8-char ids the
// quarantine.md listing shows.
const minIDPrefix = 8

// Reader reads the ledger and the stores from an fs.FS root. All four
// directories are given as root-relative, slash-separated paths (fs.FS forbids
// a leading slash): the CLI roots at os.DirFS("/") and strips the leading
// slash from each absolute dir, so /var/lib/banken/freeze is read as
// "var/lib/banken/freeze"; a test roots at os.DirFS(fixtureDir) with dirs like
// "freeze". The Reader performs no writes and holds no live-system handle.
type Reader struct {
	root          fs.FS
	ledgerDir     string
	freezeDir     string
	quarantineDir string
	evidenceDir   string
	spoolDir      string
}

// NewReader builds a Reader over root. Each dir is a root-relative path; an
// empty dir disables reads of that store (list simply shows no entry of that
// kind). The spool dir lets explain tell "never requested" (the daemon crashed
// between the decision and the order) from "requested, not yet drained" (the
// order is still in the spool). The caller derives the paths the same way the
// daemon and the drain do, so all three agree without an option.
func NewReader(root fs.FS, ledgerDir, freezeDir, quarantineDir, evidenceDir, spoolDir string) *Reader {
	return &Reader{
		root:          root,
		ledgerDir:     rel(ledgerDir),
		freezeDir:     rel(freezeDir),
		quarantineDir: rel(quarantineDir),
		evidenceDir:   rel(evidenceDir),
		spoolDir:      rel(spoolDir),
	}
}

// rel makes an absolute or relative OS path safe for fs.FS: fs.FS paths are
// slash-separated, unrooted and free of a leading slash. An empty path stays
// empty (a disabled store).
func rel(p string) string {
	if p == "" {
		return ""
	}
	return strings.TrimPrefix(p, "/")
}

// storeDirFor returns the root-relative store directory for a kind, or "" for a
// kind with no store (kill, isolate, none).
func (r *Reader) storeDirFor(kind response.Action) string {
	switch kind {
	case response.ActionFreeze:
		return r.freezeDir
	case response.ActionQuarantine:
		return r.quarantineDir
	case response.ActionCollect:
		return r.evidenceDir
	default:
		return ""
	}
}

// idMatches reports whether a full id is addressed by query: an exact match, or
// a prefix of at least minIDPrefix characters. A query shorter than the minimum
// never matches (the caller turns that into a usage error).
func idMatches(full, query string) bool {
	if len(query) < minIDPrefix {
		return false
	}
	return strings.HasPrefix(full, query)
}
