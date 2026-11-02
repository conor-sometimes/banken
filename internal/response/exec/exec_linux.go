//go:build linux

package exec

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/conor-sometimes/banken/internal/response"
)

// Linux syscall numbers. pidfd_open/pidfd_send_signal are on the generic
// syscall table and share their number across arches; renameat2 does not and
// lives in sysnum_*.go.
const (
	sysPidfdOpen       = 434
	sysPidfdSendSignal = 424
)

const (
	atFDCWD         = -0x64      // AT_FDCWD
	renameNoReplace = 1 << 0     // RENAME_NOREPLACE
	fsImmutableFL   = 0x00000010 // FS_IMMUTABLE_FL
	fsIocGetFlags   = 0x80086601 // FS_IOC_GETFLAGS (64-bit long)
	fsIocSetFlags   = 0x40086602 // FS_IOC_SETFLAGS (64-bit long)
	userHZ          = 100        // CLK_TCK; 100 on effectively every Linux
	identityTick    = time.Second / userHZ
	oPath           = 0x200000 // O_PATH (not in std syscall); 0x200000 on amd64/arm64
)

// The executor-side safety rails re-check the LIVE target (defence in depth),
// but the LISTS they check against are defined once in internal/response and
// reached through response.BuiltinDenyName, response.UnderNeverTouch,
// response.UnderAllowPaths and response.UnderTrustedExePrefix -- no second copy
// here to drift from the decision layer (M7).

type linuxExecutor struct{ cfg Config }

func newExecutor(cfg Config) (Executor, error) { return &linuxExecutor{cfg: cfg}, nil }

func (e *linuxExecutor) Enforcing() bool { return e.cfg.Enforce }

func (e *linuxExecutor) logf(format string, a ...any) { e.cfg.Logf(format, a...) }

// gate returns a prefix for log lines so a reader always sees whether an
// action was real or a dry-run.
func (e *linuxExecutor) gate() string {
	if e.cfg.Enforce {
		return "ENFORCE"
	}
	return "DRY-RUN"
}

// dryRunProcess builds the DryRun handle for a non-enforcing process verb
// (freeze, kill, collect). It evaluates the live target through identify() --
// the SAME rails the enforcing path runs -- but a rail refusal is RECORDED in
// the handle's Note ("would be refused: ...") and NEVER returned as an error: a
// dry-run must never act and never fail on a rail, so it reports the same
// outcome whether the target is uid 0 (as a self-target is when the suite runs
// as root) or not (E1). Any pidfd identify opened is closed here, and signal 0
// is the strongest syscall reached, so nothing is signalled, stopped or moved.
func (e *linuxExecutor) dryRunProcess(kind response.Action, p response.ProcessRef, scope response.Scope, verb string) Handle {
	pidfd, live, err := e.identify(p)
	if pidfd >= 0 {
		_ = syscall.Close(pidfd)
	}
	h := Handle{ID: newHandleID(), Kind: kind, PID: p.PID, Exe: live.Exe, StartTime: live.StartTime, DryRun: true, Method: "dry-run"}
	if err != nil {
		h.Note = "would be refused: " + err.Error()
		e.logf("response/exec: %s would %s pid %d but the live target would be refused: %v", e.gate(), verb, p.PID, err)
		return h
	}
	e.logf("response/exec: %s would %s pid %d (%s)%s", e.gate(), verb, p.PID, live.Exe, scopeNote(scope))
	return h
}

// scopeNote renders a scope for a dry-run log line, or "" for a scopeless verb
// (collect). It keeps dryRunProcess one shape across freeze, kill and collect.
func scopeNote(scope response.Scope) string {
	if scope == "" {
		return ""
	}
	return " scope " + string(scope)
}

// ---- process identity (the correctness crux) -------------------------------

// identify opens a pidfd (pinning one process for its lifetime), reads its
// start time and exe, confirms it is still alive through the fd, and checks
// its identity against the alert's reference. On success it returns the OPEN
// pidfd -- the caller MUST close it -- so the subsequent act is race-free: the
// fd cannot come to name a different process. See
// docs/design/response-actions.md section 5.1.
func (e *linuxExecutor) identify(p response.ProcessRef) (int, Live, error) {
	if p.PID <= 2 {
		return -1, Live{}, fmt.Errorf("%w: pid %d is init/kthreadd", ErrDenied, p.PID)
	}
	pidfd, err := pidfdOpen(p.PID)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return -1, Live{}, ErrGone
		}
		return -1, Live{}, fmt.Errorf("pidfd_open(%d): %w", p.PID, err)
	}
	// Read identity AFTER pinning the fd. If the process is still alive at the
	// liveness check below, the pid cannot have been reused between open and
	// read, so this read describes the pinned process.
	start, startErr := readStartTime(p.PID)
	exe, exeErr := readExe(p.PID)
	cg, _ := readCgroup(p.PID)

	// Liveness through the fd: signal 0 reports existence without sending.
	if err := pidfdSendSignal(pidfd, 0); err != nil {
		_ = syscall.Close(pidfd)
		if errors.Is(err, syscall.ESRCH) {
			return -1, Live{}, ErrGone
		}
		return -1, Live{}, fmt.Errorf("pidfd liveness: %w", err)
	}

	live := Live{PID: p.PID, StartTime: start, Exe: exe, CgroupPath: cg, UID: -1}

	// ---- live safety rails (ErrDenied): what is true NOW, not what the log
	// said. These run against the pinned, confirmed-alive process. ----

	// F2: a built-in protected NAME shields a process ONLY when its LIVE exe
	// realpath is under a trusted system prefix, or its cgroup is a protected
	// unit. A payload named after a daemon in a world-writable dir
	// (/tmp/.x/sshd) is a MASQUERADE: the shield is deliberately not applied,
	// so it stays killable. Shielding by name alone would let any attacker make
	// malware un-killable just by naming it `sshd`.
	realExe := strings.TrimSuffix(exe, " (deleted)")
	cgProtected := cgroupProtectedUnit(cg)
	if response.BuiltinDenyName(filepath.Base(realExe)) {
		if response.UnderTrustedExePrefix(realExe) || cgProtected {
			_ = syscall.Close(pidfd)
			return -1, live, fmt.Errorf("%w: live exe %q is a protected system process", ErrDenied, exe)
		}
		live.Masquerade = true // protected name, untrusted path: a cloak, not a shield
	}

	// F3: refuse any process whose cgroup resolves to a protected system unit
	// (init.scope or a critical unit), independent of its exe name.
	if cgProtected {
		_ = syscall.Close(pidfd)
		return -1, live, fmt.Errorf("%w: live cgroup %q is a protected unit", ErrDenied, cg)
	}

	// F3: refuse a live uid-0 target unless allowRoot. Fail closed -- a uid that
	// cannot be read cannot be confirmed non-root, so it is refused too.
	uid, uidErr := readUID(p.PID)
	if uidErr == nil {
		live.UID = uid
	}
	if !e.cfg.AllowRoot {
		if uidErr != nil {
			_ = syscall.Close(pidfd)
			return -1, live, fmt.Errorf("%w: cannot read uid for pid %d: %w", ErrDenied, p.PID, uidErr)
		}
		if uid == 0 {
			_ = syscall.Close(pidfd)
			return -1, live, fmt.Errorf("%w: live target runs as uid 0 and allowRoot is false", ErrDenied)
		}
	}

	// Identity proof. FAIL CLOSED: any failure to confirm identity -- a start
	// time that cannot be read, a start-time mismatch, an exe that cannot be
	// read or that does not match the alert's image -- refuses the target with
	// ErrStaleTarget. A pid whose identity cannot be confirmed is a pid-reuse
	// risk; refusing is always preferred to acting on the wrong process (§5.1).
	if startErr != nil {
		_ = syscall.Close(pidfd)
		return -1, live, fmt.Errorf("%w: cannot read start time for pid %d: %w", ErrStaleTarget, p.PID, startErr)
	}
	switch {
	case !p.StartTime.IsZero():
		if d := start.Sub(p.StartTime); d < -identityTick || d > identityTick {
			_ = syscall.Close(pidfd)
			return -1, live, fmt.Errorf("%w: start time %s != reference %s", ErrStaleTarget, start, p.StartTime)
		}
	case !p.EventTime.IsZero():
		// Unknown start time (auditd/Laurel): a reuser was forked after the
		// event, so its start time exceeds the event time; refuse it.
		if start.After(p.EventTime.Add(e.cfg.SkewTolerance)) {
			_ = syscall.Close(pidfd)
			return -1, live, fmt.Errorf("%w: start time %s is after event %s + skew", ErrStaleTarget, start, p.EventTime)
		}
	default:
		// No time reference at all (neither StartTime nor EventTime): pid reuse
		// cannot be excluded, and an exe match alone would not exclude it (a new
		// process running the same binary at the same path passes the exe bind).
		// Refuse, fail closed.
		_ = syscall.Close(pidfd)
		return -1, live, fmt.Errorf("%w: no start-time or event-time reference to verify pid %d against", ErrStaleTarget, p.PID)
	}

	// Exe binding: where the alert recorded an image, the live exe must be that
	// same on-disk binary. Comparison is by the real file behind each path (its
	// dev+ino), so a PATH symlink or a coreutils-multicall name still matches
	// the binary /proc/<pid>/exe resolves to, while a genuinely different
	// binary (or a process that has since exec'd onto another image) is
	// refused. Fail closed if the exe cannot be read at all.
	if p.Image != "" {
		if exeErr != nil {
			_ = syscall.Close(pidfd)
			return -1, live, fmt.Errorf("%w: cannot read exe for pid %d: %w", ErrStaleTarget, p.PID, exeErr)
		}
		if !exeMatches(p.Image, p.PID, exe) {
			_ = syscall.Close(pidfd)
			return -1, live, fmt.Errorf("%w: live exe %q != image %q", ErrStaleTarget, exe, p.Image)
		}
	}
	return pidfd, live, nil
}

// exeMatches reports whether the live exe of pid is the same on-disk binary as
// the alert's expected image. The primary test is inode identity: stat (which
// follows the magic /proc/<pid>/exe symlink to the real file) against stat of
// the expected path (following its own symlinks). This matches a PATH entry
// such as /run/current-system/sw/bin/sleep, or a coreutils multicall name, to
// the actual binary the kernel recorded, without brittle string munging. If
// either file cannot be stat'd (e.g. the exe was deleted after exec, so
// readlink returned a "<path> (deleted)" string), it falls back to a resolved
// string comparison. A failure to match is a refusal upstream, so this returns
// false whenever it cannot positively confirm the two are the same binary.
func exeMatches(expected string, pid int, liveExe string) bool {
	if expected == "" {
		return true
	}
	var le, ee syscall.Stat_t
	liveErr := syscall.Stat(fmt.Sprintf("/proc/%d/exe", pid), &le)
	expErr := syscall.Stat(expected, &ee)
	if liveErr == nil && expErr == nil {
		return le.Dev == ee.Dev && le.Ino == ee.Ino
	}
	// Fallback for a deleted or unstattable target: compare resolved paths.
	live := strings.TrimSuffix(liveExe, " (deleted)")
	if expected == live {
		return true
	}
	if r, err := filepath.EvalSymlinks(expected); err == nil && r == live {
		return true
	}
	return false
}

func (e *linuxExecutor) Verify(_ context.Context, p response.ProcessRef) (Live, error) {
	pidfd, live, err := e.identify(p)
	if pidfd >= 0 {
		_ = syscall.Close(pidfd)
	}
	return live, err
}

// ---- freeze / thaw ---------------------------------------------------------

// Freeze store state values and the thaw tombstone file name. statePending
// (store.go) is the written-before-the-act state; stateFrozen is the finalised
// one.
const (
	stateFrozen = "frozen"
	thawedName  = "thawed.json"
)

// freezeManifest is the freeze store entry (docs section 2.7). It is written
// state=pending BEFORE any pid is moved or stopped -- recording each pid's
// ORIGINAL cgroup, which Thaw moves it back to -- and finalised to state=frozen
// after the act. Order is the idempotency key the drain's already-applied check
// reads; Thaw works from this manifest alone, so the ledger is a record, not a
// database the undo depends on.
type freezeManifest struct {
	ID      string         `json:"id"`
	Version int            `json:"version"`
	Order   string         `json:"order,omitempty"`
	State   string         `json:"state"`  // pending | frozen
	Method  string         `json:"method"` // cgroup | sigstop
	Target  freezeTarget   `json:"target"`
	Scope   response.Scope `json:"scope,omitempty"`
	PIDs    []int          `json:"pids"`
	Orig    map[int]string `json:"orig,omitempty"`   // pid -> original cgroup path (cgroup method)
	Cgroup  string         `json:"cgroup,omitempty"` // the CgroupRoot child dir (absolute)
	Time    time.Time      `json:"time"`
	BootID  string         `json:"bootId,omitempty"` // a cgroup does not survive a reboot
}

type freezeTarget struct {
	PID       int       `json:"pid"`
	Exe       string    `json:"exe,omitempty"`
	StartTime time.Time `json:"startTime,omitzero"`
}

// freezeThawed is the thaw tombstone: its presence makes a second thaw a no-op.
type freezeThawed struct {
	Time        time.Time      `json:"time"`
	OperatorUID int            `json:"operatorUid"`
	Outcome     string         `json:"outcome,omitempty"` // thawed | reboot | rolled-back
	PerPID      map[int]string `json:"perPid,omitempty"`  // pid -> moved-home|moved-fallback|moved|cont|gone
}

func (e *linuxExecutor) Freeze(ctx context.Context, p response.ProcessRef, scope response.Scope) (Handle, error) {
	// Dry-run FIRST, before identify can turn a rail into a returned error: a
	// non-enforcing executor records the would-be outcome and acts on nothing
	// (E1). The enforcing path below runs the same identify and does act.
	if !e.cfg.Enforce {
		return e.dryRunProcess(response.ActionFreeze, p, scope, "freeze"), nil
	}

	pidfd, live, err := e.identify(p)
	if err != nil {
		return Handle{}, err
	}
	defer func() { _ = syscall.Close(pidfd) }()

	pids := e.targetSet(p.PID, scope)

	// F7: idempotency. If the target is ALREADY inside a child of CgroupRoot, a
	// previous Freeze put it there; return that existing handle and make no
	// second cgroup. A second cgroup would record the FIRST quarantine cgroup as
	// the pids' Orig, so thawing handle 1 then handle 2 would move them into a
	// directory handle 1 had removed -- the homeless-pid bug F7 names.
	if existing, ok := e.existingFreezeID(p.PID); ok {
		e.logf("response/exec: %s freeze is idempotent: pid %d already frozen under handle %s", e.gate(), p.PID, existing)
		return e.handleFromFreezeStore(existing, live), nil
	}

	id := newHandleID()
	entryDir := filepath.Join(e.cfg.FreezeDir, id)
	man := freezeManifest{
		ID: id, Version: manifestVersion, Order: orderIDFromContext(ctx),
		State: statePending, Target: freezeTarget{PID: p.PID, Exe: live.Exe, StartTime: live.StartTime},
		Scope: scope, PIDs: pids, Time: time.Now().UTC(), BootID: currentBootID(),
	}

	// Prefer the cgroup v2 freezer; fall back to SIGSTOP. In BOTH paths the
	// manifest is written (state pending) BEFORE anything is stopped or moved,
	// so an unwritable store refuses the freeze having touched no pid, and a
	// crash mid-migrate leaves a recoverable pending entry.
	if dir, ok := e.cgroupCreate(id); ok {
		man.Method = "cgroup"
		man.Cgroup = dir
		// Record each pid's original cgroup WHILE it is still home: this is where
		// Thaw moves it back to.
		man.Orig = make(map[int]string, len(pids))
		for _, pid := range pids {
			if cg, cerr := readCgroup(pid); cerr == nil {
				man.Orig[pid] = cg
			}
		}
		if werr := storeWriteManifest(entryDir, man); werr != nil {
			_ = os.Remove(dir) // the frozen-but-empty cgroup; no pid moved
			return Handle{}, fmt.Errorf("freeze: manifest-first write failed, no pid moved: %w", werr)
		}
		// Act: migrate the pids into the frozen cgroup (frozen on arrival).
		for _, pid := range pids {
			_ = writeCgroupProcs(dir, pid)
		}
		e.finalizeFreeze(entryDir, &man)
		e.logf("response/exec: %s froze %d task(s) via cgroup %s", e.gate(), len(pids), dir)
		return Handle{ID: id, Kind: response.ActionFreeze, PID: p.PID, Exe: live.Exe, StartTime: live.StartTime, Method: "cgroup", Undo: id}, nil
	}

	// SIGSTOP fallback (weaker: a child forked between the walk and the stop can
	// escape, and a watchdog SIGCONT can resume it -- recorded as such).
	man.Method = "sigstop"
	if werr := storeWriteManifest(entryDir, man); werr != nil {
		return Handle{}, fmt.Errorf("freeze: manifest-first write failed, no pid stopped: %w", werr)
	}
	man.PIDs = e.sigAll(pids, syscall.SIGSTOP)
	e.finalizeFreeze(entryDir, &man)
	e.logf("response/exec: %s froze %d task(s) via SIGSTOP (no cgroup v2 freezer)", e.gate(), len(man.PIDs))
	return Handle{ID: id, Kind: response.ActionFreeze, PID: p.PID, Exe: live.Exe, StartTime: live.StartTime, Method: "sigstop", Undo: id}, nil
}

// finalizeFreeze marks a freeze manifest committed (state frozen, 0400). A
// finalise failure is logged, not fatal: the act already happened, and the
// recovery pass finalises a still-pending manifest from the live cgroup.
func (e *linuxExecutor) finalizeFreeze(entryDir string, man *freezeManifest) {
	man.State = stateFrozen
	if err := storeWriteManifest(entryDir, *man); err != nil {
		e.logf("response/exec: WARNING freeze finalise write failed for %s: %v", man.ID, err)
		return
	}
	if err := storeFinalize(entryDir); err != nil {
		e.logf("response/exec: WARNING freeze finalise seal failed for %s: %v", man.ID, err)
	}
}

func (e *linuxExecutor) Thaw(_ context.Context, h Handle) error {
	if h.DryRun {
		e.logf("response/exec: %s would thaw %s", e.gate(), h.ID)
		return nil
	}
	id := h.Undo
	if id == "" {
		id = h.ID
	}
	if id == "" {
		return errors.New("thaw: handle carries no freeze store id")
	}
	entryDir := filepath.Join(e.cfg.FreezeDir, id)
	var man freezeManifest
	if err := storeReadManifest(entryDir, &man); err != nil {
		if errors.Is(err, errNoManifest) {
			return fmt.Errorf("thaw: no freeze store entry for %s (a dry-run handle, or not a freeze)", id)
		}
		return fmt.Errorf("thaw: %w", err)
	}

	// Idempotent by the tombstone: a second thaw is a no-op.
	if storeHasTombstone(entryDir, thawedName) {
		e.logf("response/exec: %s %s already thawed", e.gate(), id)
		return nil
	}

	tomb := freezeThawed{Time: time.Now().UTC(), OperatorUID: operatorUID(), PerPID: map[int]string{}}

	// A cgroup does not survive a reboot: a frozen handle from a previous boot
	// has nothing to move, so write the tombstone and return.
	if man.Method == "cgroup" && man.BootID != "" && man.BootID != currentBootID() {
		tomb.Outcome = "reboot"
		return storeTombstone(entryDir, thawedName, tomb)
	}

	switch man.Method {
	case "cgroup":
		e.thawCgroup(&man, &tomb)
	case "sigstop":
		for _, pid := range man.PIDs {
			if sigPid(pid, syscall.SIGCONT) == nil {
				tomb.PerPID[pid] = "cont"
			} else {
				tomb.PerPID[pid] = "gone"
			}
		}
	default:
		return fmt.Errorf("thaw: unknown method %q", man.Method)
	}
	tomb.Outcome = "thawed"
	return storeTombstone(entryDir, thawedName, tomb)
}

// thawCgroup moves each manifest pid back to its pre-freeze cgroup and removes
// the quarantine cgroup. It confirms a pid is in the quarantine cgroup BEFORE
// moving it: a pid that already left (killed, or moved by root) is never
// force-moved, because the pid may since have been reused by an innocent.
func (e *linuxExecutor) thawCgroup(man *freezeManifest, tomb *freezeThawed) {
	inCgroup := map[int]bool{}
	if procs, err := readCgroupProcs(man.Cgroup); err == nil {
		for _, pid := range procs {
			inCgroup[pid] = true
		}
	}
	for _, pid := range man.PIDs {
		if !inCgroup[pid] {
			tomb.PerPID[pid] = "moved" // left the cgroup already; do not chase it
			continue
		}
		switch orig := man.Orig[pid]; {
		case orig != "" && cgroupExists(orig):
			_ = writeCgroupProcs(orig, pid)
			tomb.PerPID[pid] = "moved-home"
		default:
			// Original cgroup gone: move to the parent of the quarantine root so
			// the pid is at least out of the frozen cgroup (loud, recorded).
			_ = writeCgroupProcs(filepath.Dir(e.cfg.CgroupRoot), pid)
			tomb.PerPID[pid] = "moved-fallback"
		}
	}
	if man.Cgroup != "" {
		_ = os.WriteFile(filepath.Join(man.Cgroup, "cgroup.freeze"), []byte("0"), 0o200)
		if e.waitPopulatedZero(man.Cgroup) {
			_ = os.Remove(man.Cgroup)
		}
	}
}

// ---- kill ------------------------------------------------------------------

func (e *linuxExecutor) Kill(_ context.Context, p response.ProcessRef, scope response.Scope) (Handle, error) {
	// Dry-run FIRST (E1): record the would-be outcome, signal nothing. A rail
	// (uid-0 self-target under a root test runner, a masquerade, a stale pid) is
	// a recorded note here, never a returned error.
	if !e.cfg.Enforce {
		return e.dryRunProcess(response.ActionKill, p, scope, "kill"), nil
	}

	pidfd, live, err := e.identify(p)
	if err != nil {
		return Handle{}, err
	}
	defer func() { _ = syscall.Close(pidfd) }()

	id := newHandleID()
	pids := e.targetSet(p.PID, scope)

	if scope == response.ScopeProcess {
		if err := pidfdSendSignal(pidfd, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return Handle{}, fmt.Errorf("pidfd_send_signal(SIGKILL): %w", err)
		}
		e.logf("response/exec: %s killed pid %d via pidfd", e.gate(), p.PID)
		return Handle{ID: id, Kind: response.ActionKill, PID: p.PID, Exe: live.Exe, StartTime: live.StartTime, Method: "pidfd", Note: "no undo"}, nil
	}

	// Tree kill: move into a frozen cgroup then cgroup.kill (atomic), falling
	// back to per-pid pidfd SIGKILL over the frozen set. Kill keeps no store
	// (it is not reversible), so there is no manifest here.
	if cgDir, ok := e.cgroupCreate(id); ok {
		for _, pid := range pids {
			_ = writeCgroupProcs(cgDir, pid)
		}
		method := "cgroup-kill"
		if err := os.WriteFile(filepath.Join(cgDir, "cgroup.kill"), []byte("1"), 0o200); err != nil {
			method = "pidfd-tree"
			e.sigAll(pids, syscall.SIGKILL)
		}
		// F8: a SIGKILLed task leaves the cgroup within milliseconds, but not
		// instantly; rmdir of a still-populated cgroup returns EBUSY and the dir
		// leaks. Wait for cgroup.events to report the cgroup unpopulated (bounded)
		// THEN rmdir -- never rmdir-and-ignore-the-error. A cgroup still populated
		// at the bound is left for the drain's recovery pass, recorded on the
		// handle, rather than racing a doomed rmdir.
		note := "no undo"
		if e.waitPopulatedZero(cgDir) {
			if err := os.Remove(cgDir); err != nil {
				note = "cgroupLeft: " + err.Error()
			}
		} else {
			note = "cgroupLeft: still populated after " + populatedWaitBound.String()
		}
		e.logf("response/exec: %s killed %d task(s) via %s", e.gate(), len(pids), method)
		return Handle{ID: id, Kind: response.ActionKill, PID: p.PID, Exe: live.Exe, StartTime: live.StartTime, Method: method, Note: note}, nil
	}
	e.sigAll(pids, syscall.SIGKILL)
	e.logf("response/exec: %s killed %d task(s) via per-pid pidfd (no cgroup)", e.gate(), len(pids))
	return Handle{ID: id, Kind: response.ActionKill, PID: p.PID, Exe: live.Exe, StartTime: live.StartTime, Method: "pidfd-tree", Note: "no undo"}, nil
}

// ---- quarantine / restore --------------------------------------------------

// fileStat records the inode identity and metadata of a quarantined file.
// Field widths match 64-bit Linux (amd64/arm64), the only platforms this
// file builds for.
type fileStat struct {
	Dev   uint64 `json:"dev"`
	Ino   uint64 `json:"ino"`
	Mode  uint32 `json:"mode"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	Size  int64  `json:"size"`
	MTime string `json:"mtime"`
	Nlink uint64 `json:"nlink"`
}

// Quarantine store state values and the restore tombstone name. stateHeld is
// the finalised state (statePending, store.go, is the written-before-the-act
// one). unhashedSentinel is recorded in SHA256 when the file was over
// MaxFileBytes: it is a sentinel, not a hash, so a reader tests equality and
// never parses it as hex (Q6).
const (
	stateHeld        = "held"
	restoredName     = "restored.json"
	unhashedSentinel = "unhashed"
)

// quarantineManifest is the quarantine store entry (docs quarantine.md section
// 3.5). It is written state=pending BEFORE the rename/neuter (Q2) -- carrying
// the ORIGINAL stat Restore reapplies -- and finalised to state=held after the
// act. Order is the idempotency key the drain's already-applied check reads, so
// a replayed order is a no-op. The store header (id, order, state) shares the
// json tags storeScanForOrder reads across every kind.
type quarantineManifest struct {
	ID        string    `json:"id"`
	Version   int       `json:"version"`
	Order     string    `json:"order,omitempty"`
	State     string    `json:"state"` // pending | held
	OrigPath  string    `json:"origPath"`
	Method    string    `json:"method"` // rename | neuter | pending
	Stat      fileStat  `json:"stat"`   // the PRE-neuter stat (Restore reapplies this mode)
	SHA256    string    `json:"sha256"` // hex, or unhashedSentinel over MaxFileBytes
	Immutable bool      `json:"immutable"`
	Time      time.Time `json:"time"`
	BootID    string    `json:"bootId,omitempty"`
}

// quarantineRestored is the restore tombstone: its presence makes a second
// restore a no-op, and the recovery pass writes it with outcome "rolled-back"
// for a pending entry whose act never landed (so already-applied never fires on
// it and the order reprocesses normally).
type quarantineRestored struct {
	Time        time.Time `json:"time"`
	OperatorUID int       `json:"operatorUid"`
	Outcome     string    `json:"outcome,omitempty"` // restored | rolled-back
	Dest        string    `json:"dest,omitempty"`
}

// inspectQuarantineTarget runs the quarantine path rails and opens the live
// inode read-only (O_PATH|O_NOFOLLOW), returning the open fd (the caller closes
// any non-negative fd), its stat, the bounded hash and any refusal. The refusal
// is a RETURNED VALUE, not a control-flow jump, so the dry-run path can record
// it in the handle (E1) while the enforcing path returns it before touching
// anything. Every later act binds to THIS fd's inode, never a re-resolved path,
// so a swap of the directory entry cannot redirect the act onto an innocent
// file (Q1). The hash is bounded by MaxFileBytes (Q6): over the cap the file is
// still taken but recorded "unhashed", so a 1 TiB sparse file cannot block the
// drain.
func (e *linuxExecutor) inspectQuarantineTarget(path string) (fd int, st syscall.Stat_t, sum string, railErr error) {
	fd = -1
	if pfx, bad := response.UnderNeverTouch(path); bad {
		return -1, st, "", fmt.Errorf("%w: %q under never-touch %q", ErrDenied, path, pfx)
	}
	if !response.UnderAllowPaths(e.cfg.QuarantineAllowPaths, path) {
		return -1, st, "", fmt.Errorf("%w: %q not under quarantine allowPaths", ErrDenied, path)
	}
	opened, err := syscall.Open(path, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, st, "", fmt.Errorf("open %q: %w", path, err)
	}
	fd = opened
	if err := syscall.Fstat(fd, &st); err != nil {
		return fd, st, "", fmt.Errorf("fstat %q: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fd, st, "", fmt.Errorf("%w: %q is not a regular file", ErrStaleTarget, path)
	}
	return fd, st, e.hashBounded(fd, st.Size), nil
}

func (e *linuxExecutor) Quarantine(ctx context.Context, f response.FileRef) (Handle, error) {
	path := filepath.Clean(f.Path)
	fd, st, sum, railErr := e.inspectQuarantineTarget(path)
	if fd >= 0 {
		defer func() { _ = syscall.Close(fd) }()
	}

	id := newHandleID()
	// Dry-run FIRST (E1): a rail refusal (never-touch, allowPaths, a non-regular
	// file) is RECORDED in the handle's Note, never returned as an error; nothing
	// is moved or neutered. The enforcing path returns the same refusal below,
	// before touching anything.
	if !e.cfg.Enforce {
		h := Handle{ID: id, Kind: response.ActionQuarantine, DryRun: true, Method: "dry-run"}
		if railErr != nil {
			h.Note = "would be refused: " + railErr.Error()
			e.logf("response/exec: %s would quarantine %q but it would be refused: %v", e.gate(), path, railErr)
		} else {
			h.Note = "sha256:" + sum
			e.logf("response/exec: %s would quarantine %q (ino %d, sha256 %s)", e.gate(), path, st.Ino, sum)
		}
		return h, nil
	}
	if railErr != nil {
		return Handle{}, railErr
	}
	fstat := statToFileStat(st)

	entryDir := filepath.Join(e.cfg.QuarantineDir, id)
	dest := filepath.Join(entryDir, "file")
	man := quarantineManifest{
		ID: id, Version: manifestVersion, Order: orderIDFromContext(ctx),
		State: statePending, Method: "pending", OrigPath: path,
		Stat: fstat, SHA256: sum, Time: time.Now().UTC(), BootID: currentBootID(),
	}

	// Manifest FIRST (Q2): the pending manifest is written and committed before
	// anything is moved or neutered, so a store that cannot be written refuses
	// the quarantine having touched the file, and a crash mid-act leaves a
	// recoverable pending entry rather than an orphaned, unrestorable file.
	if werr := storeWriteManifest(entryDir, man); werr != nil {
		return Handle{}, fmt.Errorf("quarantine: manifest-first write failed, nothing moved: %w", werr)
	}

	// Test seam: swap the directory entry between the fstat and the act, to
	// prove the act binds to the fstat'd inode, not a re-resolved path (Q1).
	if quarantineSwapHook != nil {
		quarantineSwapHook()
	}

	err := renameat2Fn(atFDCWD, path, atFDCWD, dest, renameNoReplace)
	switch {
	case err == nil:
		// Post-rename inode recheck: if the entry at the old path was swapped
		// between our fstat and the rename, we moved the wrong file -- put it
		// straight back and refuse.
		var dst syscall.Stat_t
		if serr := syscall.Lstat(dest, &dst); serr == nil && (dst.Dev != st.Dev || dst.Ino != st.Ino) {
			_ = renameat2Fn(atFDCWD, dest, atFDCWD, path, 0)
			_ = os.RemoveAll(entryDir)
			return Handle{}, fmt.Errorf("%w: inode changed under the rename", ErrStaleTarget)
		}
		man.Method = "rename"
		// Neuter the STORED inode on the fd we fstat'd (Q7): the O_PATH fd still
		// names the moved inode after the rename. 0000 + immutable makes the
		// stored artifact inert to a careless root shell; Restore reapplies the
		// recorded mode.
		man.Immutable = neuterFd(fd)
	case errors.Is(err, syscall.EXDEV):
		// Cross-filesystem: neuter in place rather than copy. Act on the fstat'd
		// fd, never a re-resolved path (Q1): a swap race must not neuter an
		// innocent file now sitting at the path.
		man.Method = "neuter"
		man.Immutable = neuterFd(fd)
	default:
		_ = os.RemoveAll(entryDir)
		return Handle{}, fmt.Errorf("renameat2 %q: %w", path, err)
	}

	e.finalizeQuarantine(entryDir, &man)
	e.logf("response/exec: %s quarantined %q via %s (handle %s)", e.gate(), path, man.Method, id)
	return Handle{ID: id, Kind: response.ActionQuarantine, Method: man.Method, Undo: id, Note: "sha256:" + sum}, nil
}

// finalizeQuarantine marks a quarantine manifest committed (state held, 0400),
// mirroring finalizeFreeze. A finalise failure is logged, not fatal: the act
// already landed and the recovery pass finalises a still-pending manifest from
// the store alone.
func (e *linuxExecutor) finalizeQuarantine(entryDir string, man *quarantineManifest) {
	man.State = stateHeld
	if err := storeWriteManifest(entryDir, *man); err != nil {
		e.logf("response/exec: WARNING quarantine finalise write failed for %s: %v", man.ID, err)
		return
	}
	if err := storeFinalize(entryDir); err != nil {
		e.logf("response/exec: WARNING quarantine finalise seal failed for %s: %v", man.ID, err)
	}
}

// hashBounded returns the sha256 of the inode behind an O_PATH fd, or the
// unhashed sentinel when the file is larger than MaxFileBytes or unreadable
// (Q6). It never reads a file over the cap: the fstat size decides, so a sparse
// or hung file returns instantly and is still quarantined.
func (e *linuxExecutor) hashBounded(opathFd int, size int64) string {
	if e.cfg.MaxFileBytes > 0 && size > e.cfg.MaxFileBytes {
		return unhashedSentinel
	}
	sum, err := sha256OfFd(opathFd)
	if err != nil {
		return unhashedSentinel
	}
	return sum
}

func (e *linuxExecutor) Restore(_ context.Context, h Handle, to string) error {
	if h.DryRun {
		e.logf("response/exec: %s would restore %s to %s", e.gate(), h.ID, orOrig(to))
		return nil
	}
	id := h.Undo
	if id == "" {
		id = h.ID
	}
	if id == "" {
		return errors.New("restore: handle carries no quarantine store id")
	}
	entryDir := filepath.Join(e.cfg.QuarantineDir, id)
	var man quarantineManifest
	if err := storeReadManifest(entryDir, &man); err != nil {
		if errors.Is(err, errNoManifest) {
			return fmt.Errorf("restore: no quarantine store entry for %s (a dry-run handle, or not a quarantine)", id)
		}
		return fmt.Errorf("restore: %w", err)
	}

	// Idempotent by the tombstone (Q3): a second restore is a clean no-op and the
	// entry is KEPT, so the record of what was done to whom survives for list.
	if storeHasTombstone(entryDir, restoredName) {
		e.logf("response/exec: %s %s already restored", e.gate(), id)
		return nil
	}

	dest, err := e.restoreDest(man, to)
	if err != nil {
		return err
	}

	switch man.Method {
	case "rename":
		err = e.restoreRename(entryDir, man, dest)
	case "neuter":
		err = e.restoreNeuter(man, dest)
	default:
		return fmt.Errorf("restore: unknown method %q", man.Method)
	}
	if err != nil {
		return err
	}

	// Keep the entry and the inode; write the tombstone (Q3). The record of what
	// was done to whom, and now to where, survives the restore.
	e.logf("response/exec: %s restored %s to %s", e.gate(), id, dest)
	return storeTombstone(entryDir, restoredName, quarantineRestored{
		Time: time.Now().UTC(), OperatorUID: operatorUID(), Outcome: "restored", Dest: dest,
	})
}

// restoreDest resolves the restore destination: the manifest's original path by
// default, or the operator's -to path when one was given. A non-empty -to does
// NOT bypass the allow-list -- it is bounded by the SAME functions the forward
// path uses (absolute, under allowPaths, outside never-touch) and may not land
// inside the quarantine store (docs §3.4). It is a path the operator typed,
// checked rather than trusted.
func (e *linuxExecutor) restoreDest(man quarantineManifest, to string) (string, error) {
	if to == "" {
		return man.OrigPath, nil
	}
	clean := filepath.Clean(to)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("%w: -to %q must be an absolute path", ErrDenied, to)
	}
	if pfx, bad := response.UnderNeverTouch(clean); bad {
		return "", fmt.Errorf("%w: -to %q under never-touch %q", ErrDenied, to, pfx)
	}
	if !response.UnderAllowPaths(e.cfg.QuarantineAllowPaths, clean) {
		return "", fmt.Errorf("%w: -to %q not under quarantine allowPaths", ErrDenied, to)
	}
	store := filepath.Clean(e.cfg.QuarantineDir)
	if clean == store || strings.HasPrefix(clean, store+"/") {
		return "", fmt.Errorf("%w: -to %q is inside the quarantine store", ErrDenied, to)
	}
	return clean, nil
}

// restoreRename reverses a rename-method quarantine. It confirms the stored
// inode is still the one the manifest recorded (Q4: BOTH dev and ino),
// un-neuters it (Q7's store neuter, reversed) and moves it to dest with
// RENAME_NOREPLACE, so an occupied destination is refused -- never clobbered --
// and the squatter is left untouched. On any failure after the immutable bit
// was cleared the stored file is made inert again, so the artifact is never
// left readable or executable in the store.
func (e *linuxExecutor) restoreRename(entryDir string, man quarantineManifest, dest string) error {
	stored := filepath.Join(entryDir, "file")
	var st syscall.Stat_t
	if err := syscall.Lstat(stored, &st); err != nil {
		return fmt.Errorf("restore: stat quarantined file: %w", err)
	}
	if st.Dev != man.Stat.Dev || st.Ino != man.Stat.Ino {
		return fmt.Errorf("%w: stored (dev,ino) no longer matches manifest", ErrStaleTarget)
	}
	// The store dir is 0700 root and not attacker-reachable, so a path-based
	// chmod of the stored file is race-free (the Q1 fd discipline is for the live
	// origPath; the move below is atomic).
	if man.Immutable {
		_ = clearImmutable(stored)
	}
	// Reapply the recorded mode with the RAW bits via syscall.Chmod, not
	// os.Chmod: os.FileMode's special bits (setuid/setgid/sticky) live at
	// 1<<23.. and os.Chmod would silently drop a 0o4000/0o2000/0o1000 bit, so a
	// setuid dropper would come back without its setuid bit.
	if err := syscall.Chmod(stored, man.Stat.Mode&0o7777); err != nil {
		reinertStore(stored, man.Immutable)
		return fmt.Errorf("restore: chmod stored file: %w", err)
	}
	if err := renameat2(atFDCWD, stored, atFDCWD, dest, renameNoReplace); err != nil {
		reinertStore(stored, man.Immutable)
		if errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("%w: %q is occupied; move it aside or use -to", ErrDenied, dest)
		}
		return fmt.Errorf("restore: rename back: %w", err)
	}
	return nil
}

// restoreNeuter reverses an in-place neuter. It opens the ORIGINAL path
// O_PATH|O_NOFOLLOW, confirms BOTH dev and ino against the manifest (Q4: a weak
// neuter's path may be a different file by now -- refuse with "inode replaced"),
// then clears the immutable bit and reapplies the recorded mode ON THE FD (Q1's
// fd discipline applied to the reverse direction), confirming the mode landed.
// A -to destination then moves the un-neutered inode there with RENAME_NOREPLACE.
func (e *linuxExecutor) restoreNeuter(man quarantineManifest, dest string) error {
	fd, err := syscall.Open(man.OrigPath, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("restore: open neutered path %q: %w", man.OrigPath, err)
	}
	defer func() { _ = syscall.Close(fd) }()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("restore: fstat neutered path: %w", err)
	}
	if st.Dev != man.Stat.Dev || st.Ino != man.Stat.Ino {
		return fmt.Errorf("%w: inode replaced at %q since neuter", ErrStaleTarget, man.OrigPath)
	}
	// Reopen the identical inode O_RDONLY through /proc/self/fd (an O_PATH fd can
	// neither fchmod nor ioctl); same inode by construction, no re-resolution.
	rf, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd)) //nolint:gosec // our own fd, reopened by number
	if err != nil {
		return fmt.Errorf("restore: reopen neutered inode: %w", err)
	}
	defer func() { _ = rf.Close() }()
	if man.Immutable {
		_ = chattrFd(int(rf.Fd()), false)
	}
	// Raw-bit fchmod on the fd (not os.File.Chmod): preserve setuid/setgid/sticky
	// (os.FileMode would drop them) and stay on the confirmed inode (Q1).
	if err := syscall.Fchmod(int(rf.Fd()), man.Stat.Mode&0o7777); err != nil {
		return fmt.Errorf("restore: fchmod neutered inode: %w", err)
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(int(rf.Fd()), &after); err != nil {
		return fmt.Errorf("restore: re-fstat neutered inode: %w", err)
	}
	if after.Mode&0o7777 != man.Stat.Mode&0o7777 {
		return fmt.Errorf("restore: recorded mode %o did not take (now %o)", man.Stat.Mode&0o7777, after.Mode&0o7777)
	}
	if dest != man.OrigPath {
		if err := renameat2(atFDCWD, man.OrigPath, atFDCWD, dest, renameNoReplace); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("%w: %q is occupied; move it aside or use -to", ErrDenied, dest)
			}
			return fmt.Errorf("restore: move to -to dest: %w", err)
		}
	}
	return nil
}

// reinertStore returns a partially-un-neutered stored file to its inert state
// (mode 0, immutable where it had been set) after a restore step failed, so the
// kept artifact is never left readable or executable in the store.
func reinertStore(stored string, wasImmutable bool) {
	_ = os.Chmod(stored, 0)
	if wasImmutable {
		_ = chattr(stored, true)
	}
}

// ---- collect ---------------------------------------------------------------

// evidenceManifest is the evidence store entry, written manifest-first like the
// freeze store: a pending manifest (carrying the idempotency order id) before
// any /proc file is snapshotted, finalised to state=collected after.
type evidenceManifest struct {
	ID        string    `json:"id"`
	Version   int       `json:"version"`
	Order     string    `json:"order,omitempty"`
	State     string    `json:"state"`
	PID       int       `json:"pid"`
	Exe       string    `json:"exe,omitempty"`
	StartTime time.Time `json:"startTime,omitzero"`
	SHA256    string    `json:"sha256,omitempty"`
	Time      time.Time `json:"time"`
}

const stateCollected = "collected"

func (e *linuxExecutor) Collect(ctx context.Context, p response.ProcessRef) (Handle, error) {
	// Dry-run FIRST (E1): a rail refusal is a recorded note, never a returned
	// error; no /proc is snapshotted.
	if !e.cfg.Enforce {
		return e.dryRunProcess(response.ActionCollect, p, "", "collect evidence for"), nil
	}

	// Identify BEFORE snapshotting (§5.1): bind to the process the alert named
	// -- same pidfd pin, start-time and exe check as kill/freeze -- so the
	// evidence is of the right process, not of whoever holds the pid now. A
	// mismatch returns ErrStaleTarget/ErrGone rather than a snapshot of the
	// wrong /proc. The pidfd is held open across the snapshot.
	pidfd, live, err := e.identify(p)
	if err != nil {
		return Handle{}, err
	}
	defer func() { _ = syscall.Close(pidfd) }()

	id := newHandleID()
	dir := filepath.Join(e.cfg.EvidenceDir, id)
	// Manifest first: the pending manifest (with the order id) is written before
	// any /proc snapshot, so a crash mid-snapshot leaves a recoverable entry and
	// a replayed collect order is matched by its id.
	man := evidenceManifest{
		ID: id, Version: manifestVersion, Order: orderIDFromContext(ctx),
		State: statePending, PID: p.PID, Exe: live.Exe, StartTime: live.StartTime, Time: time.Now().UTC(),
	}
	if err := storeWriteManifest(dir, man); err != nil {
		return Handle{}, fmt.Errorf("collect: manifest-first write failed: %w", err)
	}
	for _, name := range []string{"cmdline", "environ", "status", "maps", "cgroup"} {
		src := fmt.Sprintf("/proc/%d/%s", p.PID, name)
		data, rerr := os.ReadFile(src) //nolint:gosec // reading the target's own /proc, by pid
		if rerr != nil {
			continue
		}
		// name is from the fixed literal list above, not external input.
		_ = os.WriteFile(filepath.Join(dir, name), data, 0o600) //#nosec G703,G304 -- fixed evidence filename under our own dir
	}
	if live.Exe != "" {
		if sum, herr := sha256OfPath(live.Exe); herr == nil {
			man.SHA256 = sum
		}
	}
	man.State = stateCollected
	if err := storeWriteManifest(dir, man); err == nil {
		_ = storeFinalize(dir)
	}
	e.logf("response/exec: %s collected evidence for pid %d into %s", e.gate(), p.PID, dir)
	return Handle{ID: id, Kind: response.ActionCollect, PID: p.PID, Exe: live.Exe, StartTime: live.StartTime, Method: "snapshot", Undo: id}, nil
}

// ---- store idempotency + recovery ------------------------------------------

// Applied reports whether a store this executor owns already holds a FINALISED
// entry for orderID, returning the handle to record. It is the drain's
// already-applied check (docs section 2.4): a replayed order -- a crash between
// the act and the unlink, or an operator copying an order back in -- is a no-op
// for the store-backed actions. Freeze, evidence and quarantine are scanned
// here. Kill keeps no store, so a replayed kill finds the pid gone or a reuser,
// both handled by identify().
func (e *linuxExecutor) Applied(_ context.Context, orderID string) (Handle, bool, error) {
	if id, ok := storeScanForOrder(e.cfg.FreezeDir, orderID); ok {
		var man freezeManifest
		_ = storeReadManifest(filepath.Join(e.cfg.FreezeDir, id), &man)
		return Handle{ID: id, Kind: response.ActionFreeze, PID: man.Target.PID, Method: man.Method, Undo: id, Exe: man.Target.Exe, StartTime: man.Target.StartTime}, true, nil
	}
	if id, ok := storeScanForOrder(e.cfg.EvidenceDir, orderID); ok {
		var man evidenceManifest
		_ = storeReadManifest(filepath.Join(e.cfg.EvidenceDir, id), &man)
		return Handle{ID: id, Kind: response.ActionCollect, PID: man.PID, Method: "snapshot", Undo: id, Exe: man.Exe, StartTime: man.StartTime}, true, nil
	}
	if id, ok := storeScanForOrder(e.cfg.QuarantineDir, orderID); ok {
		var man quarantineManifest
		_ = storeReadManifest(filepath.Join(e.cfg.QuarantineDir, id), &man)
		return Handle{ID: id, Kind: response.ActionQuarantine, Method: man.Method, Undo: id, Note: "sha256:" + man.SHA256}, true, nil
	}
	return Handle{}, false, nil
}

// Recover is the drain's startup repair pass over the freeze and quarantine
// stores and the cgroup root (docs section 2.4 step 4). It finalises a pending
// freeze manifest whose pids did reach the cgroup, a pending quarantine
// manifest whose rename/neuter did land, rolls back either whose act never
// landed, and removes an empty cgroup dir that no live manifest owns (the
// second half of F8: a kill cgroup left populated at the bound, later emptied).
// It never touches a finalised, untombstoned entry.
func (e *linuxExecutor) Recover(_ context.Context) ([]RecoveryResult, error) {
	var out []RecoveryResult
	live := map[string]bool{} // handle id -> has a live (finalised, untombstoned) manifest

	ents, _ := os.ReadDir(e.cfg.FreezeDir)
	for _, ent := range ents {
		if !ent.IsDir() {
			continue
		}
		entryDir := filepath.Join(e.cfg.FreezeDir, ent.Name())
		var man freezeManifest
		if err := storeReadManifest(entryDir, &man); err != nil {
			continue
		}
		tombstoned := storeHasTombstone(entryDir, thawedName)
		if man.State != statePending {
			if storeFinalised(man.State) && !tombstoned {
				live[man.ID] = true
			}
			continue
		}
		if tombstoned {
			continue // a rolled-back pending entry from an earlier pass
		}
		res := e.recoverPendingFreeze(entryDir, &man)
		out = append(out, res)
		if res.Outcome == "finalised" {
			live[man.ID] = true
		}
	}

	// Quarantine store: a pending manifest is finished from the store alone (the
	// stored file or the in-place neuter is checked against the manifest's
	// (dev, ino)) or rolled back when the act never landed. A tombstoned pending
	// entry is a previous pass's rollback and is skipped.
	qents, _ := os.ReadDir(e.cfg.QuarantineDir)
	for _, ent := range qents {
		if !ent.IsDir() {
			continue
		}
		entryDir := filepath.Join(e.cfg.QuarantineDir, ent.Name())
		var man quarantineManifest
		if err := storeReadManifest(entryDir, &man); err != nil {
			continue
		}
		if man.State != statePending {
			continue
		}
		if storeHasTombstone(entryDir, restoredName) {
			continue // a rolled-back pending entry from an earlier pass
		}
		out = append(out, e.recoverPendingQuarantine(entryDir, &man))
	}

	// Empty cgroup dirs under the root with no live manifest: remove them (a
	// kill cgroup that was still populated at the F8 bound and has since
	// emptied, or any other orphan). Never remove one that still holds tasks.
	cgents, _ := os.ReadDir(e.cfg.CgroupRoot)
	for _, ent := range cgents {
		if !ent.IsDir() || live[ent.Name()] {
			continue
		}
		dir := filepath.Join(e.cfg.CgroupRoot, ent.Name())
		if cgroupPopulated(dir) {
			continue
		}
		if os.Remove(dir) == nil {
			out = append(out, RecoveryResult{ID: ent.Name(), Outcome: "cgroup-removed"})
		}
	}
	return out, nil
}

// recoverPendingFreeze finalises or rolls back a single pending freeze entry.
// It is finalised if the act landed (the cgroup holds the pids); otherwise
// rolled back (any stray pids moved home, the cgroup dropped, a tombstone
// written so already-applied never fires on it).
func (e *linuxExecutor) recoverPendingFreeze(entryDir string, man *freezeManifest) RecoveryResult {
	res := RecoveryResult{ID: man.ID, Order: man.Order, Kind: response.ActionFreeze}

	migrated := false
	if man.Method == "cgroup" && man.Cgroup != "" {
		if procs, err := readCgroupProcs(man.Cgroup); err == nil && len(procs) > 0 {
			migrated = true
		}
	}
	if migrated {
		e.finalizeFreeze(entryDir, man)
		res.Outcome = "finalised"
		return res
	}

	// The act never landed: roll back.
	if man.Method == "cgroup" && man.Cgroup != "" {
		if procs, err := readCgroupProcs(man.Cgroup); err == nil {
			for _, pid := range procs {
				if orig := man.Orig[pid]; orig != "" {
					_ = writeCgroupProcs(orig, pid)
				}
			}
		}
		_ = os.WriteFile(filepath.Join(man.Cgroup, "cgroup.freeze"), []byte("0"), 0o200)
		_ = os.Remove(man.Cgroup)
	}
	_ = storeTombstone(entryDir, thawedName, freezeThawed{Time: time.Now().UTC(), OperatorUID: operatorUID(), Outcome: "rolled-back"})
	res.Outcome = "rolled-back"
	return res
}

// recoverPendingQuarantine finalises or rolls back a single pending quarantine
// entry, from the store alone (docs quarantine.md section 3.4). It finalises
// when the act demonstrably landed: the stored <id>/file is the manifest's
// inode (the rename landed), or the original path still holds the manifest's
// inode now neutered to mode 0 (the in-place neuter landed). Otherwise -- the
// original file is intact at its path, or the inode is nowhere to be found --
// nothing destructive happened, so it is rolled back with a tombstone, which
// keeps already-applied from firing and lets the order reprocess normally.
func (e *linuxExecutor) recoverPendingQuarantine(entryDir string, man *quarantineManifest) RecoveryResult {
	res := RecoveryResult{ID: man.ID, Order: man.Order, Kind: response.ActionQuarantine}

	// Case 1: the rename landed -- the stored file is the manifest's inode.
	if dev, ino, ok := statDevIno(filepath.Join(entryDir, "file")); ok && dev == man.Stat.Dev && ino == man.Stat.Ino {
		man.Method = "rename"
		if fd, err := syscall.Open(filepath.Join(entryDir, "file"), oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0); err == nil {
			man.Immutable = neuterFd(fd) // ensure neutered (idempotent)
			_ = syscall.Close(fd)
		}
		e.finalizeQuarantine(entryDir, man)
		res.Outcome = "finalised"
		return res
	}

	// Case 2: the inode is still at its original path. If it is already mode 0,
	// the in-place neuter landed (finalise); otherwise it is intact and nothing
	// happened (roll back below).
	if fd, err := syscall.Open(man.OrigPath, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0); err == nil {
		var st syscall.Stat_t
		serr := syscall.Fstat(fd, &st)
		if serr == nil && st.Dev == man.Stat.Dev && st.Ino == man.Stat.Ino && st.Mode&0o7777 == 0 {
			man.Method = "neuter"
			man.Immutable = neuterFd(fd) // confirm/ensure
			_ = syscall.Close(fd)
			e.finalizeQuarantine(entryDir, man)
			res.Outcome = "finalised"
			return res
		}
		_ = syscall.Close(fd)
	}

	// Roll back: the act never landed (or the inode is unrecoverable). Tombstone
	// so already-applied never fires and the order reprocesses normally.
	_ = storeTombstone(entryDir, restoredName, quarantineRestored{Time: time.Now().UTC(), OperatorUID: operatorUID(), Outcome: "rolled-back"})
	res.Outcome = "rolled-back"
	return res
}

// statDevIno lstats a path and returns its (dev, ino). A missing or unstattable
// path returns ok=false, so a recovery pass can tell "the rename landed" from
// "it did not" without branching on an error string.
func statDevIno(path string) (dev, ino uint64, ok bool) {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return 0, 0, false
	}
	return st.Dev, st.Ino, true
}

// ---- cgroup helpers --------------------------------------------------------

// cgroupCreate creates a child cgroup under CgroupRoot and freezes it (empty),
// so a task migrated in afterwards is frozen on arrival. It returns the dir and
// ok=false if the v2 freezer is unavailable or not writable (the caller falls
// back to SIGSTOP, or, for kill, to per-pid pidfd SIGKILL). Migration is the
// caller's step, kept separate so Freeze can write its manifest between the
// create and the migrate.
func (e *linuxExecutor) cgroupCreate(id string) (string, bool) {
	root := e.cfg.CgroupRoot
	if _, err := os.Stat(filepath.Dir(root)); err != nil {
		return "", false
	}
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", false
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.freeze"), []byte("1"), 0o200); err != nil {
		_ = os.Remove(dir)
		return "", false
	}
	return dir, true
}

// existingFreezeID reports the handle id of an EXISTING freeze cgroup the pid
// already sits in: if /proc/<pid>/cgroup resolves under CgroupRoot, the first
// path component below the root is that handle id. This is the F7 idempotency
// key -- a second Freeze of an already-frozen tree returns the first handle
// instead of making a second cgroup.
func (e *linuxExecutor) existingFreezeID(pid int) (string, bool) {
	cg, err := readCgroup(pid)
	if err != nil {
		return "", false
	}
	full := cg
	if !strings.HasPrefix(full, "/sys/fs/cgroup") {
		full = filepath.Join("/sys/fs/cgroup", cg)
	}
	root := filepath.Clean(e.cfg.CgroupRoot)
	if full != root && !strings.HasPrefix(full, root+"/") {
		return "", false
	}
	rest := strings.TrimPrefix(full, root+"/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", false
	}
	return rest, true
}

// handleFromFreezeStore rebuilds the Handle for an already-frozen tree from its
// store manifest, so a second Freeze returns the first handle verbatim.
func (e *linuxExecutor) handleFromFreezeStore(id string, live Live) Handle {
	method := "cgroup"
	var man freezeManifest
	if err := storeReadManifest(filepath.Join(e.cfg.FreezeDir, id), &man); err == nil && man.Method != "" {
		method = man.Method
	}
	return Handle{ID: id, Kind: response.ActionFreeze, PID: live.PID, Exe: live.Exe, StartTime: live.StartTime, Method: method, Undo: id, Note: "already frozen"}
}

// populatedPollStep and populatedWaitBound bound the wait for a cgroup to empty
// after a kill (F8) or a thaw migration, before rmdir. A SIGKILLed task leaves
// the cgroup within milliseconds; 10ms steps over a 2s bound is two hundred
// chances, far more than a healthy kill needs and short enough not to stall the
// drain.
const (
	populatedPollStep  = 10 * time.Millisecond
	populatedWaitBound = 2 * time.Second
)

// waitPopulatedZero polls cgroup.events until the cgroup reports no processes,
// or the bound elapses. It returns true when the cgroup is empty (safe to
// rmdir), false if it is still populated at the bound.
func (e *linuxExecutor) waitPopulatedZero(cgDir string) bool {
	deadline := time.Now().Add(populatedWaitBound)
	for {
		if !cgroupPopulated(cgDir) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(populatedPollStep)
	}
}

// cgroupPopulated reports whether cgroup.events says the cgroup still contains
// at least one process. A missing/unreadable events file (the cgroup is gone or
// never had one) reads as unpopulated -- there is nothing to wait for. It is a
// var so a non-root test can exercise waitPopulatedZero's polling.
var cgroupPopulated = func(cgDir string) bool {
	data, err := os.ReadFile(filepath.Join(cgDir, "cgroup.events")) //nolint:gosec // our own cgroup dir
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "populated ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "populated ")) != "0"
		}
	}
	return false
}

// readCgroupProcs returns the pids in a cgroup's cgroup.procs. It is a var so a
// test can stage the confirm-then-move set without a real cgroup.
var readCgroupProcs = func(cgDir string) ([]int, error) {
	if !strings.HasPrefix(cgDir, "/sys/fs/cgroup") {
		cgDir = filepath.Join("/sys/fs/cgroup", cgDir)
	}
	data, err := os.ReadFile(filepath.Join(cgDir, "cgroup.procs")) //nolint:gosec // our own cgroup dir
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, f := range strings.Fields(string(data)) {
		if pid, perr := strconv.Atoi(f); perr == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// cgroupExists reports whether a cgroup path (absolute or relative to the v2
// mount) still exists, so Thaw does not move a pid home to a vanished cgroup.
func cgroupExists(cg string) bool {
	full := cg
	if !strings.HasPrefix(full, "/sys/fs/cgroup") {
		full = filepath.Join("/sys/fs/cgroup", cg)
	}
	_, err := os.Stat(full)
	return err == nil
}

// currentBootID reads the kernel's boot id. A cgroup does not survive a reboot,
// so a freeze manifest records it and Thaw treats a different boot id as
// "nothing to move". A var for the test seam.
var currentBootID = func() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// operatorUID is the uid credited in a thaw tombstone: the invoking user behind
// sudo if known, else the real uid.
func operatorUID() int {
	if s := os.Getenv("SUDO_UID"); s != "" {
		if u, err := strconv.Atoi(s); err == nil {
			return u
		}
	}
	return os.Getuid()
}

// writeCgroupProcs migrates a pid into a cgroup by writing cgroup.procs. It is
// a var so Thaw's confirm-then-move logic can be exercised without a real
// cgroup (and without root).
var writeCgroupProcs = func(cgDir string, pid int) error {
	// cgDir may be an absolute cgroup path ("/sys/fs/cgroup/...") or a path
	// relative to the v2 mount (from /proc/<pid>/cgroup "0::<path>").
	if !strings.HasPrefix(cgDir, "/sys/fs/cgroup") {
		cgDir = filepath.Join("/sys/fs/cgroup", cgDir)
	}
	return os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o200)
}

// ---- process-set + signal helpers -----------------------------------------

// targetSet returns the target pid, plus its descendants for ScopeTree. The
// walk is a single best-effort pass (the SIGSTOP fallback's documented
// weakness); the cgroup path closes the fork-while-migrating gap by freezing
// on arrival.
func (e *linuxExecutor) targetSet(root int, scope response.Scope) []int {
	if scope != response.ScopeTree {
		return []int{root}
	}
	children := map[int][]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []int{root}
	}
	for _, ent := range entries {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		if ppid, ok := readPPID(pid); ok {
			children[ppid] = append(children[ppid], pid)
		}
	}
	seen := map[int]bool{root: true}
	out := []int{root}
	queue := []int{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range children[cur] {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
				queue = append(queue, c)
			}
		}
	}
	return out
}

// sigAll sends sig to every pid via a per-pid pidfd (reuse-safe for the act),
// returning those still present. Best-effort: a gone pid is skipped.
func (e *linuxExecutor) sigAll(pids []int, sig syscall.Signal) []int {
	done := make([]int, 0, len(pids))
	for _, pid := range pids {
		if err := sigPid(pid, sig); err == nil {
			done = append(done, pid)
		}
	}
	return done
}

func sigPid(pid int, sig syscall.Signal) error {
	fd, err := pidfdOpen(pid)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
	return pidfdSendSignal(fd, sig)
}

// ---- raw syscalls ----------------------------------------------------------

func pidfdOpen(pid int) (int, error) {
	r, _, errno := syscall.Syscall(sysPidfdOpen, uintptr(pid), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

func pidfdSendSignal(pidfd int, sig syscall.Signal) error {
	_, _, errno := syscall.Syscall6(sysPidfdSendSignal, uintptr(pidfd), uintptr(sig), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func renameat2(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) error {
	op, err := syscall.BytePtrFromString(oldpath)
	if err != nil {
		return err
	}
	np, err := syscall.BytePtrFromString(newpath)
	if err != nil {
		return err
	}
	// op/np are C strings from BytePtrFromString, kept inline in the Syscall6
	// call so the GC cannot move them out from under the uintptr conversion.
	_, _, errno := syscall.Syscall6(sysRenameat2, uintptr(olddirfd), uintptr(unsafe.Pointer(op)), uintptr(newdirfd), uintptr(unsafe.Pointer(np)), uintptr(flags), 0) //#nosec G103 -- audited raw renameat2 syscall
	if errno != 0 {
		return errno
	}
	return nil
}

// renameat2Fn is renameat2 behind a var so a test can force the EXDEV
// (cross-filesystem) branch of Quarantine deterministically, without needing a
// real second mount -- the neuter path then runs on any filesystem.
var renameat2Fn = renameat2

// quarantineSwapHook, when non-nil, runs after the fstat and after the pending
// manifest, just before the rename/neuter act. A test uses it to swap the
// directory entry mid-operation and prove the act binds to the fstat'd inode,
// never a re-resolved path (Q1).
var quarantineSwapHook func()

// neuterFd makes the inode behind an O_PATH fd inert: mode 0 and, where the
// filesystem and privilege allow, the immutable flag. It acts on the fd -- the
// inode we fstat'd -- never on a path an attacker could swap under us (Q1). An
// O_PATH fd can neither fchmod nor ioctl, so the same inode is reopened
// O_RDONLY through /proc/self/fd (that reopen names the identical inode by
// construction). It returns whether the immutable flag took, and a post-neuter
// fstat confirms the mode landed. tmpfs before 6.0 ignores the immutable flag,
// so false is recorded honestly rather than assumed.
func neuterFd(opathFd int) bool {
	rf, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", opathFd)) //nolint:gosec // our own fd, reopened by number
	if err != nil {
		return false
	}
	defer func() { _ = rf.Close() }()
	_ = rf.Chmod(0)
	immutable := chattrFd(int(rf.Fd()), true) == nil
	// Post-neuter fstat: confirm mode 0 actually landed (an exotic filesystem
	// may refuse it); the caller's manifest already holds the pre-neuter stat.
	var st syscall.Stat_t
	if syscall.Fstat(int(rf.Fd()), &st) == nil && st.Mode&0o7777 != 0 {
		immutable = false
	}
	return immutable
}

func clearImmutable(path string) error { return chattr(path, false) }

func chattr(path string, set bool) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
	return chattrFd(fd, set)
}

// chattrFd sets or clears FS_IMMUTABLE_FL on an open (readable) fd. The caller
// holds the fd, so the flag change lands on exactly that inode -- the fd
// discipline Q1 asks for applied to the immutable bit too.
func chattrFd(fd int, set bool) error {
	var flags int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), fsIocGetFlags, uintptr(unsafe.Pointer(&flags))); errno != 0 { //#nosec G103 -- audited FS_IOC_GETFLAGS ioctl
		return errno
	}
	if set {
		flags |= fsImmutableFL
	} else {
		flags &^= fsImmutableFL
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), fsIocSetFlags, uintptr(unsafe.Pointer(&flags))); errno != 0 { //#nosec G103 -- audited FS_IOC_SETFLAGS ioctl
		return errno
	}
	return nil
}

// ---- /proc readers ---------------------------------------------------------

// readExe and readCgroup are vars so a test can stage a trusted-path or
// protected-unit live identity against a self-owned pid without needing a real
// system daemon (which a non-root, contained test cannot spawn).
var readExe = func(pid int) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}

var readCgroup = func(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid)) //nolint:gosec // /proc by pid
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		// cgroup v2: "0::<path>".
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::"), nil
		}
	}
	return "", errors.New("no cgroup v2 line")
}

// readUID returns the real uid from /proc/<pid>/status (field 1 of the Uid:
// line), mirroring the real-user identity the decision layer's allowRoot rail
// uses. It is a var for the same test-seam reason as readExe.
var readUID = func(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)) //nolint:gosec // /proc by pid
	if err != nil {
		return -1, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				return strconv.Atoi(f[1])
			}
		}
	}
	return -1, errors.New("no Uid line in /proc status")
}

// cgroupProtectedUnit reports whether a cgroup v2 path is a protected system
// unit: pid 1's init.scope, or a .service/.scope whose unit name (sans suffix)
// is one of the built-in protected names (sshd.service, auditd.service, ...).
// It deliberately does NOT protect an arbitrary *.service: a reverse shell
// spawned inside a compromised service inherits that service's cgroup, so
// blanket service protection would re-open the very masquerade hole F2 closes.
func cgroupProtectedUnit(cg string) bool {
	if cg == "" {
		return false
	}
	base := filepath.Base(cg) // e.g. "sshd.service", "init.scope"
	if base == "init.scope" {
		return true
	}
	name := base
	for _, suf := range []string{".service", ".scope", ".slice"} {
		name = strings.TrimSuffix(name, suf)
	}
	return response.BuiltinDenyName(name)
}

// statFields returns the fields of /proc/<pid>/stat after the comm field,
// which can itself contain spaces and parentheses, so we split on the LAST
// ')'. Returned slice index 0 == field 3 (state).
func statFields(pid int) ([]string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)) //nolint:gosec // /proc by pid
	if err != nil {
		return nil, err
	}
	s := string(data)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 || rparen+2 > len(s) {
		return nil, errors.New("malformed stat")
	}
	return strings.Fields(s[rparen+2:]), nil
}

func readPPID(pid int) (int, bool) {
	fields, err := statFields(pid)
	if err != nil || len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1]) // field 4
	if err != nil {
		return 0, false
	}
	return ppid, true
}

// readStartTime converts /proc/<pid>/stat field 22 (ticks since boot) to an
// absolute time using the system boot time. It is a var so a test can force
// the read-failure branch of identify() (fail-closed) without a real /proc
// fault, which cannot be staged for a live, self-owned pid.
var readStartTime = func(pid int) (time.Time, error) {
	fields, err := statFields(pid)
	if err != nil {
		return time.Time{}, err
	}
	const startIdx = 22 - 3 // field 22, slice starts at field 3
	if len(fields) <= startIdx {
		return time.Time{}, errors.New("stat too short")
	}
	ticks, err := strconv.ParseInt(fields[startIdx], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	btime, err := bootTime()
	if err != nil {
		return time.Time{}, err
	}
	secs := ticks / userHZ
	nsec := (ticks % userHZ) * (int64(time.Second) / userHZ)
	return time.Unix(btime+secs, nsec).UTC(), nil
}

func bootTime() (int64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "btime ") {
			return strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
		}
	}
	return 0, errors.New("no btime in /proc/stat")
}

// ---- misc helpers ----------------------------------------------------------

func statToFileStat(st syscall.Stat_t) fileStat {
	// Nlink is uint32 on arm64 and uint64 on amd64; the conversion is needed
	// on arm64 (and a no-op the linter would otherwise flag on amd64).
	return fileStat{
		Dev: st.Dev, Ino: st.Ino, Mode: st.Mode,
		UID: st.Uid, GID: st.Gid, Size: st.Size,
		Nlink: uint64(st.Nlink), //nolint:unconvert // uint32 on arm64
		MTime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec).UTC().Format(time.RFC3339Nano),
	}
}

func sha256OfFd(opathFd int) (string, error) {
	// Re-open the same inode for reading via /proc/self/fd (an O_PATH fd is
	// not itself readable), so the hash is of exactly the inode we fstat'd.
	f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", opathFd)) //nolint:gosec // our own fd
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sha256OfPath(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // evidence hashing of a resolved exe path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func newHandleID() string {
	var b [12]byte
	ns := time.Now().UTC().UnixNano()
	for i := 7; i >= 0; i-- {
		b[i] = byte(ns)
		ns >>= 8
	}
	_, _ = rand.Read(b[8:])
	return hex.EncodeToString(b[:])
}
