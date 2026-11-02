//go:build linux

package exec

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	pidfd, live, err := e.identify(p)
	if err != nil {
		return Handle{}, err
	}
	defer func() { _ = syscall.Close(pidfd) }()

	pids := e.targetSet(p.PID, scope)

	if !e.cfg.Enforce {
		e.logf("response/exec: %s would freeze %s pid %d (%s), %d task(s)", e.gate(), scope, p.PID, live.Exe, len(pids))
		return Handle{ID: newHandleID(), Kind: response.ActionFreeze, PID: p.PID, Exe: live.Exe, StartTime: live.StartTime, DryRun: true, Method: "dry-run"}, nil
	}

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
	pidfd, live, err := e.identify(p)
	if err != nil {
		return Handle{}, err
	}
	defer func() { _ = syscall.Close(pidfd) }()

	id := newHandleID()
	pids := e.targetSet(p.PID, scope)

	if !e.cfg.Enforce {
		e.logf("response/exec: %s would kill %s pid %d (%s), %d task(s)", e.gate(), scope, p.PID, live.Exe, len(pids))
		return Handle{ID: id, Kind: response.ActionKill, PID: p.PID, Exe: live.Exe, StartTime: live.StartTime, DryRun: true, Method: "dry-run"}, nil
	}

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

type quarantineManifest struct {
	ID        string    `json:"id"`
	OrigPath  string    `json:"origPath"`
	Method    string    `json:"method"` // rename | neuter
	Stat      fileStat  `json:"stat"`
	SHA256    string    `json:"sha256"`
	Immutable bool      `json:"immutable"`
	Time      time.Time `json:"time"`
}

func (e *linuxExecutor) Quarantine(_ context.Context, f response.FileRef) (Handle, error) {
	path := filepath.Clean(f.Path)
	if pfx, bad := response.UnderNeverTouch(path); bad {
		return Handle{}, fmt.Errorf("%w: %q under never-touch %q", ErrDenied, path, pfx)
	}
	if !response.UnderAllowPaths(e.cfg.QuarantineAllowPaths, path) {
		return Handle{}, fmt.Errorf("%w: %q not under quarantine allowPaths", ErrDenied, path)
	}

	// Open the path without following symlinks and confirm it is a regular
	// file; act on the fd's inode, never a re-resolved path.
	fd, err := syscall.Open(path, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Handle{}, fmt.Errorf("open %q: %w", path, err)
	}
	defer func() { _ = syscall.Close(fd) }()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return Handle{}, fmt.Errorf("fstat %q: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return Handle{}, fmt.Errorf("%w: %q is not a regular file", ErrStaleTarget, path)
	}
	sum, _ := sha256OfFd(fd)
	fstat := statToFileStat(st)

	id := newHandleID()
	if !e.cfg.Enforce {
		e.logf("response/exec: %s would quarantine %q (ino %d, sha256 %s)", e.gate(), path, st.Ino, sum)
		return Handle{ID: id, Kind: response.ActionQuarantine, DryRun: true, Method: "dry-run", Note: "sha256:" + sum}, nil
	}

	entryDir := filepath.Join(e.cfg.QuarantineDir, id)
	if err := os.MkdirAll(entryDir, 0o700); err != nil {
		return Handle{}, fmt.Errorf("quarantine mkdir: %w", err)
	}
	dest := filepath.Join(entryDir, "file")
	man := quarantineManifest{ID: id, OrigPath: path, Stat: fstat, SHA256: sum, Time: time.Now().UTC()}

	err = renameat2(atFDCWD, path, atFDCWD, dest, renameNoReplace)
	switch {
	case err == nil:
		// Post-rename inode recheck: if the entry at the old path was swapped
		// between our fstat and the rename, we moved the wrong file -- put it
		// straight back and refuse.
		var dst syscall.Stat_t
		if serr := syscall.Lstat(dest, &dst); serr == nil && (dst.Dev != st.Dev || dst.Ino != st.Ino) {
			_ = renameat2(atFDCWD, dest, atFDCWD, path, 0)
			_ = os.RemoveAll(entryDir)
			return Handle{}, fmt.Errorf("%w: inode changed under the rename", ErrStaleTarget)
		}
		man.Method = "rename"
	case errors.Is(err, syscall.EXDEV):
		// Cross-filesystem: neuter in place rather than copy.
		man.Method = "neuter"
		_ = os.Chmod(path, 0)
		man.Immutable = setImmutable(path)
	default:
		_ = os.RemoveAll(entryDir)
		return Handle{}, fmt.Errorf("renameat2 %q: %w", path, err)
	}

	if err := writeManifest(entryDir, man); err != nil {
		e.logf("response/exec: WARNING manifest write failed for %s: %v", id, err)
	}
	e.logf("response/exec: %s quarantined %q via %s (handle %s)", e.gate(), path, man.Method, id)
	return Handle{ID: id, Kind: response.ActionQuarantine, Method: man.Method, Undo: entryDir, Note: "sha256:" + sum}, nil
}

func (e *linuxExecutor) Restore(_ context.Context, h Handle) error {
	if h.DryRun {
		e.logf("response/exec: %s would restore %s", e.gate(), h.ID)
		return nil
	}
	entryDir := h.Undo
	man, err := readManifest(entryDir)
	if err != nil {
		return fmt.Errorf("restore: read manifest: %w", err)
	}
	switch man.Method {
	case "rename":
		dest := filepath.Join(entryDir, "file")
		var dst syscall.Stat_t
		if err := syscall.Lstat(dest, &dst); err != nil {
			return fmt.Errorf("restore: stat quarantined file: %w", err)
		}
		if dst.Ino != man.Stat.Ino {
			return errors.New("restore: quarantined inode no longer matches manifest")
		}
		if err := renameat2(atFDCWD, dest, atFDCWD, man.OrigPath, renameNoReplace); err != nil {
			return fmt.Errorf("restore: rename back: %w", err)
		}
		_ = os.RemoveAll(entryDir)
		return nil
	case "neuter":
		if man.Immutable {
			_ = clearImmutable(man.OrigPath)
		}
		if err := os.Chmod(man.OrigPath, os.FileMode(man.Stat.Mode&0o7777)); err != nil {
			return fmt.Errorf("restore: chmod: %w", err)
		}
		_ = os.RemoveAll(entryDir)
		return nil
	default:
		return fmt.Errorf("restore: unknown method %q", man.Method)
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
	if !e.cfg.Enforce {
		e.logf("response/exec: %s would collect evidence for pid %d (%s)", e.gate(), p.PID, live.Exe)
		return Handle{ID: id, Kind: response.ActionCollect, PID: p.PID, Exe: live.Exe, StartTime: live.StartTime, DryRun: true, Method: "dry-run"}, nil
	}
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
// for the store-backed actions. Freeze and evidence are scanned here; the
// quarantine store joins in build item 5. Kill keeps no store, so a replayed
// kill finds the pid gone or a reuser, both handled by identify().
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
	return Handle{}, false, nil
}

// Recover is the drain's startup repair pass over the freeze store and the
// cgroup root (docs section 2.4 step 4). It finalises a pending freeze manifest
// whose pids did reach the cgroup, rolls back one whose act never landed, and
// removes an empty cgroup dir that no live manifest owns (the second half of
// F8: a kill cgroup left populated at the bound, later emptied). It never
// touches a finalised, untombstoned entry.
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

func setImmutable(path string) bool    { return chattr(path, true) == nil }
func clearImmutable(path string) error { return chattr(path, false) }

func chattr(path string, set bool) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
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

func writeManifest(dir string, m quarantineManifest) error {
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), buf, 0o600)
}

func readManifest(dir string) (quarantineManifest, error) {
	var m quarantineManifest
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json")) //nolint:gosec // our own quarantine dir
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(data, &m)
	return m, err
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
