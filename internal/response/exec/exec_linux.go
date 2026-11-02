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

// builtinDenyNames mirrors the decision layer's list for the executor-side
// live re-check (names drift, so this is belt and braces with the pid check).
var builtinDenyNames = map[string]bool{
	"systemd": true, "init": true, "sshd": true, "sshd-session": true,
	"auditd": true, "laurel": true, "systemd-journald": true,
	"dbus-daemon": true, "dbus-broker": true, "login": true, "agetty": true,
}

var builtinNeverTouchPrefixes = []string{
	"/nix/store", "/usr", "/bin", "/sbin", "/lib", "/lib64",
	"/etc", "/boot", "/proc", "/sys", "/run",
}

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
	exe, _ := readExe(p.PID)
	cg, _ := readCgroup(p.PID)

	// Liveness through the fd: signal 0 reports existence without sending.
	if err := pidfdSendSignal(pidfd, 0); err != nil {
		_ = syscall.Close(pidfd)
		if errors.Is(err, syscall.ESRCH) {
			return -1, Live{}, ErrGone
		}
		return -1, Live{}, fmt.Errorf("pidfd liveness: %w", err)
	}

	live := Live{PID: p.PID, StartTime: start, Exe: exe, CgroupPath: cg}

	// Live denylist re-check against what is true now, not what the log said.
	if base := filepath.Base(exe); builtinDenyNames[base] {
		_ = syscall.Close(pidfd)
		return -1, live, fmt.Errorf("%w: live exe %q is protected", ErrDenied, base)
	}

	// Identity proof.
	if startErr == nil {
		if !p.StartTime.IsZero() {
			if d := start.Sub(p.StartTime); d < -identityTick || d > identityTick {
				_ = syscall.Close(pidfd)
				return -1, live, fmt.Errorf("%w: start time %s != reference %s", ErrStaleTarget, start, p.StartTime)
			}
		} else if !p.EventTime.IsZero() {
			// Unknown start time (auditd/Laurel): a reuser was forked after the
			// event, so its start time exceeds the event time; refuse it.
			if start.After(p.EventTime.Add(e.cfg.SkewTolerance)) {
				_ = syscall.Close(pidfd)
				return -1, live, fmt.Errorf("%w: start time %s is after event %s + skew", ErrStaleTarget, start, p.EventTime)
			}
		}
	}
	return pidfd, live, nil
}

func (e *linuxExecutor) Verify(_ context.Context, p response.ProcessRef) (Live, error) {
	pidfd, live, err := e.identify(p)
	if pidfd >= 0 {
		_ = syscall.Close(pidfd)
	}
	return live, err
}

// ---- freeze / thaw ---------------------------------------------------------

// freezeUndo is serialised into Handle.Undo so Thaw can reverse exactly what
// Freeze did.
type freezeUndo struct {
	Method string         `json:"method"`           // cgroup | sigstop
	PIDs   []int          `json:"pids"`             // the stopped/migrated set
	Orig   map[int]string `json:"orig,omitempty"`   // pid -> original cgroup path (cgroup method)
	Cgroup string         `json:"cgroup,omitempty"` // the banken.quarantine child dir
}

func (e *linuxExecutor) Freeze(_ context.Context, p response.ProcessRef, scope response.Scope) (Handle, error) {
	pidfd, live, err := e.identify(p)
	if err != nil {
		return Handle{}, err
	}
	defer func() { _ = syscall.Close(pidfd) }()

	id := newHandleID()
	pids := e.targetSet(p.PID, scope)

	if !e.cfg.Enforce {
		e.logf("response/exec: %s would freeze %s pid %d (%s), %d task(s)", e.gate(), scope, p.PID, live.Exe, len(pids))
		return Handle{ID: id, Kind: response.ActionFreeze, PID: p.PID, DryRun: true, Method: "dry-run"}, nil
	}

	// Real enforcement. Prefer the cgroup v2 freezer; fall back to SIGSTOP.
	if cgDir, orig, ok := e.cgroupFreeze(id, pids); ok {
		undo, _ := json.Marshal(freezeUndo{Method: "cgroup", PIDs: pids, Orig: orig, Cgroup: cgDir})
		e.logf("response/exec: %s froze %d task(s) via cgroup %s", e.gate(), len(pids), cgDir)
		return Handle{ID: id, Kind: response.ActionFreeze, PID: p.PID, Method: "cgroup", Undo: string(undo)}, nil
	}
	// SIGSTOP fallback (weaker: a child forked between the walk and the stop
	// can escape, and a watchdog SIGCONT can resume it -- recorded as such).
	stopped := e.sigAll(pids, syscall.SIGSTOP)
	undo, _ := json.Marshal(freezeUndo{Method: "sigstop", PIDs: stopped})
	e.logf("response/exec: %s froze %d task(s) via SIGSTOP (no cgroup v2 freezer)", e.gate(), len(stopped))
	return Handle{ID: id, Kind: response.ActionFreeze, PID: p.PID, Method: "sigstop", Undo: string(undo)}, nil
}

func (e *linuxExecutor) Thaw(_ context.Context, h Handle) error {
	if h.DryRun {
		e.logf("response/exec: %s would thaw %s", e.gate(), h.ID)
		return nil
	}
	var u freezeUndo
	if h.Undo != "" {
		_ = json.Unmarshal([]byte(h.Undo), &u)
	}
	switch u.Method {
	case "cgroup":
		// Move each pid back to its original cgroup first, so a thawed process
		// never runs for an instant in the quarantine cgroup, then remove it.
		for _, pid := range u.PIDs {
			if orig := u.Orig[pid]; orig != "" {
				_ = writeCgroupProcs(orig, pid)
			}
		}
		if u.Cgroup != "" {
			_ = os.WriteFile(filepath.Join(u.Cgroup, "cgroup.freeze"), []byte("0"), 0o200)
			_ = os.Remove(u.Cgroup)
		}
		return nil
	case "sigstop":
		for _, pid := range u.PIDs {
			_ = sigPid(pid, syscall.SIGCONT)
		}
		return nil
	default:
		return fmt.Errorf("thaw: unknown undo method %q", u.Method)
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
		return Handle{ID: id, Kind: response.ActionKill, PID: p.PID, DryRun: true, Method: "dry-run"}, nil
	}

	if scope == response.ScopeProcess {
		if err := pidfdSendSignal(pidfd, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return Handle{}, fmt.Errorf("pidfd_send_signal(SIGKILL): %w", err)
		}
		e.logf("response/exec: %s killed pid %d via pidfd", e.gate(), p.PID)
		return Handle{ID: id, Kind: response.ActionKill, PID: p.PID, Method: "pidfd", Note: "no undo"}, nil
	}

	// Tree kill: move into a frozen cgroup then cgroup.kill (atomic), falling
	// back to per-pid pidfd SIGKILL over the frozen set.
	if cgDir, _, ok := e.cgroupFreeze(id, pids); ok {
		method := "cgroup-kill"
		if err := os.WriteFile(filepath.Join(cgDir, "cgroup.kill"), []byte("1"), 0o200); err != nil {
			method = "pidfd-tree"
			e.sigAll(pids, syscall.SIGKILL)
		}
		_ = os.Remove(cgDir)
		e.logf("response/exec: %s killed %d task(s) via %s", e.gate(), len(pids), method)
		return Handle{ID: id, Kind: response.ActionKill, PID: p.PID, Method: method, Note: "no undo"}, nil
	}
	e.sigAll(pids, syscall.SIGKILL)
	e.logf("response/exec: %s killed %d task(s) via per-pid pidfd (no cgroup)", e.gate(), len(pids))
	return Handle{ID: id, Kind: response.ActionKill, PID: p.PID, Method: "pidfd-tree", Note: "no undo"}, nil
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
	if pfx, bad := underNeverTouch(path); bad {
		return Handle{}, fmt.Errorf("%w: %q under never-touch %q", ErrDenied, path, pfx)
	}
	if !underAllowPaths(e.cfg.QuarantineAllowPaths, path) {
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

func (e *linuxExecutor) Collect(_ context.Context, p response.ProcessRef) (Handle, error) {
	id := newHandleID()
	if !e.cfg.Enforce {
		e.logf("response/exec: %s would collect evidence for pid %d (%s)", e.gate(), p.PID, p.Image)
		return Handle{ID: id, Kind: response.ActionCollect, PID: p.PID, DryRun: true, Method: "dry-run"}, nil
	}
	dir := filepath.Join(e.cfg.EvidenceDir, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Handle{}, fmt.Errorf("collect mkdir: %w", err)
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
	exe, _ := readExe(p.PID)
	sum := ""
	if exe != "" {
		if h, herr := sha256OfPath(exe); herr == nil {
			sum = h
		}
	}
	man := map[string]any{"id": id, "pid": p.PID, "exe": exe, "sha256": sum, "time": time.Now().UTC()}
	buf, _ := json.MarshalIndent(man, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), buf, 0o600)
	e.logf("response/exec: %s collected evidence for pid %d into %s", e.gate(), p.PID, dir)
	return Handle{ID: id, Kind: response.ActionCollect, PID: p.PID, Method: "snapshot", Undo: dir}, nil
}

// ---- cgroup helpers --------------------------------------------------------

// cgroupFreeze creates a child cgroup, freezes it, and migrates the pids into
// it (a task migrated into a frozen cgroup is frozen on arrival). It returns
// the cgroup dir, each pid's original cgroup path, and ok=false if the v2
// freezer is unavailable or not writable (the caller then falls back).
func (e *linuxExecutor) cgroupFreeze(id string, pids []int) (string, map[int]string, bool) {
	root := e.cfg.CgroupRoot
	if _, err := os.Stat(filepath.Dir(root)); err != nil {
		return "", nil, false
	}
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", nil, false
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.freeze"), []byte("1"), 0o200); err != nil {
		_ = os.Remove(dir)
		return "", nil, false
	}
	orig := make(map[int]string, len(pids))
	for _, pid := range pids {
		if cg, err := readCgroup(pid); err == nil {
			orig[pid] = cg
		}
		_ = writeCgroupProcs(dir, pid)
	}
	return dir, orig, true
}

func writeCgroupProcs(cgDir string, pid int) error {
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

func readExe(pid int) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}

func readCgroup(pid int) (string, error) {
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
// absolute time using the system boot time.
func readStartTime(pid int) (time.Time, error) {
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

func underNeverTouch(path string) (string, bool) {
	clean := filepath.Clean(path)
	for _, pfx := range builtinNeverTouchPrefixes {
		if clean == pfx || strings.HasPrefix(clean, pfx+"/") {
			return pfx, true
		}
	}
	return "", false
}

func underAllowPaths(allow []string, path string) bool {
	clean := filepath.Clean(path)
	for _, a := range allow {
		a = filepath.Clean(a)
		if clean == a || strings.HasPrefix(clean, a+"/") {
			return true
		}
	}
	return false
}
