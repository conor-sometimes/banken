//go:build linux

package view

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/conor-sometimes/banken/internal/response"
)

// FS_IMMUTABLE_FL and the FS_IOC_{GET,SET}FLAGS ioctls, matching the executor's
// own constants (exec_linux.go). GETFLAGS is the only one the read-only view
// ever issues.
const (
	fsImmutableFL = 0x00000010
	fsIocGetFlags = 0x80086601
)

// SysProber gathers live facts from the real system for list/explain on a host.
// It is read-only: it stats inodes, reads cgroup.events/cgroup.procs and the
// boot id, and re-hashes the stored file, but opens nothing writable and
// signals nothing. QuarantineDir is the absolute store dir it joins with a
// handle id to find the stored file for a rename re-hash; MaxFileBytes bounds
// that hash exactly as the executor's write did (Q6), so a 1 TiB sparse file in
// the store cannot stall list.
type SysProber struct {
	QuarantineDir string
	MaxFileBytes  int64
}

// NewSysProber builds the live prober for a host. maxFileBytes <= 0 falls back
// to the executor's 256 MiB default so a hand-built prober caps the same way.
func NewSysProber(quarantineDir string, maxFileBytes int64) SysProber {
	if maxFileBytes <= 0 {
		maxFileBytes = 268435456
	}
	return SysProber{QuarantineDir: quarantineDir, MaxFileBytes: maxFileBytes}
}

// Probe observes the live system for one entry. Every failure degrades to a
// zero fact (not observed / gone), never a panic: a race that removes the
// target between the ledger read and the stat reads as a loss, which is the
// honest state.
func (p SysProber) Probe(e Entry) LiveFacts {
	f := LiveFacts{Known: true, BootID: currentBootID()}
	switch e.Kind {
	case response.ActionFreeze:
		p.probeFreeze(e.Freeze, &f)
	case response.ActionQuarantine:
		p.probeQuarantine(e, &f)
	}
	return f
}

func (p SysProber) probeFreeze(m *FreezeManifest, f *LiveFacts) {
	if m == nil || m.Cgroup == "" {
		return
	}
	if _, err := os.Stat(m.Cgroup); err != nil {
		return
	}
	f.CgroupExists = true
	f.CgroupFrozen = cgroupFrozen(m.Cgroup)
	f.CgroupPIDs = readCgroupProcs(m.Cgroup)
}

func (p SysProber) probeQuarantine(e Entry, f *LiveFacts) {
	m := e.Quar
	if m == nil {
		return
	}
	switch m.Method {
	case methodRename:
		stored := filepath.Join(p.QuarantineDir, e.ID, "file")
		p.probeInode(stored, f, true)
	case methodNeuter:
		p.probeInode(m.OrigPath, f, false)
	}
}

// probeInode opens a path O_RDONLY|O_NOFOLLOW (the stored file is mode 0000 but
// root can still open it) and reads its (dev, ino), mode, immutable bit, and -
// for the rename store - a bounded sha256. A failure to open leaves
// TargetExists false (the inode-replaced / lost branch).
func (p SysProber) probeInode(path string, f *LiveFacts, hash bool) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer func() { _ = syscall.Close(fd) }()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return
	}
	f.TargetExists = true
	f.Dev = st.Dev
	f.Ino = st.Ino
	f.Mode = st.Mode & 0o7777
	f.Immutable = fdImmutable(fd)
	if hash {
		f.SHA256 = sha256OfFd(fd, p.MaxFileBytes)
	}
}

// fdImmutable reports whether FS_IMMUTABLE_FL is set on an open fd. A
// filesystem that does not support the ioctl reads as not immutable.
func fdImmutable(fd int) bool {
	var flags int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), fsIocGetFlags, uintptr(unsafe.Pointer(&flags))); errno != 0 { //#nosec G103 -- audited read-only FS_IOC_GETFLAGS ioctl
		return false
	}
	return flags&fsImmutableFL != 0
}

// sha256OfFd hashes up to maxBytes of an open fd. Over the cap it returns the
// unhashed sentinel, so list classifies "held unhashed" exactly as the store
// recorded it (Q6). A read error yields "" (list then shows CHANGED, the safe
// surprise). The fd offset is reset so hashing never disturbs a later read.
func sha256OfFd(fd int, maxBytes int64) string {
	size, err := syscall.Seek(fd, 0, io.SeekEnd)
	if err == nil && maxBytes > 0 && size > maxBytes {
		return unhashedSentinel + ": " + strconv.FormatInt(size, 10)
	}
	if _, err := syscall.Seek(fd, 0, io.SeekStart); err != nil {
		return ""
	}
	h := sha256.New()
	buf := make([]byte, 1<<16)
	var read int64
	for {
		n, rerr := syscall.Read(fd, buf)
		if n > 0 {
			read += int64(n)
			if maxBytes > 0 && read > maxBytes {
				return unhashedSentinel + ": " + strconv.FormatInt(read, 10)
			}
			h.Write(buf[:n])
		}
		if rerr != nil || n == 0 {
			if rerr != nil {
				return ""
			}
			break
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// cgroupFrozen reads cgroup.events and reports whether it says "frozen 1".
func cgroupFrozen(cgDir string) bool {
	data, err := os.ReadFile(filepath.Join(cgDir, "cgroup.events")) //nolint:gosec // read-only, our own cgroup dir
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "frozen 1" {
			return true
		}
	}
	return false
}

// readCgroupProcs returns the pids in a cgroup's cgroup.procs, or nil.
func readCgroupProcs(cgDir string) []int {
	data, err := os.ReadFile(filepath.Join(cgDir, "cgroup.procs")) //nolint:gosec // read-only, our own cgroup dir
	if err != nil {
		return nil
	}
	var pids []int
	for _, field := range strings.Fields(string(data)) {
		if pid, perr := strconv.Atoi(field); perr == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// currentBootID reads the kernel boot id for the freeze reboot check.
func currentBootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
