//go:build linux && !amd64

package exec

// renameat2 on the generic Linux syscall table (arm64, riscv64, loong64,
// ...). These 64-bit arches share number 276; x86_64 is the exception (316,
// in sysnum_amd64.go). 32-bit arches are not a banken target.
const sysRenameat2 = 276
