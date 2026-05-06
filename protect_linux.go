//go:build linux

package writ

import (
	"os"
	"syscall"
	"unsafe" //#nosec G103 -- ioctl for FS_APPEND_FL; unsafe.Pointer is the only available interface
)

// FS ioctl constants for 64-bit Linux (_IOR/'f'/1/sizeof(long) and _IOW/'f'/2/sizeof(long)).
const (
	_fsIOCGetFlags = uintptr(0x80086601)
	_fsIOCSetFlags = uintptr(0x40086602)
	_fsAppendFL    = int64(0x00000020)
)

// trySetAppendOnly attempts to set the FS_APPEND_FL attribute (chattr +a) on
// the file at path. Returns true if the flag was already set or successfully
// applied. Returns false on unsupported filesystems or insufficient privilege.
func trySetAppendOnly(path string) bool {
	f, err := os.Open(path) //#nosec G304 -- construction-time path
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	var flags int64
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), _fsIOCGetFlags, uintptr(unsafe.Pointer(&flags))); errno != 0 { //#nosec G103
		return false
	}
	if flags&_fsAppendFL != 0 {
		return true
	}
	flags |= _fsAppendFL
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), _fsIOCSetFlags, uintptr(unsafe.Pointer(&flags))) //#nosec G103
	return errno == 0
}
