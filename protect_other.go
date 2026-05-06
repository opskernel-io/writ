//go:build !linux

package writ

// trySetAppendOnly returns false on non-Linux platforms where FS_APPEND_FL
// is not available. Use chattr +a manually on Linux to harden the chain file.
func trySetAppendOnly(_ string) bool {
	return false
}
