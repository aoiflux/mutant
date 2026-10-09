//go:build !windows

package builtin

// sfProcessEnvUnreadable has nothing to add off Windows. The Linux reader opens
// /proc/<pid>/environ and returns the open error, so an unreadable environment
// already arrives as an error rather than as an empty answer, and an empty file
// there means the process really was started with no environment -- which
// execve permits and which this must therefore be able to report.
func sfProcessEnvUnreadable(_ int) error { return nil }
