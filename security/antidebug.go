package security

import (
	"runtime"
	"strings"
)

// IsDebuggerPresent checks if a debugger is currently attached to the process.
// It uses multiple platform-specific detection techniques:
//
// Windows:
//   - IsDebuggerPresent API (checks PEB BeingDebugged flag)
//   - CheckRemoteDebuggerPresent API
//   - NtQueryInformationProcess with ProcessDebugPort
//   - NtQueryInformationProcess with ProcessDebugObjectHandle
//   - OutputDebugString timing test
//   - Parent process name analysis
//   - Common debugger DLL detection
//
// Linux:
//   - TracerPid from /proc/self/status
//   - ptrace self-attachment test
//   - Parent process name analysis
//   - LD_PRELOAD detection
//
// macOS:
//   - sysctl P_TRACED flag
//   - LLDB environment variables
//   - DYLD_INSERT_LIBRARIES detection
//
// Returns true if any debugger detection method triggers.
func IsDebuggerPresent() bool {
	detected, methods := DetectDebuggerDetails()
	securityDevLogf("debugger detected=%t methods=%s", detected, strings.Join(methods, ","))
	return detected
}

// DetectDebuggerDetails returns debugger detection status plus triggered methods.
func DetectDebuggerDetails() (bool, []string) {
	switch runtime.GOOS {
	case "windows":
		return detectDebuggerDetailsWindows()
	case "linux":
		return detectDebuggerDetailsLinux()
	case "darwin":
		return detectDebuggerDetailsDarwin()
	default:
		return false, nil
	}
}

// DebuggerTamperDetail reports which debugger checks fired, for a run that is
// stopping because of one.
//
// It probes again rather than reusing the gate's answer. Unlike the sandbox
// detector, debugger detection is deliberately not cached: a process that
// started clean can have a debugger attached to it later, so a cached "no"
// would be wrong for the rest of the run. The gate's answer is what terminates;
// this is a second reading taken to describe it, and it reports nothing if the
// debugger detached in between. (M-7)
func DebuggerTamperDetail() TamperDetail {
	detected, methods := DetectDebuggerDetails()
	if !detected {
		return TamperDetail{Detector: "debugger"}
	}

	return TamperDetail{Detector: "debugger", Signals: methods}
}
