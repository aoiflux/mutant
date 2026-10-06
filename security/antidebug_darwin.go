//go:build darwin
// +build darwin

package security

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	darwinDebugMethodPTraced    = "darwin:p_traced"
	darwinDebugMethodParentProc = "darwin:parent_debugger_process"
	darwinDebugMethodEnvMarkers = "darwin:debugger_environment"

	darwinSysctlCTLKern     = 1
	darwinSysctlKernProc    = 14
	darwinSysctlKernProcPID = 1

	darwinDYLDInsertLibsEnv = "DYLD_INSERT_LIBRARIES"
	darwinPsCommand         = "ps"
	darwinPgrepCommand      = "pgrep"
	darwinOtoolCommand      = "otool"
)

var (
	darwinDebuggerEnvVars = []string{
		"LLDB_DEBUGSERVER_PORT",
		"LLDB_MasterPort",
		"GDB_OPTS",
		"GDBHISTFILE",
		"XCODE_DEBUG_PORT",
		darwinDYLDInsertLibsEnv,
		"DYLD_ROOT_PATH",
		"XCODE_VERSION_ACTUAL",
		"XPC_DEBUG",
		"LLVM_DEBUG",
		"FRIDA_DEBUG",
	}

	darwinSuspiciousDYLDLibs = []string{"libgmalloc", "libc++abi", "libsystem_trace", "libsystem_sandbox"}
	darwinRunningDebuggers   = []string{"lldb", "gdb", "xcode", "Instruments", "Simulator", "frida-server", "idb"}
	darwinOtoolIndicators    = []string{"liblldb", "libgdb", "libdebug", "/tmp/", "/var/tmp/"}
)

// isDebuggerPresentDarwin performs multiple anti-debugging checks on macOS/Darwin
// Uses techniques employed by security vendors like Objective-See
func isDebuggerPresentDarwin() bool {
	detected, _ := detectDebuggerDetailsDarwin()
	return detected
}

func detectDebuggerDetailsDarwin() (bool, []string) {
	methods := make([]string, 0, 3)

	// Check 1: P_TRACED flag (ptrace-based debuggers like lldb, gdb)
	if isProcessBeingTraced() {
		methods = append(methods, darwinDebugMethodPTraced)
	}

	// Check 2: Check parent process for known debuggers
	if isParentDebuggerDarwin() {
		methods = append(methods, darwinDebugMethodParentProc)
	}

	// Check 3: Environment variables set by debugging tools
	if hasDebuggerEnvironmentMarkersDarwin() {
		methods = append(methods, darwinDebugMethodEnvMarkers)
	}

	return len(methods) > 0, methods
}

// isProcessBeingTraced checks if the process is being traced via P_TRACED flag
func isProcessBeingTraced() bool {
	// Define kinfo_proc structure (simplified, only the parts we need)
	// The P_TRACED flag is at a specific offset in the kp_proc.p_flag field
	type kinfoProc struct {
		_    [40]byte  // padding to kp_proc
		_    [4]byte   // kp_proc.p_pid
		_    [296]byte // padding to kp_proc.p_flag
		Flag uint32    // kp_proc.p_flag
		_    [624]byte // rest of structure
	}

	const P_TRACED = 0x00000800 // Process is being traced

	// sysctl MIB for querying process info
	// CTL_KERN.KERN_PROC.KERN_PROC_PID.<pid>
	mib := []int32{darwinSysctlCTLKern, darwinSysctlKernProc, darwinSysctlKernProcPID, int32(os.Getpid()), int32(unsafe.Sizeof(kinfoProc{})), 1}

	var info kinfoProc
	size := uintptr(unsafe.Sizeof(info))

	_, _, err := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&size)),
		0,
		0,
	)

	if err != 0 {
		return false
	}

	// Check if P_TRACED flag is set
	return (info.Flag & P_TRACED) != 0
}

// isParentDebuggerDarwin checks whether the parent process is one of the
// debuggers in darwinDebuggerProcessNames, by the name of its executable.
//
// macOS has no /proc, so the parent's name comes from ps, and the name is
// compared exactly rather than searched for inside what ps printed. Searching
// matched far more than it meant to even on a bare name: the list holds "trace",
// which matched ltrace, pytrace and dtrace, and "heap", which matched
// heaptrack, so an ordinary parent was reported as a debugger -- and in secure
// mode that ends the run (M26-TMP-019). `ps -o comm=` on this platform is
// documented to print the executable's path, which if it holds makes the same
// list match every tool under /Applications/Xcode.app through the entry
// "xcode"; taking the base name covers both readings and needs neither to be
// settled.
//
// A parent whose name cannot be read is not a debugger, for the same reason as
// on Linux: isTracedDarwin is the check that finds one actually attached, and
// this one should err towards silence.
func isParentDebuggerDarwin() bool {
	ppid := os.Getppid()

	cmd := exec.Command(darwinPsCommand, "-o", "comm=", "-p", strconv.Itoa(ppid))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	return debuggerProcessNameMatches(string(output), darwinDebuggerProcessNames)
}

// hasDebuggerEnvironmentMarkersDarwin checks for debugger environment markers on macOS
func hasDebuggerEnvironmentMarkersDarwin() bool {
	for _, envVar := range darwinDebuggerEnvVars {
		if _, exists := os.LookupEnv(envVar); exists {
			return true
		}
	}

	// Check for unusual DYLD settings which indicate debugging
	if dyldLibs, exists := os.LookupEnv(darwinDYLDInsertLibsEnv); exists {
		// Check if suspicious libraries are being injected
		for _, lib := range darwinSuspiciousDYLDLibs {
			if strings.Contains(dyldLibs, lib) {
				return true
			}
		}
	}

	return false
}

// hasDebuggerProcessRunningDarwin checks if known debuggers are running
func hasDebuggerProcessRunningDarwin() bool {
	for _, debugger := range darwinRunningDebuggers {
		cmd := exec.Command(darwinPgrepCommand, "-x", debugger)
		err := cmd.Run()
		if err == nil {
			return true
		}
	}

	return false
}

// hasInjectedCode detects code injection or unusual memory patterns
// Debuggers on macOS often inject code via DYLD or task ports
func hasInjectedCode() bool {
	// Check if we can access our own task port (sign of debugging)
	// This is a simplified check - in reality, task port access is restricted

	// Alternative: Check for unusual library loading
	// Check if standard system libraries are loaded from unusual paths
	cmd := exec.Command(darwinOtoolCommand, "-L", "/proc/self/exe")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := strings.ToLower(string(output))

		// Debuggers often load debugging libraries
		for _, indicator := range darwinOtoolIndicators {
			if strings.Contains(outputStr, indicator) {
				return true
			}
		}
	}

	return false
}
