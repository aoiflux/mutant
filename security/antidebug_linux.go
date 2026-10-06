//go:build linux
// +build linux

package security

import (
	"os"
	"strconv"
	"strings"
)

const (
	linuxProcSelfStatusPath   = "/proc/self/status"
	linuxTracerPidPrefix      = "TracerPid:"
	linuxParentCommPathPrefix = "/proc/"
	linuxParentCommPathSuffix = "/comm"
	linuxLDPreloadVar         = "LD_PRELOAD"
	linuxLDPreloadLengthLimit = 50
	linuxForcedExitCode       = 1
)

var (
	linuxDebuggerEnvVars = []string{
		"GDB_OPTS",
		"GDBHISTFILE",
		"LLDB_DEBUGSERVER",
		"LLDB_HIST_FILE",
		"VALGRIND_LIB",
		"VALGRIND_PID",
		linuxLDPreloadVar,
		"LD_AUDIT",
		"SYSTEMTAP_STAPRUN",
		"FRIDA_SERVER_PORT",
	}
)

// isDebuggerPresentLinux performs multiple anti-debugging checks on Linux
// using techniques employed by major security firms and tech companies
func isDebuggerPresentLinux() bool {
	detected, _ := detectDebuggerDetailsLinux()
	return detected
}

func detectDebuggerDetailsLinux() (bool, []string) {
	methods := make([]string, 0, 3)

	// Check 1: TracerPid detection (ptrace-based debuggers)
	if isTracingDetected() {
		methods = append(methods, "linux:tracer_pid")
	}

	// Check 2: Debugger process detection via /proc/cmdline of parent
	if isParentDebugger() {
		methods = append(methods, "linux:parent_debugger_process")
	}

	// Check 3: GDB specific markers in environment
	if hasDebuggerEnvironmentMarkers() {
		methods = append(methods, "linux:debugger_environment")
	}

	return len(methods) > 0, methods
}

// isTracingDetected checks if the process is being traced via ptrace
// Used by debuggers like gdb, lldb, and system tracing tools
func isTracingDetected() bool {
	data, err := os.ReadFile(linuxProcSelfStatusPath)
	if err != nil {
		return false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, linuxTracerPidPrefix) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pid, err := strconv.Atoi(fields[1])
				if err == nil && pid != 0 {
					return true
				}
			}
			break
		}
	}

	return false
}

// isParentDebugger checks whether the parent process is one of the debuggers
// in linuxDebuggerProcessNames, by the name of its executable and nothing else.
//
// /proc/<ppid>/comm is the kernel's own name for the parent: no path, no
// arguments, and at most fifteen characters, which every name in the list fits
// inside. Reading /proc/<ppid>/cmdline instead and searching the whole of it is
// what made an ordinary argument look like a debugger, and in secure mode that
// ends the run (M26-TMP-002).
//
// A parent whose comm cannot be read is not a debugger. The file is gone for a
// reaped parent and unreadable under some container policies, and this is the
// weaker of the two checks the Linux detector makes -- isTracingDetected is the
// one that finds a debugger actually attached -- so it fails towards silence
// rather than terminating a run over a file it could not open.
func isParentDebugger() bool {
	ppid := os.Getppid()

	commPath := linuxParentCommPathPrefix + strconv.Itoa(ppid) + linuxParentCommPathSuffix
	commData, err := os.ReadFile(commPath)
	if err != nil {
		return false
	}

	return debuggerProcessNameMatches(string(commData), linuxDebuggerProcessNames)
}

// hasDebuggerEnvironmentMarkers checks for environment variables set by debuggers
// GDB, LLDB, and other debuggers typically set specific environment variables
func hasDebuggerEnvironmentMarkers() bool {
	for _, envVar := range linuxDebuggerEnvVars {
		if _, exists := os.LookupEnv(envVar); exists {
			return true
		}
	}

	// Check for excessive LD_PRELOAD which is often used in debuggers
	if preload, exists := os.LookupEnv(linuxLDPreloadVar); exists && len(preload) > linuxLDPreloadLengthLimit {
		return true
	}

	return false
}

// DetectDebuggerAndTerminate is a helper that detects debuggers and terminates
// This should be called early in the program execution
func DetectDebuggerAndTerminate() error {
	if isDebuggerPresentLinux() {
		// Take evasive action: exit ungracefully
		os.Exit(linuxForcedExitCode)
	}
	return nil
}
