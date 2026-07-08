//go:build linux
// +build linux

package security

import (
	"bytes"
	"os"
	"strconv"
	"strings"
)

const (
	linuxProcSelfStatusPath      = "/proc/self/status"
	linuxTracerPidPrefix         = "TracerPid:"
	linuxParentCmdlinePathPrefix = "/proc/"
	linuxParentCmdlinePathSuffix = "/cmdline"
	linuxNullByteTrimSet         = "\x00"
	linuxLDPreloadVar            = "LD_PRELOAD"
	linuxLDPreloadLengthLimit    = 50
	linuxForcedExitCode          = 1
)

var (
	linuxDebuggerPatterns = []string{
		"gdb", "lldb", "valgrind",
		"radare2", "ida", "ghidra", "angr", "frida",
		"rr", "pernosco",
	}

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

// isParentDebugger checks if the parent process is a known debugger
// Looks for gdb, lldb, valgrind, strace, ltrace, etc.
func isParentDebugger() bool {
	ppid := os.Getppid()

	// Try to read parent process cmdline
	cmdlinePath := linuxParentCmdlinePathPrefix + strconv.Itoa(ppid) + linuxParentCmdlinePathSuffix
	cmdlineData, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return false
	}

	// Parse cmdline (null-separated)
	cmdline := string(bytes.Trim(cmdlineData, linuxNullByteTrimSet))
	cmdline = strings.ToLower(cmdline)

	for _, pattern := range linuxDebuggerPatterns {
		if strings.Contains(cmdline, pattern) {
			return true
		}
	}

	return false
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
