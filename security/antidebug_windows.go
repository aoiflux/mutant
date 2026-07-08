//go:build windows
// +build windows

package security

import (
	"syscall"
	"unsafe"
)

const (
	debugMethodIsDebuggerPresent    = "windows:is_debugger_present"
	debugMethodCheckRemoteDebugger  = "windows:check_remote_debugger_present"
	debugMethodProcessDebugPort     = "windows:process_debug_port"
	debugMethodProcessDebugObject   = "windows:process_debug_object_handle"
	debugMethodSystemDebugControl   = "windows:system_debug_control_query_version"
	debugMethodOutputDebugTiming    = "windows:output_debug_string_timing"
	debugMethodDebuggerDLLLoaded    = "windows:debugger_dll_loaded"
	outputDebugTimingThresholdTicks = 10
	weakSignalTriggerThreshold      = 2
	outputDebugProbeMessage         = "DEBUG_CHECK"
)

var debuggerDLLs = []string{"dbghelp.dll", "msvcr120d.dll", "msvcd120d.dll", "vccorlib120d.dll"}

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	ntdll                          = syscall.NewLazyDLL("ntdll.dll")
	procIsDebuggerPresent          = kernel32.NewProc("IsDebuggerPresent")
	procGetModuleHandle            = kernel32.NewProc("GetModuleHandleW")
	procGetProcAddress             = kernel32.NewProc("GetProcAddress")
	procOutputDebugString          = kernel32.NewProc("OutputDebugStringW")
	procGetCurrentProcess          = kernel32.NewProc("GetCurrentProcess")
	procNtQueryInformationProcess  = ntdll.NewProc("NtQueryInformationProcess")
	procGetParentProcess           = kernel32.NewProc("CreateToolhelp32Snapshot")
	procCheckRemoteDebuggerPresent = kernel32.NewProc("CheckRemoteDebuggerPresent")
	procCheckSystemDebugControl    = ntdll.NewProc("NtSystemDebugControl")
	procGetTickCount               = kernel32.NewProc("GetTickCount")
)

// ProcessDebugPort is used with NtQueryInformationProcess
const (
	ProcessDebugPort         = 7
	ProcessDebugObjectHandle = 30
	statusSuccess            = 0
	statusDebuggerInactive   = 0xC0000354
	sysDbgQueryVersion       = 7
)

type dbgkdGetVersion64 struct {
	MajorVersion       uint16
	MinorVersion       uint16
	ProtocolVersion    byte
	KdSecondaryVersion byte
	Flags              uint16
	MachineType        uint16
	MaxPacketType      byte
	MaxStateChange     byte
	MaxManipulate      byte
	Simulation         byte
	Unused             [1]uint16
	KernBase           uint64
	PsLoadedModuleList uint64
	DebuggerDataList   uint64
}

// isDebuggerPresentWindows performs multiple debugger detection techniques.
// Uses a combination of methods inspired by Kaspersky, Symantec, and other security vendors.
func isDebuggerPresentWindows() bool {
	detected, _ := detectDebuggerDetailsWindows()
	return detected
}

func detectDebuggerDetailsWindows() (bool, []string) {
	methods := make([]string, 0, 7)

	// High-confidence checks: a single hit is enough.
	if checkBeingDebugged() {
		methods = append(methods, debugMethodIsDebuggerPresent)
	}
	if checkRemoteDebugger() {
		methods = append(methods, debugMethodCheckRemoteDebugger)
	}
	if checkProcessDebugPort() {
		methods = append(methods, debugMethodProcessDebugPort)
	}
	if checkProcessDebugObjectHandle() {
		methods = append(methods, debugMethodProcessDebugObject)
	}
	if checkSystemDebugControlQueryVersion() {
		methods = append(methods, debugMethodSystemDebugControl)
	}
	if len(methods) > 0 {
		return true, methods
	}

	// Lower-confidence heuristics: require multiple weak signals.
	weakHits := 0
	if checkOutputDebugStringTest() {
		weakHits++
		methods = append(methods, debugMethodOutputDebugTiming)
	}
	if checkDebuggerDLLs() {
		weakHits++
		methods = append(methods, debugMethodDebuggerDLLLoaded)
	}

	return shouldTriggerDebuggerByWeight(false, weakHits, weakSignalTriggerThreshold), methods
}

// checkBeingDebugged uses IsDebuggerPresent API
func checkBeingDebugged() bool {
	ret, _, _ := procIsDebuggerPresent.Call()
	return ret != 0
}

// checkRemoteDebugger checks if a remote debugger is attached using CheckRemoteDebuggerPresent.
func checkRemoteDebugger() bool {
	handle, _, _ := procGetCurrentProcess.Call()
	var debuggerPresent int32

	ret, _, _ := procCheckRemoteDebuggerPresent.Call(
		handle,
		uintptr(unsafe.Pointer(&debuggerPresent)),
	)

	if ret == 0 {
		return false
	}

	return debuggerPresent != 0
}

// checkProcessDebugPort queries the ProcessDebugPort using NtQueryInformationProcess.
// A non-zero value indicates the process is being debugged.
func checkProcessDebugPort() bool {
	handle, _, _ := procGetCurrentProcess.Call()

	var debugPort uintptr
	returnLength := uint32(0)

	ret, _, _ := procNtQueryInformationProcess.Call(
		handle,
		ProcessDebugPort,
		uintptr(unsafe.Pointer(&debugPort)),
		unsafe.Sizeof(debugPort),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	// ret == 0 means STATUS_SUCCESS
	if ret == 0 && debugPort != 0 {
		return true
	}

	return false
}

// checkProcessDebugObjectHandle queries ProcessDebugObjectHandle.
// A non-null handle indicates a debugger is attached.
func checkProcessDebugObjectHandle() bool {
	handle, _, _ := procGetCurrentProcess.Call()

	var debugHandle uintptr
	returnLength := uint32(0)

	ret, _, _ := procNtQueryInformationProcess.Call(
		handle,
		ProcessDebugObjectHandle,
		uintptr(unsafe.Pointer(&debugHandle)),
		unsafe.Sizeof(debugHandle),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	// ret == 0 means STATUS_SUCCESS
	if ret == 0 && debugHandle != 0 {
		return true
	}

	return false
}

// checkSystemDebugControlQueryVersion probes the kernel debugger interface.
// A successful SysDbgQueryVersion call implies the kernel debugger is active.
// When no kernel debugger is attached, Windows returns STATUS_DEBUGGER_INACTIVE.
func checkSystemDebugControlQueryVersion() bool {
	var version dbgkdGetVersion64
	var returnLength uint32

	ret, _, _ := procCheckSystemDebugControl.Call(
		uintptr(sysDbgQueryVersion),
		0,
		0,
		uintptr(unsafe.Pointer(&version)),
		unsafe.Sizeof(version),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if uint32(ret) == statusSuccess {
		return true
	}

	if uint32(ret) == statusDebuggerInactive {
		return false
	}

	return false
}

// checkOutputDebugStringTest uses a trick with OutputDebugString.
// If a debugger is present, it will consume the output.
// We can detect this by checking system state before/after.
func checkOutputDebugStringTest() bool {
	// Store initial tick count
	initialTicks := getTicks()

	// Call OutputDebugString - debugger will intercept this
	msg, _ := syscall.UTF16PtrFromString(outputDebugProbeMessage)
	procOutputDebugString.Call(uintptr(unsafe.Pointer(msg)))

	// If a debugger consumed it, there might be timing artifacts
	// This is a weak check but can help in some cases
	finalTicks := getTicks()

	// If time difference is suspicious (debugger stepping), flag it
	// Allow up to 10ms normally, debuggers often take longer
	if finalTicks-initialTicks > outputDebugTimingThresholdTicks {
		return true
	}

	return false
}

// getTicks returns the current system tick count
func getTicks() uint32 {
	ret, _, _ := procGetTickCount.Call()
	return uint32(ret)
}

// checkDebuggerDLLs checks if common debugger DLLs are loaded in memory
func checkDebuggerDLLs() bool {
	for _, dll := range debuggerDLLs {
		moduleHandle, _, _ := procGetModuleHandle.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(dll))))
		if moduleHandle != 0 {
			// DLL is loaded - could indicate debugger tools
			return true
		}
	}

	return false
}
