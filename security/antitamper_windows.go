//go:build windows
// +build windows

package security

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	pageExecuteReadWrite = 0x40

	winModuleNtdll    = "ntdll.dll"
	winModuleKernel32 = "kernel32.dll"

	winFnNtOpenProcess      = "NtOpenProcess"
	winFnNtWriteVirtualMem  = "NtWriteVirtualMemory"
	winFnNtCreateThreadEx   = "NtCreateThreadEx"
	winFnCreateRemoteThread = "CreateRemoteThread"

	hookOpcodeRelativeJmp = 0xE9
	hookOpcodeNearCall    = 0xE8
	hookOpcodeGroup5      = 0xFF
	hookOpcodeIndirectJmp = 0x25
	hookOpcodeRexW        = 0x48
	hookOpcodeMovAbsRAX   = 0xB8
	hookOpcodeJmpRAX      = 0xE0
)

var (
	suspiciousModuleNames = []string{"frida-gadget.dll", "frida-agent.dll", "easyhook64.dll", "detoured.dll", "scyllahide.dll"}
	injectionEnvMarkers   = []string{"COR_ENABLE_PROFILING", "COR_PROFILER", "COR_PROFILER_PATH", "JAVA_TOOL_OPTIONS", "_NT_SYMBOL_PATH"}
	injectionTaskMarkers  = []string{"processhacker", "x64dbg", "ollydbg", "cheat engine", "frida", "dnspy"}
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

var (
	getModuleHandle = func(name string) uintptr {
		h, _, _ := procGetModuleHandle.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))))
		return h
	}
	resolveProcAddress = procAddress
	queryMemoryInfoAt  = queryMemoryInfo
)

func detectIATGOT() AntiTamperSignal {
	ntdllHandle := getModuleHandle(winModuleNtdll)
	if ntdllHandle == 0 {
		return makeSignal(ProbeIATGOT, false, ConfidenceNone, "ntdll unavailable")
	}

	suspicious := make([]string, 0, 3)
	for _, fn := range []string{winFnNtOpenProcess, winFnNtWriteVirtualMem, winFnNtCreateThreadEx} {
		addr := resolveProcAddress(ntdllHandle, fn)
		if addr == 0 {
			continue
		}

		mbi, ok := queryMemoryInfoAt(addr)
		if !ok {
			continue
		}
		if mbi.AllocationBase != ntdllHandle {
			suspicious = append(suspicious, fn)
		}
	}

	if len(suspicious) == 0 {
		return makeSignal(ProbeIATGOT, false, ConfidenceNone, "critical ntdll exports within image")
	}

	return makeSignal(ProbeIATGOT, true, ConfidenceIATGOTDetected, "redirected_exports="+strings.Join(suspicious, ","))
}

func detectSyscallTable() AntiTamperSignal {
	trampoline := detectTrampoline()
	if trampoline.Detected {
		return makeSignal(ProbeSyscallTable, true, ConfidenceSyscallTableDetected, "ntdll syscall trampoline anomalies")
	}

	return makeSignal(ProbeSyscallTable, false, ConfidenceNone, "no syscall trampoline anomaly")
}

func detectTrampoline() AntiTamperSignal {
	targets := []struct {
		module string
		name   string
	}{
		{module: winModuleNtdll, name: winFnNtOpenProcess},
		{module: winModuleNtdll, name: winFnNtWriteVirtualMem},
		{module: winModuleNtdll, name: winFnNtCreateThreadEx},
		{module: winModuleKernel32, name: winFnCreateRemoteThread},
	}

	flagged := make([]string, 0, len(targets))
	for _, target := range targets {
		handle := getModuleHandle(target.module)
		if handle == 0 {
			continue
		}

		addr := resolveProcAddress(handle, target.name)
		if addr == 0 {
			continue
		}
		if isLikelyHookTrampoline(addr) {
			flagged = append(flagged, target.module+":"+target.name)
		}
	}

	if len(flagged) == 0 {
		return makeSignal(ProbeTrampoline, false, ConfidenceNone, "no trampoline signature")
	}

	confidence := ConfidenceTrampolineDetected
	if len(flagged) >= 2 {
		confidence = ConfidenceTrampolineMultiHit
	}

	return makeSignal(ProbeTrampoline, true, confidence, "hooked_apis="+strings.Join(flagged, ","))
}

func detectProcessInjection() AntiTamperSignal {
	envHits := findInjectionEnvMarkers()
	procHits := findInjectionProcessMarkers()
	if len(envHits) == 0 && len(procHits) == 0 {
		return makeSignal(ProbeProcessInjection, false, ConfidenceNone, "no injection markers")
	}

	confidence := ConfidenceProcessInjectionDetected
	detailParts := make([]string, 0, 2)
	if len(envHits) > 0 {
		detailParts = append(detailParts, "env="+strings.Join(envHits, ","))
		confidence = ConfidenceProcessInjectionEnvDetected
	}
	if len(procHits) > 0 {
		detailParts = append(detailParts, "processes="+strings.Join(procHits, ","))
		if len(envHits) > 0 {
			confidence = ConfidenceProcessInjectionCombined
		}
	}

	return makeSignal(ProbeProcessInjection, true, confidence, strings.Join(detailParts, ";"))
}

func detectModuleIntegrity() AntiTamperSignal {
	suspicious := make([]string, 0, 4)
	for _, dll := range suspiciousModuleNames {
		h := getModuleHandle(dll)
		if h != 0 {
			suspicious = append(suspicious, dll)
		}
	}

	if len(suspicious) == 0 {
		return makeSignal(ProbeModuleIntegrity, false, ConfidenceNone, "no suspicious module marker")
	}

	return makeSignal(ProbeModuleIntegrity, true, ConfidenceModuleIntegrityDetected, "suspicious_modules="+strings.Join(suspicious, ","))
}

func detectMemoryPageAnomaly() AntiTamperSignal {
	targets := []struct {
		module string
		name   string
	}{
		{module: winModuleNtdll, name: winFnNtOpenProcess},
		{module: winModuleNtdll, name: winFnNtWriteVirtualMem},
		{module: winModuleKernel32, name: winFnCreateRemoteThread},
	}

	flagged := make([]string, 0, len(targets))
	for _, target := range targets {
		handle := getModuleHandle(target.module)
		if handle == 0 {
			continue
		}
		addr := resolveProcAddress(handle, target.name)
		if addr == 0 {
			continue
		}

		mbi, ok := queryMemoryInfoAt(addr)
		if !ok {
			continue
		}
		if mbi.Protect == pageExecuteReadWrite {
			flagged = append(flagged, target.module+":"+target.name)
		}
	}

	if len(flagged) == 0 {
		return makeSignal(ProbeMemoryPageAnomaly, false, ConfidenceNone, "no rwx api page")
	}

	return makeSignal(ProbeMemoryPageAnomaly, true, ConfidenceMemoryPageAnomalyDetected, "rwx_api_pages="+strings.Join(flagged, ","))
}

func procAddress(module uintptr, fnName string) uintptr {
	name := append([]byte(fnName), 0)
	addr, _, _ := procGetProcAddress.Call(module, uintptr(unsafe.Pointer(&name[0])))
	return addr
}

func queryMemoryInfo(addr uintptr) (memoryBasicInformation, bool) {
	procVirtualQuery := kernel32.NewProc("VirtualQuery")
	var mbi memoryBasicInformation
	ret, _, _ := procVirtualQuery.Call(
		addr,
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi),
	)
	if ret == 0 {
		return memoryBasicInformation{}, false
	}

	return mbi, true
}

func isLikelyHookTrampoline(addr uintptr) bool {
	bytes, ok := readCurrentProcessMemory(addr, 12)
	if !ok || len(bytes) < 6 {
		return false
	}

	return isLikelyHookBytes(bytes)
}

func isLikelyHookBytes(bytes []byte) bool {
	if len(bytes) < 6 {
		return false
	}

	if bytes[0] == hookOpcodeRelativeJmp || bytes[0] == hookOpcodeNearCall {
		return true
	}
	if bytes[0] == hookOpcodeGroup5 && bytes[1] == hookOpcodeIndirectJmp {
		return true
	}
	if bytes[0] == hookOpcodeRexW && bytes[1] == hookOpcodeMovAbsRAX && len(bytes) >= 12 && bytes[10] == hookOpcodeGroup5 && bytes[11] == hookOpcodeJmpRAX {
		return true
	}

	return false
}

func readCurrentProcessMemory(addr uintptr, size int) ([]byte, bool) {
	if size <= 0 {
		return nil, false
	}

	procReadProcessMemory := kernel32.NewProc("ReadProcessMemory")
	handle, _, _ := procGetCurrentProcess.Call()
	buf := make([]byte, size)
	var bytesRead uintptr

	ret, _, _ := procReadProcessMemory.Call(
		handle,
		addr,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 || bytesRead == 0 {
		return nil, false
	}

	return buf[:bytesRead], true
}

func findInjectionEnvMarkers() []string {
	out := make([]string, 0, len(injectionEnvMarkers))
	for _, marker := range injectionEnvMarkers {
		if value, ok := os.LookupEnv(marker); ok && strings.TrimSpace(value) != "" {
			out = append(out, marker)
		}
	}
	return out
}

func findInjectionProcessMarkers() []string {
	out, err := exec.Command("tasklist").Output()
	if err != nil {
		return nil
	}

	tasks := strings.ToLower(string(out))
	hits := make([]string, 0, len(injectionTaskMarkers))
	for _, marker := range injectionTaskMarkers {
		if strings.Contains(tasks, marker) {
			hits = append(hits, marker)
		}
	}
	return hits
}
