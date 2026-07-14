//go:build windows
// +build windows

package security

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	windowsSandboxTypeVMware     = "VMware"
	windowsSandboxTypeVirtualBox = "VirtualBox"
	windowsSandboxTypeXen        = "Xen"
	windowsSandboxTypeSandboxie  = "Sandboxie"
	windowsSandboxTypeCuckoo     = "Cuckoo"
	windowsSandboxTypeWSL        = "WSL"
	windowsSandboxTypeWindowsSB  = "Windows Sandbox"
	windowsSandboxTypeKVMQEMU    = "KVM/QEMU"
	windowsSandboxTypeHyperV     = "Hyper-V"
	windowsSandboxTypeVM         = "VM"

	windowsConfidenceFileDriver        = 80
	windowsConfidenceSandboxieFile     = 85
	windowsConfidenceSandboxieEnv      = 85
	windowsConfidenceCuckooEnv         = 85
	windowsConfidenceVboxEnv           = 70
	windowsConfidenceWslContextEnv     = 95
	windowsConfidenceWslEnvOnly        = 35
	windowsConfidenceWslCwd            = 90
	windowsConfidenceWslParent         = 90
	windowsConfidenceWdagSignals       = 95
	windowsConfidenceVmProcessTools    = 70
	windowsConfidenceHyperVIntegration = 80
	windowsConfidenceHyperVBaseboard   = 85
	windowsConfidenceHyperVSMBIOS      = 90
	windowsConfidenceHyperVRegistry    = 85
	windowsConfidenceHyperVPnP         = 35
	windowsConfidenceCPUHypervisor     = 20
	windowsConfidenceCPUHyperVVendor   = 20

	windowsPathVmMouse     = `C:\\windows\\system32\\drivers\\vmmouse.sys`
	windowsPathVmHgfs      = `C:\\windows\\system32\\drivers\\vmhgfs.sys`
	windowsPathVboxMouse   = `C:\\windows\\system32\\drivers\\VBoxMouse.sys`
	windowsPathVboxGuest   = `C:\\windows\\system32\\drivers\\VBoxGuest.sys`
	windowsPathXenBus      = `C:\\windows\\system32\\drivers\\xenbus.sys`
	windowsPathSandboxie   = `C:\\windows\\system32\\SbieDll.dll`
	windowsPathWdagProfile = `\users\wdagutilityaccount`

	windowsEnvSandboxie     = "SANDBOXIE"
	windowsEnvCuckoo        = "CUCKOO"
	windowsEnvVBoxInstall   = "VBOX_INSTALL_PATH"
	windowsEnvUsername      = "USERNAME"
	windowsEnvUserProfile   = "USERPROFILE"
	windowsEnvWSLInterop    = "WSL_INTEROP"
	windowsEnvWSLDistroName = "WSL_DISTRO_NAME"
	windowsEnvWSLEnv        = "WSLENV"

	windowsWdagUtilityAccount = "WDAGUtilityAccount"

	windowsIndicatorFileVmMouse       = "windows:file:vmmouse.sys"
	windowsIndicatorFileVmHgfs        = "windows:file:vmhgfs.sys"
	windowsIndicatorFileVboxMouse     = "windows:file:vboxmouse.sys"
	windowsIndicatorFileVboxGuest     = "windows:file:vboxguest.sys"
	windowsIndicatorFileXenBus        = "windows:file:xenbus.sys"
	windowsIndicatorFileSandboxieDLL  = "windows:file:sbiedll.dll"
	windowsIndicatorEnvSandboxie      = "windows:env:sandboxie"
	windowsIndicatorEnvCuckoo         = "windows:env:cuckoo"
	windowsIndicatorEnvVboxInstall    = "windows:env:vbox_install_path"
	windowsIndicatorEnvWSLContext     = "windows:env:wsl_context"
	windowsIndicatorEnvWSLEnvOnly     = "windows:env:wslenv_only"
	windowsIndicatorEnvWdagUser       = "windows:env:wdag_utility_account"
	windowsIndicatorEnvWdagProfile    = "windows:env:userprofile_wdag"
	windowsIndicatorCwdWSLUNC         = "windows:cwd:wsl_unc_path"
	windowsIndicatorParentWSL         = "windows:process_parent:wsl"
	windowsIndicatorProcVMwareTools   = "windows:process:vmware_tools"
	windowsIndicatorProcVboxTools     = "windows:process:virtualbox_tools"
	windowsIndicatorProcXenService    = "windows:process:xenservice"
	windowsIndicatorProcQemuAgent     = "windows:process:qemu_guest_agent"
	windowsIndicatorProcSandboxie     = "windows:process:sandboxie"
	windowsIndicatorProcHyperVGuest   = "windows:process:hyperv_guest_integration"
	windowsIndicatorWMICBaseboardHV   = "windows:wmic:baseboard_hyperv"
	windowsIndicatorWMICSystemHV      = "windows:wmic:computersystem_hyperv"
	windowsIndicatorPowerShellCimHV   = "windows:powershell:cim_hyperv"
	windowsIndicatorSMBIOSHyperV      = "windows:smbios:hyperv"
	windowsIndicatorRegistryHyperVKey = "windows:registry:virtualmachine_key"
	windowsIndicatorRegistryHyperVBIO = "windows:registry:bios_hyperv"
	windowsIndicatorPnPHyperV         = "windows:wmi:pnp_hyperv"
	windowsIndicatorCPUHypervisor     = "windows:cpuid:hypervisor_bit"
	windowsIndicatorCPUHyperVVendor   = "windows:cpuid:microsoft_hv"

	windowsRSMBSignature = uint32('R') | uint32('S')<<8 | uint32('M')<<16 | uint32('B')<<24
)

var (
	windowsSandboxFileChecks = []struct {
		path  string
		kind  string
		score int
		mark  string
	}{
		{windowsPathVmMouse, windowsSandboxTypeVMware, windowsConfidenceFileDriver, windowsIndicatorFileVmMouse},
		{windowsPathVmHgfs, windowsSandboxTypeVMware, windowsConfidenceFileDriver, windowsIndicatorFileVmHgfs},
		{windowsPathVboxMouse, windowsSandboxTypeVirtualBox, windowsConfidenceFileDriver, windowsIndicatorFileVboxMouse},
		{windowsPathVboxGuest, windowsSandboxTypeVirtualBox, windowsConfidenceFileDriver, windowsIndicatorFileVboxGuest},
		{windowsPathXenBus, windowsSandboxTypeXen, windowsConfidenceFileDriver, windowsIndicatorFileXenBus},
		{windowsPathSandboxie, windowsSandboxTypeSandboxie, windowsConfidenceSandboxieFile, windowsIndicatorFileSandboxieDLL},
	}

	windowsHyperVProcesses = []string{
		"vmicsvc.exe",
		"vmicheartbeat.exe",
		"vmicvss.exe",
		"vmicrdv.exe",
		"vmicshutdown.exe",
		"vmictimesync.exe",
		"vmicvmsession.exe",
		"vmicexchange.exe",
		"vmicguestinterface.exe",
		"vmickvpexchange.exe",
	}
	windowsHyperVHostProcesses = []string{"vmcompute.exe", "vmwp.exe", "vmms.exe"}
	windowsWSLParentNames      = []string{"wsl.exe", "wslhost.exe", "bash.exe"}

	modkernel32                = syscall.NewLazyDLL("kernel32.dll")
	procGetSystemFirmwareTable = modkernel32.NewProc("GetSystemFirmwareTable")
)

func detectSandboxWindows() (sandboxDetection, error) {
	typeScore := map[string]int{}
	indicators := make([]string, 0, 8)

	add := func(kind string, confidence int, indicator string) {
		if confidence <= 0 {
			return
		}
		typeScore[kind] += confidence
		indicators = append(indicators, indicator)
	}

	var detection sandboxDetection

	for _, path := range windowsSandboxFileChecks {
		if _, err := os.Stat(path.path); err == nil {
			add(path.kind, path.score, path.mark)
		}
	}

	if envSet(windowsEnvSandboxie) {
		add(windowsSandboxTypeSandboxie, windowsConfidenceSandboxieEnv, windowsIndicatorEnvSandboxie)
	}
	if envSet(windowsEnvCuckoo) {
		add(windowsSandboxTypeCuckoo, windowsConfidenceCuckooEnv, windowsIndicatorEnvCuckoo)
	}
	if envSet(windowsEnvVBoxInstall) {
		add(windowsSandboxTypeVirtualBox, windowsConfidenceVboxEnv, windowsIndicatorEnvVboxInstall)
	}
	addWindowsEnvIndicators(os.LookupEnv, add)
	if wd, err := os.Getwd(); err == nil {
		addWindowsWSLCwdIndicators(wd, add)
	}
	if parent, err := getWindowsParentProcessName(os.Getppid); err == nil {
		addWindowsWSLParentIndicators(parent, add)
	}

	if user, ok := os.LookupEnv(windowsEnvUsername); ok && strings.EqualFold(strings.TrimSpace(user), windowsWdagUtilityAccount) {
		add(windowsSandboxTypeWindowsSB, windowsConfidenceWdagSignals, windowsIndicatorEnvWdagUser)
	}
	if profile, ok := os.LookupEnv(windowsEnvUserProfile); ok {
		profile = strings.ToLower(strings.TrimSpace(profile))
		if strings.Contains(profile, windowsPathWdagProfile) {
			add(windowsSandboxTypeWindowsSB, windowsConfidenceWdagSignals, windowsIndicatorEnvWdagProfile)
		}
	}

	hyperVHostRoleDetected := false
	if out, err := exec.Command("tasklist").CombinedOutput(); err == nil {
		procs := strings.ToLower(string(out))
		addWindowsProcessIndicators(procs, add)
		hyperVHostRoleDetected = hasWindowsHyperVHostProcesses(procs)
	}

	if hypervisorVendor := getCPUIDHypervisorVendor(); hasAnyHypervisorVendor(hypervisorVendor) {
		add(windowsSandboxTypeVM, windowsConfidenceCPUHypervisor, windowsIndicatorCPUHypervisor)
		if !hyperVHostRoleDetected && isMicrosoftHypervisorVendor(hypervisorVendor) {
			add(windowsSandboxTypeHyperV, windowsConfidenceCPUHyperVVendor, windowsIndicatorCPUHyperVVendor)
		}
	}

	if out, err := exec.Command("wmic", "baseboard", "get", "manufacturer,product").CombinedOutput(); err == nil {
		addWindowsBaseboardIndicators(string(out), add)
	}

	if out, err := exec.Command("wmic", "computersystem", "get", "manufacturer,model").CombinedOutput(); err == nil {
		addWindowsSystemModelIndicators(string(out), add)
	}

	if !hyperVHostRoleDetected {
		if out, err := exec.Command("wmic", "path", "Win32_PnPEntity", "get", "Name").CombinedOutput(); err == nil {
			addWindowsPnPIndicators(string(out), add)
		}
	}

	if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer; Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty Model").CombinedOutput(); err == nil {
		addWindowsPowerShellCimIndicators(string(out), add)
	}

	if !hyperVHostRoleDetected {
		if table, err := getWindowsRawSMBIOS(); err == nil {
			addWindowsSMBIOSIndicators(table, add)
		}
	}

	addWindowsRegistryIndicators(add)

	detection = finalizeWindowsDetection(typeScore, indicators)
	return detection, nil
}

func addWindowsBaseboardIndicators(baseboardOutput string, add func(kind string, confidence int, indicator string)) {
	if isWindowsHyperVBaseboardOutput(baseboardOutput) {
		add(windowsSandboxTypeHyperV, windowsConfidenceHyperVBaseboard, windowsIndicatorWMICBaseboardHV)
	}
}

func addWindowsSMBIOSIndicators(rawSMBIOS []byte, add func(kind string, confidence int, indicator string)) {
	if isWindowsHyperVSMBIOS(rawSMBIOS) {
		add(windowsSandboxTypeHyperV, windowsConfidenceHyperVSMBIOS, windowsIndicatorSMBIOSHyperV)
	}
}

func addWindowsSystemModelIndicators(systemOutput string, add func(kind string, confidence int, indicator string)) {
	if isWindowsHyperVVendorModelOutput(systemOutput) {
		add(windowsSandboxTypeHyperV, windowsConfidenceHyperVBaseboard, windowsIndicatorWMICSystemHV)
	}
}

func addWindowsPowerShellCimIndicators(cimOutput string, add func(kind string, confidence int, indicator string)) {
	if isWindowsHyperVVendorModelOutput(cimOutput) {
		add(windowsSandboxTypeHyperV, windowsConfidenceHyperVBaseboard, windowsIndicatorPowerShellCimHV)
	}
}

func addWindowsPnPIndicators(pnpOutput string, add func(kind string, confidence int, indicator string)) {
	if isWindowsHyperVPnPOutput(pnpOutput) {
		add(windowsSandboxTypeHyperV, windowsConfidenceHyperVPnP, windowsIndicatorPnPHyperV)
	}
}

func addWindowsRegistryIndicators(add func(kind string, confidence int, indicator string)) {
	if out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\VirtualMachine\Guest`).CombinedOutput(); err == nil {
		if isWindowsRegistryVirtualMachineKeyOutput(string(out)) {
			add(windowsSandboxTypeHyperV, windowsConfidenceHyperVRegistry, windowsIndicatorRegistryHyperVKey)
		}
	}
	if out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\VirtualMachine\Auto`).CombinedOutput(); err == nil {
		if isWindowsRegistryVirtualMachineKeyOutput(string(out)) {
			add(windowsSandboxTypeHyperV, windowsConfidenceHyperVRegistry, windowsIndicatorRegistryHyperVKey)
		}
	}

	var systemManufacturerOut string
	if out, err := exec.Command("reg", "query", `HKLM\HARDWARE\DESCRIPTION\System\BIOS`, "/v", "SystemManufacturer").CombinedOutput(); err == nil {
		systemManufacturerOut = string(out)
	}

	var systemProductOut string
	if out, err := exec.Command("reg", "query", `HKLM\HARDWARE\DESCRIPTION\System\BIOS`, "/v", "SystemProductName").CombinedOutput(); err == nil {
		systemProductOut = string(out)
	}

	if isWindowsHyperVRegistryBIOSOutput(systemManufacturerOut, systemProductOut) {
		add(windowsSandboxTypeHyperV, windowsConfidenceHyperVRegistry, windowsIndicatorRegistryHyperVBIO)
	}
}

func isWindowsHyperVBaseboardOutput(baseboardOutput string) bool {
	out := strings.ToLower(baseboardOutput)
	return strings.Contains(out, "microsoft corporation") && strings.Contains(out, "virtual machine")
}

func isWindowsHyperVVendorModelOutput(output string) bool {
	out := strings.ToLower(output)
	return strings.Contains(out, "microsoft corporation") && strings.Contains(out, "virtual machine")
}

func isWindowsHyperVSMBIOS(rawSMBIOS []byte) bool {
	if len(rawSMBIOS) == 0 {
		return false
	}
	data := bytes.ToLower(rawSMBIOS)
	return bytes.Contains(data, []byte("microsoft corporation")) && bytes.Contains(data, []byte("virtual machine"))
}

func isWindowsHyperVPnPOutput(pnpOutput string) bool {
	out := strings.ToLower(pnpOutput)
	return strings.Contains(out, "vmbus") || strings.Contains(out, "virtual machine bus") || strings.Contains(out, "hyper-v heartbeat") || strings.Contains(out, "hyper-v guest shutdown")
}

func hasWindowsHyperVHostProcesses(procs string) bool {
	return containsAny(strings.ToLower(procs), windowsHyperVHostProcesses)
}

func isWindowsRegistryVirtualMachineKeyOutput(out string) bool {
	value := strings.ToLower(strings.TrimSpace(out))
	return strings.Contains(value, `software\microsoft\virtualmachine\`)
}

func isWindowsHyperVRegistryBIOSOutput(systemManufacturerOut string, systemProductOut string) bool {
	manufacturer := strings.ToLower(systemManufacturerOut)
	product := strings.ToLower(systemProductOut)
	return strings.Contains(manufacturer, "microsoft corporation") && strings.Contains(product, "virtual machine")
}

func addWindowsProcessIndicators(procs string, add func(kind string, confidence int, indicator string)) {
	procs = strings.ToLower(procs)

	if strings.Contains(procs, "vmtoolsd.exe") || strings.Contains(procs, "vmwaretray.exe") {
		add(windowsSandboxTypeVMware, windowsConfidenceVmProcessTools, windowsIndicatorProcVMwareTools)
	}
	if strings.Contains(procs, "vboxservice.exe") || strings.Contains(procs, "vboxtray.exe") {
		add(windowsSandboxTypeVirtualBox, windowsConfidenceVmProcessTools, windowsIndicatorProcVboxTools)
	}
	if strings.Contains(procs, "xenservice.exe") {
		add(windowsSandboxTypeXen, windowsConfidenceVmProcessTools, windowsIndicatorProcXenService)
	}
	if strings.Contains(procs, "qemu-ga.exe") {
		add(windowsSandboxTypeKVMQEMU, windowsConfidenceVmProcessTools, windowsIndicatorProcQemuAgent)
	}
	if strings.Contains(procs, "sbiectrl.exe") || strings.Contains(procs, "sandboxiedcomlaunch.exe") {
		add(windowsSandboxTypeSandboxie, windowsConfidenceSandboxieEnv, windowsIndicatorProcSandboxie)
	}

	if containsAny(procs, windowsHyperVProcesses) {
		add(windowsSandboxTypeHyperV, windowsConfidenceHyperVIntegration, windowsIndicatorProcHyperVGuest)
	}
}

func addWindowsEnvIndicators(lookupEnv func(string) (string, bool), add func(kind string, confidence int, indicator string)) {
	for _, name := range []string{windowsEnvWSLInterop, windowsEnvWSLDistroName} {
		if value, ok := lookupEnv(name); ok && strings.TrimSpace(value) != "" {
			add(windowsSandboxTypeWSL, windowsConfidenceWslContextEnv, windowsIndicatorEnvWSLContext)
			return
		}
	}

	// WSLENV can leak into host shells (for example via terminal profiles),
	// so treat it as weak evidence unless corroborated by stronger signals.
	if value, ok := lookupEnv(windowsEnvWSLEnv); ok && strings.TrimSpace(value) != "" {
		add(windowsSandboxTypeWSL, windowsConfidenceWslEnvOnly, windowsIndicatorEnvWSLEnvOnly)
	}
}

func addWindowsWSLCwdIndicators(cwd string, add func(kind string, confidence int, indicator string)) {
	path := strings.ToLower(strings.TrimSpace(cwd))
	if strings.HasPrefix(path, `\\wsl$\`) || strings.HasPrefix(path, `\\wsl.localhost\`) {
		add(windowsSandboxTypeWSL, windowsConfidenceWslCwd, windowsIndicatorCwdWSLUNC)
	}
}

func addWindowsWSLParentIndicators(parentName string, add func(kind string, confidence int, indicator string)) {
	parent := strings.ToLower(strings.TrimSpace(parentName))
	if containsAny(parent, windowsWSLParentNames) {
		add(windowsSandboxTypeWSL, windowsConfidenceWslParent, windowsIndicatorParentWSL)
	}
}

func getWindowsParentProcessName(getppid func() int) (string, error) {
	ppid := getppid()
	if ppid <= 0 {
		return "", nil
	}
	out, err := exec.Command("tasklist", "/fo", "csv", "/nh", "/fi", fmt.Sprintf("PID eq %d", ppid)).CombinedOutput()
	if err != nil {
		return "", err
	}
	return parseTasklistImageName(out)
}

func getWindowsRawSMBIOS() ([]byte, error) {
	size, _, _ := procGetSystemFirmwareTable.Call(
		uintptr(windowsRSMBSignature),
		0,
		0,
		0,
	)
	if size == 0 {
		return nil, fmt.Errorf("failed to get SMBIOS size")
	}

	buf := make([]byte, size)
	ret, _, _ := procGetSystemFirmwareTable.Call(
		uintptr(windowsRSMBSignature),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		size,
	)
	if ret == 0 {
		return nil, fmt.Errorf("failed to read SMBIOS")
	}

	return buf, nil
}

func parseTasklistImageName(out []byte) (string, error) {
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return "", nil
	}
	reader := csv.NewReader(strings.NewReader(raw))
	rec, err := reader.Read()
	if err != nil {
		return "", err
	}
	if len(rec) == 0 {
		return "", nil
	}
	imageName := strings.ToLower(strings.TrimSpace(rec[0]))
	if strings.HasPrefix(imageName, "info:") {
		return "", nil
	}
	return imageName, nil
}

func finalizeWindowsDetection(typeScore map[string]int, indicators []string) sandboxDetection {
	priority := map[string]int{
		windowsSandboxTypeHyperV:     100,
		windowsSandboxTypeKVMQEMU:    90,
		windowsSandboxTypeVMware:     90,
		windowsSandboxTypeVirtualBox: 90,
		windowsSandboxTypeXen:        90,
		windowsSandboxTypeWindowsSB:  85,
		windowsSandboxTypeSandboxie:  80,
		windowsSandboxTypeCuckoo:     80,
		windowsSandboxTypeWSL:        70,
		windowsSandboxTypeVM:         60,
	}

	bestType := ""
	bestScore := 0
	bestPriority := 0
	for kind, score := range typeScore {
		kindPriority := priority[kind]
		if score > bestScore || (score == bestScore && kindPriority > bestPriority) {
			bestType = kind
			bestScore = score
			bestPriority = kindPriority
		}
	}
	if bestScore > maxConfidenceScore {
		bestScore = maxConfidenceScore
	}

	return sandboxDetection{
		Type:       bestType,
		Confidence: bestScore,
		Indicators: uniqueStrings(indicators),
	}
}
