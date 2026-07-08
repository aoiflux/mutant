//go:build windows
// +build windows

package security

import (
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"strings"
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

	windowsIndicatorFileVmMouse      = "windows:file:vmmouse.sys"
	windowsIndicatorFileVmHgfs       = "windows:file:vmhgfs.sys"
	windowsIndicatorFileVboxMouse    = "windows:file:vboxmouse.sys"
	windowsIndicatorFileVboxGuest    = "windows:file:vboxguest.sys"
	windowsIndicatorFileXenBus       = "windows:file:xenbus.sys"
	windowsIndicatorFileSandboxieDLL = "windows:file:sbiedll.dll"
	windowsIndicatorEnvSandboxie     = "windows:env:sandboxie"
	windowsIndicatorEnvCuckoo        = "windows:env:cuckoo"
	windowsIndicatorEnvVboxInstall   = "windows:env:vbox_install_path"
	windowsIndicatorEnvWSLContext    = "windows:env:wsl_context"
	windowsIndicatorEnvWSLEnvOnly    = "windows:env:wslenv_only"
	windowsIndicatorEnvWdagUser      = "windows:env:wdag_utility_account"
	windowsIndicatorEnvWdagProfile   = "windows:env:userprofile_wdag"
	windowsIndicatorCwdWSLUNC        = "windows:cwd:wsl_unc_path"
	windowsIndicatorParentWSL        = "windows:process_parent:wsl"
	windowsIndicatorProcVMwareTools  = "windows:process:vmware_tools"
	windowsIndicatorProcVboxTools    = "windows:process:virtualbox_tools"
	windowsIndicatorProcXenService   = "windows:process:xenservice"
	windowsIndicatorProcQemuAgent    = "windows:process:qemu_guest_agent"
	windowsIndicatorProcSandboxie    = "windows:process:sandboxie"
	windowsIndicatorProcHyperVGuest  = "windows:process:hyperv_guest_integration"
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

	windowsHyperVProcesses = []string{"vmicheartbeat.exe", "vmicvss.exe", "vmicrdv.exe", "vmicshutdown.exe", "vmictimesync.exe", "vmicvmsession.exe"}
	windowsWSLParentNames  = []string{"wsl.exe", "wslhost.exe", "bash.exe"}
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

	if out, err := exec.Command("tasklist").CombinedOutput(); err == nil {
		addWindowsProcessIndicators(strings.ToLower(string(out)), add)
	}

	detection = finalizeWindowsDetection(typeScore, indicators)
	return detection, nil
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
	bestType := ""
	bestScore := 0
	for kind, score := range typeScore {
		if score > bestScore {
			bestType = kind
			bestScore = score
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
