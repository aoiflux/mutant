//go:build windows
// +build windows

package security

import (
	"strings"
	"testing"
)

func TestDetectSandboxWindowsFromTasklistHyperV(t *testing.T) {
	detection := detectSandboxWindowsFromTasklist("vmicheartbeat.exe vmictimesync.exe")
	if detection.Type != windowsSandboxTypeHyperV {
		t.Fatalf("expected %s detection, got %q", windowsSandboxTypeHyperV, detection.Type)
	}
	if detection.Confidence < windowsConfidenceHyperVIntegration {
		t.Fatalf("expected Hyper-V confidence >= %d, got %d", windowsConfidenceHyperVIntegration, detection.Confidence)
	}
	if len(detection.Indicators) == 0 {
		t.Fatalf("expected Hyper-V indicators")
	}
}

func TestDetectSandboxWindowsFromTasklistHyperVVmicsvc(t *testing.T) {
	detection := detectSandboxWindowsFromTasklist("svchost.exe vmicsvc.exe")
	if detection.Type != windowsSandboxTypeHyperV {
		t.Fatalf("expected %s detection, got %q", windowsSandboxTypeHyperV, detection.Type)
	}
	if detection.Confidence < windowsConfidenceHyperVIntegration {
		t.Fatalf("expected Hyper-V confidence >= %d, got %d", windowsConfidenceHyperVIntegration, detection.Confidence)
	}
}

func TestIsWindowsHyperVBaseboardOutput(t *testing.T) {
	out := "Manufacturer           Product\r\nMicrosoft Corporation  Virtual Machine\r\n"
	if !isWindowsHyperVBaseboardOutput(out) {
		t.Fatalf("expected Hyper-V baseboard output to be detected")
	}
}

func TestIsWindowsHyperVBaseboardOutputNegative(t *testing.T) {
	out := "Manufacturer Product\r\nDell Inc. Latitude\r\n"
	if isWindowsHyperVBaseboardOutput(out) {
		t.Fatalf("expected non-Hyper-V baseboard output to be ignored")
	}
}

func TestIsWindowsHyperVVendorModelOutput(t *testing.T) {
	out := "Manufacturer           Model\r\nMicrosoft Corporation  Virtual Machine\r\n"
	if !isWindowsHyperVVendorModelOutput(out) {
		t.Fatalf("expected Hyper-V vendor/model output to be detected")
	}
}

func TestIsWindowsHyperVVendorModelOutputNegative(t *testing.T) {
	out := "Manufacturer  Model\r\nDell Inc.     Precision\r\n"
	if isWindowsHyperVVendorModelOutput(out) {
		t.Fatalf("expected non-Hyper-V vendor/model output to be ignored")
	}
}

func TestIsWindowsHyperVSMBIOS(t *testing.T) {
	data := []byte("...Microsoft Corporation...Virtual Machine...")
	if !isWindowsHyperVSMBIOS(data) {
		t.Fatalf("expected Hyper-V SMBIOS marker to be detected")
	}
}

func TestIsWindowsHyperVSMBIOSNegative(t *testing.T) {
	data := []byte("...Dell Inc...Latitude...")
	if isWindowsHyperVSMBIOS(data) {
		t.Fatalf("expected non-Hyper-V SMBIOS marker to be ignored")
	}
}

func TestIsWindowsHyperVPnPOutput(t *testing.T) {
	out := "Name\r\nMicrosoft Hyper-V Virtual Machine Bus Provider\r\n"
	if !isWindowsHyperVPnPOutput(out) {
		t.Fatalf("expected Hyper-V PnP output to be detected")
	}
}

func TestIsWindowsHyperVPnPOutputNegative(t *testing.T) {
	out := "Name\r\nMicrosoft Hyper-V Virtual Ethernet Adapter\r\n"
	if isWindowsHyperVPnPOutput(out) {
		t.Fatalf("expected host-side Hyper-V adapter output to be ignored")
	}
}

func TestHasWindowsHyperVHostProcesses(t *testing.T) {
	if !hasWindowsHyperVHostProcesses("svchost.exe vmcompute.exe") {
		t.Fatalf("expected Hyper-V host process set to be detected")
	}
}

func TestHasWindowsHyperVHostProcessesNegative(t *testing.T) {
	if hasWindowsHyperVHostProcesses("svchost.exe explorer.exe") {
		t.Fatalf("expected non-host process list to be ignored")
	}
}

func TestIsWindowsRegistryVirtualMachineKeyOutput(t *testing.T) {
	out := "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\VirtualMachine\\Guest"
	if !isWindowsRegistryVirtualMachineKeyOutput(out) {
		t.Fatalf("expected Hyper-V virtual machine key output to be detected")
	}
}

func TestIsWindowsHyperVRegistryBIOSOutput(t *testing.T) {
	manufacturer := "SystemManufacturer    REG_SZ    Microsoft Corporation"
	product := "SystemProductName      REG_SZ    Virtual Machine"
	if !isWindowsHyperVRegistryBIOSOutput(manufacturer, product) {
		t.Fatalf("expected Hyper-V BIOS registry output to be detected")
	}
}

func TestIsWindowsHyperVRegistryBIOSOutputNegative(t *testing.T) {
	manufacturer := "SystemManufacturer    REG_SZ    Dell Inc."
	product := "SystemProductName      REG_SZ    Latitude"
	if isWindowsHyperVRegistryBIOSOutput(manufacturer, product) {
		t.Fatalf("expected non-Hyper-V BIOS registry output to be ignored")
	}
}

func TestDetectSandboxWindowsFromTasklistHostHyperVProcessesNoSignal(t *testing.T) {
	detection := detectSandboxWindowsFromTasklist("vmcompute.exe vmwp.exe vmms.exe")
	if detection.Type != "" || detection.Confidence != 0 {
		t.Fatalf("expected no sandbox signal from host Hyper-V processes, got type=%q confidence=%d", detection.Type, detection.Confidence)
	}
}

func TestDetectSandboxWindowsFromTasklistHostWSLProcessesNoSignal(t *testing.T) {
	detection := detectSandboxWindowsFromTasklist("wslhost.exe wslservice.exe vmmemwsl.exe")
	if detection.Type != "" || detection.Confidence != 0 {
		t.Fatalf("expected no sandbox signal from host WSL processes, got type=%q confidence=%d", detection.Type, detection.Confidence)
	}
}

func TestDetectSandboxWindowsFromEnvWSL(t *testing.T) {
	detection := detectSandboxWindowsFromEnv(map[string]string{windowsEnvWSLInterop: `/run/WSL/9_interop`})
	if detection.Type != windowsSandboxTypeWSL {
		t.Fatalf("expected WSL detection, got %q", detection.Type)
	}
	if detection.Confidence < windowsConfidenceWslCwd {
		t.Fatalf("expected WSL confidence >= %d, got %d", windowsConfidenceWslCwd, detection.Confidence)
	}
	if len(detection.Indicators) == 0 {
		t.Fatalf("expected WSL indicators")
	}
}

func TestDetectSandboxWindowsFromEnvWSLENV(t *testing.T) {
	detection := detectSandboxWindowsFromEnv(map[string]string{windowsEnvWSLEnv: "PATH/l"})
	if detection.Type != windowsSandboxTypeWSL {
		t.Fatalf("expected WSL detection, got %q", detection.Type)
	}
	if detection.Confidence != windowsConfidenceWslEnvOnly {
		t.Fatalf("expected WSLENV-only confidence %d, got %d", windowsConfidenceWslEnvOnly, detection.Confidence)
	}
	if detection.Confidence >= SandboxDetectedThreshold {
		t.Fatalf("expected WSLENV-only signal to stay below sandbox threshold, got %d", detection.Confidence)
	}
}

func TestDetectSandboxWindowsFromCwdWSLUNC(t *testing.T) {
	detection := detectSandboxWindowsFromCwd(`\\wsl.localhost\Ubuntu\home\user\project`)
	if detection.Type != windowsSandboxTypeWSL {
		t.Fatalf("expected WSL detection from cwd, got %q", detection.Type)
	}
	if detection.Confidence < windowsConfidenceWslCwd {
		t.Fatalf("expected WSL cwd confidence >= %d, got %d", windowsConfidenceWslCwd, detection.Confidence)
	}
}

func TestDetectSandboxWindowsFromParentWSLHost(t *testing.T) {
	detection := detectSandboxWindowsFromParent("wslhost.exe")
	if detection.Type != windowsSandboxTypeWSL {
		t.Fatalf("expected WSL detection from parent process, got %q", detection.Type)
	}
	if detection.Confidence < windowsConfidenceWslParent {
		t.Fatalf("expected WSL parent confidence >= %d, got %d", windowsConfidenceWslParent, detection.Confidence)
	}
}

// TestDetectSandboxWindowsFromParentGitBashIsReportedTruthfully is the filed
// half of M26-TMP-003. Git for Windows, MSYS2 and Cygwin all ship a bash.exe,
// and that name scored 90 under the type WSL, so a plain Windows host with no
// WSL installed was told it was running under WSL. The halt is intended and is
// asserted here; the label was not, and is asserted too.
func TestDetectSandboxWindowsFromParentGitBashIsReportedTruthfully(t *testing.T) {
	for _, parent := range []string{"bash.exe", "BASH.EXE", " bash.exe "} {
		detection := detectSandboxWindowsFromParent(parent)
		if detection.Type == windowsSandboxTypeWSL {
			t.Fatalf("parent %q is the shell Git for Windows, MSYS2 and Cygwin all ship, and "+
				"the legacy WSL launcher shares its name, so it must not be reported as %q",
				parent, windowsSandboxTypeWSL)
		}
		if detection.Type != windowsSandboxTypePosixShell {
			t.Fatalf("parent %q: expected type %q, got %q",
				parent, windowsSandboxTypePosixShell, detection.Type)
		}
		if detection.Confidence < SandboxDetectedThreshold {
			t.Fatalf("parent %q must still count as detected: expected confidence >= %d, got %d",
				parent, SandboxDetectedThreshold, detection.Confidence)
		}
	}
}

// TestDetectSandboxWindowsFromParentMatchesTheWholeName is the half found while
// fixing the first. Both name lists were compared with containsAny, a substring
// search, so an image name that merely held one of their entries scored 90 as
// though it were that entry. None of these is a shell or a launcher.
func TestDetectSandboxWindowsFromParentMatchesTheWholeName(t *testing.T) {
	for _, parent := range []string{
		"notwsl.exe", "mywsl.exe", "wslhost.exe.bak", "mywslhost.exe",
		"gitbash.exe", "bash.exe.bak", "mybash.exe",
	} {
		detection := detectSandboxWindowsFromParent(parent)
		if detection.Type != "" || detection.Confidence != 0 {
			t.Fatalf("parent %q only holds a name from one of the lists and is not one, so it "+
				"must not score at all; got %q at confidence %d",
				parent, detection.Type, detection.Confidence)
		}
	}
}

// TestDetectSandboxWindowsFromParentStillFindsWSL is the other direction: the
// names that do mean WSL still score as WSL, in any case and with surrounding
// space, so narrowing the match did not disable it.
func TestDetectSandboxWindowsFromParentStillFindsWSL(t *testing.T) {
	for _, parent := range []string{"wsl.exe", "wslhost.exe", "WSLHOST.EXE", " wsl.exe "} {
		detection := detectSandboxWindowsFromParent(parent)
		if detection.Type != windowsSandboxTypeWSL {
			t.Fatalf("parent %q is a WSL launcher; expected %q, got %q",
				parent, windowsSandboxTypeWSL, detection.Type)
		}
		if detection.Confidence < windowsConfidenceWslParent {
			t.Fatalf("parent %q: expected confidence >= %d, got %d",
				parent, windowsConfidenceWslParent, detection.Confidence)
		}
	}
}

func TestParseTasklistImageName(t *testing.T) {
	image, err := parseTasklistImageName([]byte(`"wslhost.exe","4231","Console","1","10,240 K"`))
	if err != nil {
		t.Fatalf("expected no parse error, got %v", err)
	}
	if image != "wslhost.exe" {
		t.Fatalf("expected image name wslhost.exe, got %q", image)
	}
}

func TestDetectSandboxWindowsFromEnvWindowsSandbox(t *testing.T) {
	detection := detectSandboxWindowsFromEnv(map[string]string{windowsEnvUsername: windowsWdagUtilityAccount})
	if detection.Type != windowsSandboxTypeWindowsSB {
		t.Fatalf("expected Windows Sandbox detection, got %q", detection.Type)
	}
	if detection.Confidence < windowsConfidenceWdagSignals {
		t.Fatalf("expected Windows Sandbox confidence >= %d, got %d", windowsConfidenceWdagSignals, detection.Confidence)
	}
	if len(detection.Indicators) == 0 {
		t.Fatalf("expected Windows Sandbox indicators")
	}
}

func TestFinalizeWindowsDetectionCapsConfidence(t *testing.T) {
	typeScore := map[string]int{windowsSandboxTypeWSL: maxConfidenceScore + 50}
	detection := finalizeWindowsDetection(typeScore, []string{windowsIndicatorEnvWSLContext})

	if detection.Confidence != maxConfidenceScore {
		t.Fatalf("expected confidence cap at %d, got %d", maxConfidenceScore, detection.Confidence)
	}
	if detection.Type != windowsSandboxTypeWSL {
		t.Fatalf("expected type %q, got %q", windowsSandboxTypeWSL, detection.Type)
	}
}

func TestFinalizeWindowsDetectionTieBreakPrefersHyperV(t *testing.T) {
	typeScore := map[string]int{
		windowsSandboxTypeHyperV: 85,
		windowsSandboxTypeWSL:    85,
	}
	detection := finalizeWindowsDetection(typeScore, []string{windowsIndicatorWMICBaseboardHV, windowsIndicatorEnvWSLContext})
	if detection.Type != windowsSandboxTypeHyperV {
		t.Fatalf("expected tie-break to prefer %q, got %q", windowsSandboxTypeHyperV, detection.Type)
	}
}

// TestFinalizeWindowsDetectionTieBreakPrefersWSLOverTheAmbiguousShell is why a
// real WSL run is not reported under the type a bash.exe parent gets. A Windows
// build reached from WSL scores WSL from its context environment and its UNC
// working directory too, and where one of those ties with the parent-name score
// the specific type has to win (M26-TMP-003).
func TestFinalizeWindowsDetectionTieBreakPrefersWSLOverTheAmbiguousShell(t *testing.T) {
	typeScore := map[string]int{
		windowsSandboxTypeWSL:        windowsConfidenceWslCwd,
		windowsSandboxTypePosixShell: windowsConfidenceBashParent,
	}
	detection := finalizeWindowsDetection(typeScore, []string{windowsIndicatorCwdWSLUNC, windowsIndicatorParentBash})
	if detection.Type != windowsSandboxTypeWSL {
		t.Fatalf("expected tie-break to prefer %q, got %q", windowsSandboxTypeWSL, detection.Type)
	}
}

// TestFinalizeWindowsDetectionTieBreakPrefersTheShellOverAGenericVM is the other
// side of the same priority entry, and the side that needs it: a type absent
// from the priority map scores 0 there and silently loses every tie, so naming
// the shell would lose to the generic VM bucket without the entry. At an equal
// score the shell is the more specific answer and has to win (M26-TMP-003).
func TestFinalizeWindowsDetectionTieBreakPrefersTheShellOverAGenericVM(t *testing.T) {
	typeScore := map[string]int{
		windowsSandboxTypePosixShell: 60,
		windowsSandboxTypeVM:         60,
	}
	detection := finalizeWindowsDetection(typeScore, []string{windowsIndicatorParentBash, windowsIndicatorCPUHypervisor})
	if detection.Type != windowsSandboxTypePosixShell {
		t.Fatalf("expected tie-break to prefer %q, got %q", windowsSandboxTypePosixShell, detection.Type)
	}
}

func detectSandboxWindowsFromTasklist(tasklist string) sandboxDetection {
	typeScore := map[string]int{}
	indicators := make([]string, 0, 8)

	add := func(kind string, confidence int, indicator string) {
		if confidence <= 0 {
			return
		}
		typeScore[kind] += confidence
		indicators = append(indicators, indicator)
	}

	addWindowsProcessIndicators(tasklist, add)
	return finalizeWindowsDetection(typeScore, indicators)
}

func TestDetectSandboxWindowsFromTasklistHostWindowsSandboxProcessesNoSignal(t *testing.T) {
	detection := detectSandboxWindowsFromTasklist("WindowsSandbox.exe SandboxClient.exe")
	if detection.Type != "" || detection.Confidence != 0 {
		t.Fatalf("expected no sandbox signal from host Windows Sandbox processes, got type=%q confidence=%d", detection.Type, detection.Confidence)
	}
}

func detectSandboxWindowsFromEnv(env map[string]string) sandboxDetection {
	typeScore := map[string]int{}
	indicators := make([]string, 0, 8)

	add := func(kind string, confidence int, indicator string) {
		if confidence <= 0 {
			return
		}
		typeScore[kind] += confidence
		indicators = append(indicators, indicator)
	}

	addWindowsEnvIndicators(func(name string) (string, bool) {
		value, ok := env[name]
		return value, ok
	}, add)
	if value, ok := env[windowsEnvUsername]; ok && value == windowsWdagUtilityAccount {
		add(windowsSandboxTypeWindowsSB, windowsConfidenceWdagSignals, windowsIndicatorEnvWdagUser)
	}
	if value, ok := env[windowsEnvUserProfile]; ok && value != "" {
		profile := strings.ToLower(value)
		if strings.Contains(profile, windowsPathWdagProfile) {
			add(windowsSandboxTypeWindowsSB, windowsConfidenceWdagSignals, windowsIndicatorEnvWdagProfile)
		}
	}

	return finalizeWindowsDetection(typeScore, indicators)
}

func detectSandboxWindowsFromCwd(cwd string) sandboxDetection {
	typeScore := map[string]int{}
	indicators := make([]string, 0, 8)

	add := func(kind string, confidence int, indicator string) {
		if confidence <= 0 {
			return
		}
		typeScore[kind] += confidence
		indicators = append(indicators, indicator)
	}

	addWindowsWSLCwdIndicators(cwd, add)
	return finalizeWindowsDetection(typeScore, indicators)
}

func detectSandboxWindowsFromParent(parentName string) sandboxDetection {
	typeScore := map[string]int{}
	indicators := make([]string, 0, 8)

	add := func(kind string, confidence int, indicator string) {
		if confidence <= 0 {
			return
		}
		typeScore[kind] += confidence
		indicators = append(indicators, indicator)
	}

	addWindowsParentProcessIndicators(parentName, add)
	return finalizeWindowsDetection(typeScore, indicators)
}
