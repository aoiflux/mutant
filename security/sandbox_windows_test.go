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
	if detection.Confidence >= sandboxDetectedThreshold {
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

	addWindowsWSLParentIndicators(parentName, add)
	return finalizeWindowsDetection(typeScore, indicators)
}
