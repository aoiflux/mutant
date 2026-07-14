//go:build darwin
// +build darwin

package security

import (
	"os"
	"os/exec"
	"strings"
)

const (
	darwinSandboxTypeAppSandbox = "macOS App Sandbox"
	darwinSandboxTypeColima     = "Colima"
	darwinSandboxTypeVMware     = "VMware Fusion"
	darwinSandboxTypeVirtualBox = "VirtualBox"
	darwinSandboxTypeParallels  = "Parallels"
	darwinSandboxTypeUTM        = "UTM"
	darwinSandboxTypeQEMU       = "QEMU"
	darwinSandboxTypeVM         = "VM"

	darwinConfidenceAppSandboxEnv = 85
	darwinConfidenceDYLDEnv       = 35
	darwinConfidenceColimaEnv     = 80
	darwinConfidenceVMAppFile     = 80
	darwinConfidenceParallelsDir  = 60
	darwinConfidenceColimaBin     = 70
	darwinConfidenceVMProcess     = 70
	darwinConfidenceCPUIDVendor   = 35

	darwinEnvAppSandboxContainer = "APP_SANDBOX_CONTAINER_ID"
	darwinEnvDYLDInsertLibraries = "DYLD_INSERT_LIBRARIES"
	darwinEnvColimaHome          = "COLIMA_HOME"

	darwinIndicatorEnvAppSandbox = "darwin:env:app_sandbox_container_id"
	darwinIndicatorEnvDYLDInsert = "darwin:env:dyld_insert_libraries"
	darwinIndicatorEnvColimaHome = "darwin:env:colima_home"
	darwinIndicatorProcVMware    = "darwin:process:vmware_vmx"
	darwinIndicatorProcVBox      = "darwin:process:virtualbox_tools"
	darwinIndicatorProcParallels = "darwin:process:parallels_tools"
	darwinIndicatorProcQEMU      = "darwin:process:qemu_system"
	darwinIndicatorProcColima    = "darwin:process:colima"
	darwinIndicatorCPUIDHypervis = "darwin:cpuid:hypervisor"
)

var darwinSandboxPathChecks = []struct {
	path  string
	kind  string
	score int
	mark  string
}{
	{"/Applications/VMware Fusion.app", darwinSandboxTypeVMware, darwinConfidenceVMAppFile, "darwin:file:vmware_fusion_app"},
	{"/Applications/VirtualBox.app", darwinSandboxTypeVirtualBox, darwinConfidenceVMAppFile, "darwin:file:virtualbox_app"},
	{"/Applications/Parallels Desktop.app", darwinSandboxTypeParallels, darwinConfidenceVMAppFile, "darwin:file:parallels_app"},
	{"/Applications/UTM.app", darwinSandboxTypeUTM, darwinConfidenceVMAppFile, "darwin:file:utm_app"},
	{"/Users/Shared/Parallels", darwinSandboxTypeParallels, darwinConfidenceParallelsDir, "darwin:file:parallels_shared"},
	{"/opt/homebrew/bin/colima", darwinSandboxTypeColima, darwinConfidenceColimaBin, "darwin:file:colima_bin"},
}

func detectSandboxDarwin() (sandboxDetection, error) {
	var detection sandboxDetection

	typeScore := map[string]int{}
	indicators := make([]string, 0, 8)

	add := func(kind string, confidence int, indicator string) {
		if confidence <= 0 {
			return
		}
		typeScore[kind] += confidence
		indicators = append(indicators, indicator)
	}

	if envSet(darwinEnvAppSandboxContainer) {
		add(darwinSandboxTypeAppSandbox, darwinConfidenceAppSandboxEnv, darwinIndicatorEnvAppSandbox)
	}
	if envSet(darwinEnvDYLDInsertLibraries) {
		add(darwinSandboxTypeAppSandbox, darwinConfidenceDYLDEnv, darwinIndicatorEnvDYLDInsert)
	}
	if envSet(darwinEnvColimaHome) {
		add(darwinSandboxTypeColima, darwinConfidenceColimaEnv, darwinIndicatorEnvColimaHome)
	}

	for _, path := range darwinSandboxPathChecks {
		if _, err := os.Stat(path.path); err == nil {
			add(path.kind, path.score, path.mark)
		}
	}

	if out, err := exec.Command("ps", "-axo", "comm").CombinedOutput(); err == nil {
		procs := strings.ToLower(string(out))
		if strings.Contains(procs, "vmware-vmx") {
			add(darwinSandboxTypeVMware, darwinConfidenceVMProcess, darwinIndicatorProcVMware)
		}
		if strings.Contains(procs, "vboxservice") || strings.Contains(procs, "vboxclient") {
			add(darwinSandboxTypeVirtualBox, darwinConfidenceVMProcess, darwinIndicatorProcVBox)
		}
		if strings.Contains(procs, "prl_tools") {
			add(darwinSandboxTypeParallels, darwinConfidenceVMProcess, darwinIndicatorProcParallels)
		}
		if strings.Contains(procs, "qemu-system") {
			add(darwinSandboxTypeQEMU, darwinConfidenceVMProcess, darwinIndicatorProcQEMU)
		}
		if strings.Contains(procs, "colima") {
			add(darwinSandboxTypeColima, darwinConfidenceVMProcess, darwinIndicatorProcColima)
		}
	}

	if hypervisorVendor := getCPUIDHypervisorVendor(); hasAnyHypervisorVendor(hypervisorVendor) {
		add(darwinSandboxTypeVM, darwinConfidenceCPUIDVendor, darwinIndicatorCPUIDHypervis)
	}

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

	detection.Type = bestType
	detection.Confidence = bestScore
	detection.Indicators = uniqueStrings(indicators)
	return detection, nil
}
