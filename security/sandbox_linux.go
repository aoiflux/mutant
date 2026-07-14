//go:build linux
// +build linux

package security

import (
	"os"
	"os/exec"
	"strings"
)

const (
	linuxSandboxTypeContainer    = "Container"
	linuxSandboxTypeKubernetes   = "Kubernetes"
	linuxSandboxTypeWSL          = "WSL"
	linuxSandboxTypeLXC          = "LXC"
	linuxSandboxTypeSystemdSpawn = "systemd-nspawn"
	linuxSandboxTypeVM           = "VM"
	linuxSandboxTypeKVMQEMU      = "KVM/QEMU"
	linuxSandboxTypeVMware       = "VMware"
	linuxSandboxTypeVirtualBox   = "VirtualBox"
	linuxSandboxTypeXen          = "Xen"
	linuxSandboxTypeHyperV       = "Hyper-V"

	linuxConfidenceDockerFile     = 85
	linuxConfidenceContainerFile  = 75
	linuxConfidenceKubernetesEnv  = 85
	linuxConfidenceWSLEnv         = 95
	linuxConfidenceKubernetesCgrp = 80
	linuxConfidenceContainerCgrp  = 70
	linuxConfidenceLXC            = 75
	linuxConfidenceSystemdNspawn  = 60
	linuxConfidenceHypervisorFlag = 30
	linuxConfidenceVMVendorCPU    = 80
	linuxConfidenceHyperVCPU      = 85
	linuxConfidenceWSLKernel      = 90
	linuxConfidenceDMIVendor      = 75
	linuxConfidenceXenProcFile    = 85
	linuxConfidenceHyperVLinuxSig = 80
	linuxConfidenceCPUIDVendor    = 35

	linuxPathContainerEnv   = "/run/.containerenv"
	linuxPathProc1Cgroup    = "/proc/1/cgroup"
	linuxPathProcSelfCgrp   = "/proc/self/cgroup"
	linuxPathProcCPUInfo    = "/proc/cpuinfo"
	linuxPathProcVersion    = "/proc/version"
	linuxPathProcXen        = "/proc/xen"
	linuxPathDMIProduct     = "/sys/class/dmi/id/product_name"
	linuxPathDMISysVendor   = "/sys/class/dmi/id/sys_vendor"
	linuxPathDMIBoardVendor = "/sys/class/dmi/id/board_vendor"
	linuxPathDMIBIOSVendor  = "/sys/class/dmi/id/bios_vendor"
	linuxPathBusVMBus       = "/sys/bus/vmbus/devices"
	linuxPathHvKvpDaemon    = "/usr/sbin/hv_kvp_daemon"
	linuxPathHvFcopyDaemon  = "/usr/sbin/hv_fcopy_daemon"
	linuxPathHvVssDaemon    = "/usr/sbin/hv_vss_daemon"

	linuxEnvKubernetesHost = "KUBERNETES_SERVICE_HOST"
	linuxEnvKubernetesPort = "KUBERNETES_SERVICE_PORT"
	linuxEnvWSLInterop     = "WSL_INTEROP"
	linuxEnvWSLDistroName  = "WSL_DISTRO_NAME"

	linuxIndicatorContainerFile     = "linux:file:/run/.containerenv"
	linuxIndicatorKubernetesEnv     = "linux:env:kubernetes_service"
	linuxIndicatorWSLEnv            = "linux:env:wsl"
	linuxIndicatorKubernetesCgroup  = "linux:cgroup:kubepods"
	linuxIndicatorContainerRuntime  = "linux:cgroup:container_runtime"
	linuxIndicatorLXC               = "linux:cgroup:lxc"
	linuxIndicatorSystemdNspawn     = "linux:cgroup:systemd_nspawn"
	linuxIndicatorCPUHypervisorFlag = "linux:cpu:hypervisor_flag"
	linuxIndicatorCPUKVMQEMU        = "linux:cpu:kvm_qemu"
	linuxIndicatorCPUVMware         = "linux:cpu:vmware"
	linuxIndicatorCPUVirtualBox     = "linux:cpu:virtualbox"
	linuxIndicatorCPUXen            = "linux:cpu:xen"
	linuxIndicatorCPUHyperV         = "linux:cpu:hyperv"
	linuxIndicatorKernelMicrosoft   = "linux:kernel:microsoft"
	linuxIndicatorDMIVMware         = "linux:dmi:vmware"
	linuxIndicatorDMIVirtualBox     = "linux:dmi:virtualbox"
	linuxIndicatorDMIKVMQEMU        = "linux:dmi:kvm_qemu"
	linuxIndicatorDMIXen            = "linux:dmi:xen"
	linuxIndicatorDMIHyperV         = "linux:dmi:hyperv"
	linuxIndicatorDMIMicrosoftVM    = "linux:dmi:microsoft_virtual_machine"
	linuxIndicatorFileProcXen       = "linux:file:/proc/xen"
	linuxIndicatorFileVMBus         = "linux:file:/sys/bus/vmbus/devices"
	linuxIndicatorModuleHvVMBus     = "linux:module:hv_vmbus"
	linuxIndicatorHvDaemon          = "linux:file:hyperv_daemon"
	linuxIndicatorCPUIDHypervisor   = "linux:cpuid:hypervisor"
	linuxIndicatorCPUIDHyperVVendor = "linux:cpuid:microsoft_hv"
)

var (
	linuxCgroupPaths       = []string{linuxPathProc1Cgroup, linuxPathProcSelfCgrp}
	linuxContainerRuntimes = []string{"docker", "containerd", "podman", "libpod", "crio"}
	linuxDMIPaths          = []string{linuxPathDMIProduct, linuxPathDMISysVendor, linuxPathDMIBoardVendor, linuxPathDMIBIOSVendor}
	linuxHyperVDaemonPaths = []string{linuxPathHvKvpDaemon, linuxPathHvFcopyDaemon, linuxPathHvVssDaemon}
)

func detectSandboxLinux() (sandboxDetection, error) {
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

	if fileExists(LNX_DCKR_ENV_0) {
		add(DOCKER, linuxConfidenceDockerFile, LNX_DCKR_ENV_1)
	}
	if fileExists(linuxPathContainerEnv) {
		add(linuxSandboxTypeContainer, linuxConfidenceContainerFile, linuxIndicatorContainerFile)
	}
	if envSet(linuxEnvKubernetesHost) || envSet(linuxEnvKubernetesPort) {
		add(linuxSandboxTypeKubernetes, linuxConfidenceKubernetesEnv, linuxIndicatorKubernetesEnv)
	}
	if envSet(linuxEnvWSLInterop) || envSet(linuxEnvWSLDistroName) {
		add(linuxSandboxTypeWSL, linuxConfidenceWSLEnv, linuxIndicatorWSLEnv)
	}

	for _, cgroupPath := range linuxCgroupPaths {
		data, err := os.ReadFile(cgroupPath)
		if err != nil {
			return detection, err
		}

		cgroup := strings.ToLower(string(data))
		if strings.Contains(cgroup, "kubepods") {
			add(linuxSandboxTypeKubernetes, linuxConfidenceKubernetesCgrp, linuxIndicatorKubernetesCgroup)
		}

		if containsAny(cgroup, linuxContainerRuntimes) {
			add(DOCKER, linuxConfidenceContainerCgrp, linuxIndicatorContainerRuntime)
		}

		if strings.Contains(cgroup, "lxc") {
			add(linuxSandboxTypeLXC, linuxConfidenceLXC, linuxIndicatorLXC)
		}
		if strings.Contains(cgroup, "machine.slice") && strings.Contains(cgroup, "systemd") {
			add(linuxSandboxTypeSystemdSpawn, linuxConfidenceSystemdNspawn, linuxIndicatorSystemdNspawn)
		}
	}

	if data, err := os.ReadFile(linuxPathProcCPUInfo); err == nil {
		cpu := strings.ToLower(string(data))
		if strings.Contains(cpu, "hypervisor") {
			add(linuxSandboxTypeVM, linuxConfidenceHypervisorFlag, linuxIndicatorCPUHypervisorFlag)
		}
		if strings.Contains(cpu, "microsoft hv") || strings.Contains(cpu, "hyper-v") {
			add(linuxSandboxTypeHyperV, linuxConfidenceHyperVCPU, linuxIndicatorCPUHyperV)
		}
		if strings.Contains(cpu, "kvm") || strings.Contains(cpu, "qemu") {
			add(linuxSandboxTypeKVMQEMU, linuxConfidenceVMVendorCPU, linuxIndicatorCPUKVMQEMU)
		}
		if strings.Contains(cpu, "vmware") {
			add(linuxSandboxTypeVMware, linuxConfidenceVMVendorCPU, linuxIndicatorCPUVMware)
		}
		if strings.Contains(cpu, "virtualbox") {
			add(linuxSandboxTypeVirtualBox, linuxConfidenceVMVendorCPU, linuxIndicatorCPUVirtualBox)
		}
		if strings.Contains(cpu, "xen") {
			add(linuxSandboxTypeXen, linuxConfidenceVMVendorCPU, linuxIndicatorCPUXen)
		}
	}

	if hypervisorVendor := getCPUIDHypervisorVendor(); hasAnyHypervisorVendor(hypervisorVendor) {
		add(linuxSandboxTypeVM, linuxConfidenceCPUIDVendor, linuxIndicatorCPUIDHypervisor)
		if isMicrosoftHypervisorVendor(hypervisorVendor) {
			add(linuxSandboxTypeHyperV, linuxConfidenceHyperVCPU, linuxIndicatorCPUIDHyperVVendor)
		}
	}

	if data, err := os.ReadFile(linuxPathProcVersion); err == nil {
		kernel := strings.ToLower(string(data))
		if strings.Contains(kernel, "microsoft") {
			add(linuxSandboxTypeWSL, linuxConfidenceWSLKernel, linuxIndicatorKernelMicrosoft)
		}
	}

	dmiHasMicrosoftVendor := false
	dmiHasVirtualMachine := false

	for _, dmiPath := range linuxDMIPaths {
		if data, err := os.ReadFile(dmiPath); err == nil {
			v := strings.ToLower(string(data))
			if strings.Contains(v, "microsoft corporation") {
				dmiHasMicrosoftVendor = true
			}
			if strings.Contains(v, "virtual machine") || strings.Contains(v, "virtual") {
				dmiHasVirtualMachine = true
			}
			if strings.Contains(v, "vmware") {
				add(linuxSandboxTypeVMware, linuxConfidenceDMIVendor, linuxIndicatorDMIVMware)
			}
			if strings.Contains(v, "virtualbox") {
				add(linuxSandboxTypeVirtualBox, linuxConfidenceDMIVendor, linuxIndicatorDMIVirtualBox)
			}
			if strings.Contains(v, "kvm") || strings.Contains(v, "qemu") {
				add(linuxSandboxTypeKVMQEMU, linuxConfidenceDMIVendor, linuxIndicatorDMIKVMQEMU)
			}
			if strings.Contains(v, "xen") {
				add(linuxSandboxTypeXen, linuxConfidenceDMIVendor, linuxIndicatorDMIXen)
			}
			if strings.Contains(v, "microsoft corporation") && strings.Contains(v, "virtual") {
				add(linuxSandboxTypeHyperV, linuxConfidenceDMIVendor, linuxIndicatorDMIHyperV)
			}
		}
	}

	if dmiHasMicrosoftVendor && dmiHasVirtualMachine {
		add(linuxSandboxTypeHyperV, linuxConfidenceDMIVendor, linuxIndicatorDMIMicrosoftVM)
	}

	if fileExists(linuxPathProcXen) {
		add(linuxSandboxTypeXen, linuxConfidenceXenProcFile, linuxIndicatorFileProcXen)
	}

	if hasLinuxHyperVVMBus(linuxPathBusVMBus) {
		add(linuxSandboxTypeHyperV, linuxConfidenceHyperVLinuxSig, linuxIndicatorFileVMBus)
	}

	if hasLinuxHyperVModule() {
		add(linuxSandboxTypeHyperV, linuxConfidenceHyperVLinuxSig, linuxIndicatorModuleHvVMBus)
	}

	if hasLinuxHyperVDaemon(linuxHyperVDaemonPaths) {
		add(linuxSandboxTypeHyperV, linuxConfidenceHyperVLinuxSig, linuxIndicatorHvDaemon)
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

func hasLinuxHyperVVMBus(path string) bool {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	return len(entries) > 0
}

func hasLinuxHyperVModule() bool {
	out, err := exec.Command("lsmod").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "hv_vmbus")
}

func hasLinuxHyperVDaemon(paths []string) bool {
	for _, daemonPath := range paths {
		if fileExists(daemonPath) {
			return true
		}
	}
	return false
}
