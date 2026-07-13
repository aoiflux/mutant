package security

import (
	"strings"

	cpuid "github.com/klauspost/cpuid/v2"
)

func getCPUIDHypervisorVendor() string {
	return strings.ToLower(strings.TrimSpace(cpuid.CPU.HypervisorVendorString))
}

func isMicrosoftHypervisorVendor(vendor string) bool {
	v := strings.ToLower(strings.TrimSpace(vendor))
	return strings.Contains(v, "microsoft hv") || strings.Contains(v, "hyper-v")
}

func hasAnyHypervisorVendor(vendor string) bool {
	return strings.TrimSpace(vendor) != ""
}
