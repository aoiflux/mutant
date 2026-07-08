//go:build !windows
// +build !windows

package security

func detectIATGOT() AntiTamperSignal {
	return makeSignal(ProbeIATGOT, false, ConfidenceNone, "not supported on this platform")
}

func detectSyscallTable() AntiTamperSignal {
	return makeSignal(ProbeSyscallTable, false, ConfidenceNone, "not supported on this platform")
}

func detectTrampoline() AntiTamperSignal {
	return makeSignal(ProbeTrampoline, false, ConfidenceNone, "not supported on this platform")
}

func detectProcessInjection() AntiTamperSignal {
	return makeSignal(ProbeProcessInjection, false, ConfidenceNone, "not supported on this platform")
}

func detectModuleIntegrity() AntiTamperSignal {
	return makeSignal(ProbeModuleIntegrity, false, ConfidenceNone, "not supported on this platform")
}

func detectMemoryPageAnomaly() AntiTamperSignal {
	return makeSignal(ProbeMemoryPageAnomaly, false, ConfidenceNone, "not supported on this platform")
}
