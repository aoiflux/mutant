package security

func probeOne(name string) AntiTamperSignal {
	switch name {
	case ProbeHardwareBreakpoint:
		return detectHardwareBreakpoint()
	case ProbeTiming:
		return detectTiming()
	case ProbeSyscall:
		return detectSyscall()
	case ProbeFridaPtrace:
		return detectFridaPtrace()
	case ProbeLDPreload:
		return detectLDPreload()
	case ProbeCPUIDHypervisor:
		return detectCPUIDHypervisor()
	case ProbeRDTSCDrift:
		return detectRDTSCDrift()
	case ProbeACPIPCI:
		return makeSignal(name, false, ConfidenceNone, AntiTamperDetailNotImplemented)
	case ProbeGPUFeature:
		return makeSignal(name, false, ConfidenceNone, AntiTamperDetailNotImplemented)
	case ProbeIATGOT:
		return detectIATGOT()
	case ProbeSyscallTable:
		return detectSyscallTable()
	case ProbeTrampoline:
		return detectTrampoline()
	case ProbeProcessInjection:
		return detectProcessInjection()
	case ProbeModuleIntegrity:
		return detectModuleIntegrity()
	case ProbeMemoryPageAnomaly:
		return detectMemoryPageAnomaly()
	case "":
		return makeSignal("", false, ConfidenceNone, AntiTamperDetailUnknownProbe)
	default:
		return makeSignal(name, false, ConfidenceNone, AntiTamperDetailUnknownProbe)
	}
}
