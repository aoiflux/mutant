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
	case ProbeCPUIDHypervisor:
		return detectCPUIDHypervisor()
	case ProbeRDTSCDrift:
		return detectRDTSCDrift()
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
		return unmeasuredSignal("", AntiTamperDetailUnknownProbe)
	default:
		return unmeasuredSignal(name, AntiTamperDetailUnknownProbe)
	}
}
