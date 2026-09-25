//go:build !windows
// +build !windows

package security

import "runtime"

// notMeasuredHere is the answer of a probe that reads Windows process
// structures -- the import table, ntdll's prologues, loaded modules, page
// protections -- on a host that has none. It did not look, and says so: all
// five probes the runner's process protection runs are among these, so off
// Windows that protection measures nothing.
func notMeasuredHere(name string) AntiTamperSignal {
	return unmeasuredSignal(name, "not measured on "+runtime.GOOS+": this probe reads Windows process structures")
}

func detectIATGOT() AntiTamperSignal {
	return notMeasuredHere(ProbeIATGOT)
}

func detectSyscallTable() AntiTamperSignal {
	return notMeasuredHere(ProbeSyscallTable)
}

func detectTrampoline() AntiTamperSignal {
	return notMeasuredHere(ProbeTrampoline)
}

func detectProcessInjection() AntiTamperSignal {
	return notMeasuredHere(ProbeProcessInjection)
}

func detectModuleIntegrity() AntiTamperSignal {
	return notMeasuredHere(ProbeModuleIntegrity)
}

func detectMemoryPageAnomaly() AntiTamperSignal {
	return notMeasuredHere(ProbeMemoryPageAnomaly)
}
