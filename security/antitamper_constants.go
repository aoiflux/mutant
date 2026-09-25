package security

const (
	ProbeHardwareBreakpoint = "hardware_breakpoint"
	ProbeTiming             = "timing"
	ProbeSyscall            = "syscall"
	ProbeFridaPtrace        = "frida_ptrace"
	ProbeCPUIDHypervisor    = "cpuid_hypervisor"
	ProbeRDTSCDrift         = "rdtsc_drift"
	ProbeIATGOT             = "iat_got"
	ProbeSyscallTable       = "syscall_table"
	ProbeTrampoline         = "trampoline"
	ProbeProcessInjection   = "process_injection"
	ProbeModuleIntegrity    = "module_integrity"
	ProbeMemoryPageAnomaly  = "memory_page_anomaly"

	AntiTamperUnknownStage = "unknown"

	AntiTamperDetailUnknownProbe = "unknown probe"

	ConfidenceNone                        = 0
	ConfidenceTimingBaseline              = 5
	ConfidenceRDTSCDriftSuspicious        = 35
	ConfidenceTimingSuspicious            = 40
	ConfidenceHardwareBreakpointDetected  = 65
	ConfidenceCPUIDHypervisorDetected     = 70
	ConfidenceHardwareBreakpointNamed     = 70
	ConfidenceProcessInjectionDetected    = 70
	ConfidenceTrampolineDetected          = 75
	ConfidenceFridaPtraceTracerDetected   = 75
	ConfidenceSyscallDetected             = 80
	ConfidenceSyscallTableDetected        = 82
	ConfidenceFridaTasklistDetected       = 85
	ConfidenceModuleIntegrityDetected     = 85
	ConfidenceIATGOTDetected              = 90
	ConfidenceFridaEnvMarkerDetected      = 90
	ConfidenceProcessInjectionEnvDetected = 90
	ConfidenceTrampolineMultiHit          = 90
	ConfidenceMemoryPageAnomalyDetected   = 92
	ConfidenceProcessInjectionCombined    = 95

	TimingLoopIterations        uint64 = 200000
	TimingLoopXORConstant       uint64 = 0x9E3779B9
	TimingSuspiciousThresholdUs        = 200000

	RDTSCDriftSleepIterations = 3
	RDTSCDriftThresholdMs     = 10

	LinuxProcSelfStatusPath = "/proc/self/status"
)

var (
	fridaEnvMarkers  = []string{"FRIDA", "FRIDA_AGENT", "FRIDA_GADGET"}
	fridaTaskMarkers = []string{"frida", "frida-helper", "frida-server", "frida-agent"}

	windowsInjectionEnvMarkers = []string{"COR_ENABLE_PROFILING", "COR_PROFILER", "COR_PROFILER_PATH", "__COMPAT_LAYER"}

	// AntiTamperSupportedProbes are the probes that measure something. Three
	// names that did not left the list in 2.6.0 and are unknown probes now:
	// acpi_pci re-reported the sandbox detector, which cpuid_hypervisor
	// reports; gpu_feature was never implemented; and ld_preload could not
	// have seen anything, because a statically linked build (CGO_ENABLED=0,
	// as every release is) never runs the dynamic loader LD_PRELOAD works
	// through. docs/ANTITAMPER_PROBE.md says the same.
	AntiTamperSupportedProbes = []string{
		ProbeHardwareBreakpoint,
		ProbeTiming,
		ProbeSyscall,
		ProbeFridaPtrace,
		ProbeCPUIDHypervisor,
		ProbeRDTSCDrift,
		ProbeIATGOT,
		ProbeSyscallTable,
		ProbeTrampoline,
		ProbeProcessInjection,
		ProbeModuleIntegrity,
		ProbeMemoryPageAnomaly,
	}
)
