package security

const (
	AntiTamperProbeEnableEnv = "MUTANT_ENABLE_ANTITAMPER_PROBE"

	ProbeHardwareBreakpoint = "hardware_breakpoint"
	ProbeTiming             = "timing"
	ProbeSyscall            = "syscall"
	ProbeFridaPtrace        = "frida_ptrace"
	ProbeLDPreload          = "ld_preload"
	ProbeCPUIDHypervisor    = "cpuid_hypervisor"
	ProbeRDTSCDrift         = "rdtsc_drift"
	ProbeACPIPCI            = "acpi_pci"
	ProbeGPUFeature         = "gpu_feature"
	ProbeIATGOT             = "iat_got"
	ProbeSyscallTable       = "syscall_table"
	ProbeTrampoline         = "trampoline"
	ProbeProcessInjection   = "process_injection"
	ProbeModuleIntegrity    = "module_integrity"
	ProbeMemoryPageAnomaly  = "memory_page_anomaly"

	AntiTamperUnknownStage = "unknown"

	AntiTamperDetailNotImplemented = "not implemented yet"
	AntiTamperDetailUnknownProbe   = "unknown probe"

	ConfidenceNone                        = 0
	ConfidenceTimingBaseline              = 5
	ConfidenceRDTSCDriftSuspicious        = 35
	ConfidenceTimingSuspicious            = 40
	ConfidenceLDPreloadWindowsMarkers     = 55
	ConfidenceHardwareBreakpointDetected  = 65
	ConfidenceCPUIDHypervisorDetected     = 70
	ConfidenceHardwareBreakpointNamed     = 70
	ConfidenceProcessInjectionDetected    = 70
	ConfidenceTrampolineDetected          = 75
	ConfidenceFridaPtraceTracerDetected   = 75
	ConfidenceSyscallDetected             = 80
	ConfidenceSyscallTableDetected        = 82
	ConfidenceFridaTasklistDetected       = 85
	ConfidenceLDPreloadDetected           = 85
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

	ACPIPCIConfidenceCap = 60
	ACPIPCIConfidenceMin = 1

	LinuxProcSelfStatusPath = "/proc/self/status"
)

var (
	fridaEnvMarkers  = []string{"FRIDA", "FRIDA_AGENT", "FRIDA_GADGET"}
	fridaTaskMarkers = []string{"frida", "frida-helper", "frida-server", "frida-agent"}

	windowsInjectionEnvMarkers = []string{"COR_ENABLE_PROFILING", "COR_PROFILER", "COR_PROFILER_PATH", "__COMPAT_LAYER"}

	AntiTamperSupportedProbes = []string{
		ProbeHardwareBreakpoint,
		ProbeTiming,
		ProbeSyscall,
		ProbeFridaPtrace,
		ProbeLDPreload,
		ProbeCPUIDHypervisor,
		ProbeRDTSCDrift,
		ProbeACPIPCI,
		ProbeGPUFeature,
		ProbeIATGOT,
		ProbeSyscallTable,
		ProbeTrampoline,
		ProbeProcessInjection,
		ProbeModuleIntegrity,
		ProbeMemoryPageAnomaly,
	}
)
