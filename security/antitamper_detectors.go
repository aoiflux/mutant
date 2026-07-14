package security

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func detectHardwareBreakpoint() AntiTamperSignal {
	detected, methods := DetectDebuggerDetails()
	if !detected {
		return makeSignal(ProbeHardwareBreakpoint, false, ConfidenceNone, "no debugger method detected")
	}

	if len(methods) == 0 {
		return makeSignal(ProbeHardwareBreakpoint, true, ConfidenceHardwareBreakpointDetected, "debugger detected without named method")
	}

	return makeSignal(
		ProbeHardwareBreakpoint,
		true,
		ConfidenceHardwareBreakpointNamed,
		"debugger_methods="+strings.Join(methods, ","),
	)
}

func detectTiming() AntiTamperSignal {
	start := time.Now()
	var acc uint64
	for i := uint64(0); i < TimingLoopIterations; i++ {
		acc ^= i * TimingLoopXORConstant
	}
	elapsedUs := time.Since(start).Microseconds()
	suspicious := elapsedUs > TimingSuspiciousThresholdUs
	confidence := ConfidenceTimingBaseline
	if suspicious {
		confidence = ConfidenceTimingSuspicious
	}

	return makeSignal(
		ProbeTiming,
		suspicious,
		confidence,
		"loop_us="+strconv.FormatInt(elapsedUs, 10)+";acc="+strconv.FormatUint(acc, 10),
	)
}

func detectSyscall() AntiTamperSignal {
	detected, methods := DetectDebuggerDetails()
	if !detected {
		return makeSignal(ProbeSyscall, false, ConfidenceNone, "no debugger API signal detected")
	}

	detail := "debugger signal detected"
	if len(methods) > 0 {
		detail = "api_hits=" + strings.Join(methods, ",")
	}

	return makeSignal(ProbeSyscall, true, ConfidenceSyscallDetected, detail)
}

func detectFridaPtrace() AntiTamperSignal {
	for _, marker := range fridaEnvMarkers {
		if _, ok := os.LookupEnv(marker); ok {
			return makeSignal(ProbeFridaPtrace, true, ConfidenceFridaEnvMarkerDetected, "env marker present: "+marker)
		}
	}

	if runtime.GOOS == "linux" {
		if tracer, ok := readLinuxTracerPID(); ok && tracer > 0 {
			return makeSignal(ProbeFridaPtrace, true, ConfidenceFridaPtraceTracerDetected, "ptrace tracer pid: "+strconv.Itoa(tracer))
		}
	}

	if runtime.GOOS == "windows" {
		out, err := exec.Command("tasklist").Output()
		if err == nil {
			tasks := strings.ToLower(string(out))
			for _, marker := range fridaTaskMarkers {
				if strings.Contains(tasks, marker) {
					return makeSignal(ProbeFridaPtrace, true, ConfidenceFridaTasklistDetected, "tasklist marker: "+marker)
				}
			}
		}
	}

	return makeSignal(ProbeFridaPtrace, false, ConfidenceNone, "no frida/ptrace heuristic triggered")
}

func detectLDPreload() AntiTamperSignal {
	return makeSignal(ProbeLDPreload, false, ConfidenceNone, "env-based preload checks disabled")
}

func detectCPUIDHypervisor() AntiTamperSignal {
	sandboxType, confidence, err := DetectSandboxType()
	if err == nil && sandboxType != sandboxTypeNone && confidence >= sandboxDetectedThreshold {
		return makeSignal(ProbeCPUIDHypervisor, true, ConfidenceCPUIDHypervisorDetected, "sandbox_type="+sandboxType)
	}

	return makeSignal(ProbeCPUIDHypervisor, false, ConfidenceNone, "no hypervisor signal")
}

func detectRDTSCDrift() AntiTamperSignal {
	start := time.Now()
	for i := 0; i < RDTSCDriftSleepIterations; i++ {
		time.Sleep(time.Millisecond)
	}
	elapsedMs := int(time.Since(start).Milliseconds())
	drift := elapsedMs - RDTSCDriftSleepIterations
	if drift < 0 {
		drift = -drift
	}

	suspicious := drift > RDTSCDriftThresholdMs
	confidence := ConfidenceNone
	if suspicious {
		confidence = ConfidenceRDTSCDriftSuspicious
	}

	return makeSignal(
		ProbeRDTSCDrift,
		suspicious,
		confidence,
		"sleep_ms="+strconv.Itoa(elapsedMs)+";drift_ms="+strconv.Itoa(drift),
	)
}

func detectACPIPCI() AntiTamperSignal {
	sandboxType, confidence, err := DetectSandboxType()
	if err != nil {
		return makeSignal(ProbeACPIPCI, false, ConfidenceNone, "sandbox detect error: "+err.Error())
	}

	indicators, indicatorsErr := GetSandboxIndicators()
	if indicatorsErr != nil {
		return makeSignal(ProbeACPIPCI, false, ConfidenceNone, "sandbox indicators error: "+indicatorsErr.Error())
	}

	detail := "no sandbox indicators"
	if len(indicators) > 0 {
		detail = "indicators=" + strings.Join(indicators, ";")
	}

	if sandboxType != sandboxTypeNone && confidence > 0 {
		score := confidence
		if score > ACPIPCIConfidenceCap {
			score = ACPIPCIConfidenceCap
		}
		if score < ACPIPCIConfidenceMin {
			score = ACPIPCIConfidenceMin
		}
		return makeSignal(ProbeACPIPCI, true, score, "sandbox_type="+sandboxType+";"+detail)
	}

	return makeSignal(ProbeACPIPCI, false, ConfidenceNone, detail)
}

func readLinuxTracerPID() (int, bool) {
	if runtime.GOOS != "linux" {
		return 0, false
	}

	status, err := os.ReadFile(LinuxProcSelfStatusPath)
	if err != nil {
		return 0, false
	}

	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "TracerPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		pid, parseErr := strconv.Atoi(fields[1])
		if parseErr != nil {
			return 0, false
		}
		return pid, true
	}

	return 0, false
}
