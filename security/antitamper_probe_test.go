package security

import "testing"

func TestRunAntiTamperProbeDisabled(t *testing.T) {
	ResetSecurityTelemetry()
	SetAntiTamperProbeEnabledForTesting(false)
	defer SetAntiTamperProbeEnabledForTesting(true)

	signals, enabled, err := RunAntiTamperProbe([]string{ProbeCPUIDHypervisor}, "test-disabled")
	if err != nil {
		t.Fatalf("expected nil error when anti-tamper probe disabled, got: %v", err)
	}
	if enabled {
		t.Fatalf("expected enabled=false")
	}
	if len(signals) != 0 {
		t.Fatalf("expected no signals, got %d", len(signals))
	}

	snapshot := SecurityTelemetrySnapshot()
	if snapshot["anti_tamper_probe_invoked"] != 0 || snapshot["anti_tamper_probe_error"] != 0 {
		t.Fatalf("expected no telemetry changes when disabled, got %+v", snapshot)
	}
}

func TestRunAntiTamperProbeEnabled(t *testing.T) {
	ResetSecurityTelemetry()
	SetAntiTamperProbeEnabledForTesting(true)

	signals, enabled, err := RunAntiTamperProbe([]string{ProbeCPUIDHypervisor}, "test-enabled")
	if !enabled {
		t.Fatalf("expected enabled=true")
	}
	if err != nil {
		t.Fatalf("expected nil error with native go probe engine, got: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected one signal, got %d", len(signals))
	}
	if signals[0].Name != ProbeCPUIDHypervisor {
		t.Fatalf("expected %s signal, got %q", ProbeCPUIDHypervisor, signals[0].Name)
	}

	snapshot := SecurityTelemetrySnapshot()
	if snapshot["anti_tamper_probe_invoked"] != 1 {
		t.Fatalf("expected anti_tamper_probe_invoked=1, got %d", snapshot["anti_tamper_probe_invoked"])
	}
	if snapshot["anti_tamper_probe_error"] != 0 {
		t.Fatalf("expected anti_tamper_probe_error=0, got %d", snapshot["anti_tamper_probe_error"])
	}
}

func TestRunAntiTamperProbeRoutesProcessProtectionSignals(t *testing.T) {
	requested := []string{ProbeProcessInjection, ProbeTrampoline, ProbeIATGOT, ProbeModuleIntegrity, ProbeMemoryPageAnomaly, ProbeSyscallTable}
	signals, enabled, err := RunAntiTamperProbe(requested, "test-process-protection")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if !enabled {
		t.Fatalf("expected enabled=true")
	}
	if len(signals) != len(requested) {
		t.Fatalf("expected %d signals, got %d", len(requested), len(signals))
	}

	for i, signal := range signals {
		if signal.Name != requested[i] {
			t.Fatalf("unexpected signal name at index %d: got=%q want=%q", i, signal.Name, requested[i])
		}
	}
}

func TestRunAntiTamperProbeRoutesAllSupportedNames(t *testing.T) {
	requested := append([]string(nil), AntiTamperSupportedProbes...)
	signals, enabled, err := RunAntiTamperProbe(requested, "test-all-supported")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if !enabled {
		t.Fatalf("expected enabled=true")
	}
	if len(signals) != len(requested) {
		t.Fatalf("expected %d signals, got %d", len(requested), len(signals))
	}

	for i, signal := range signals {
		if signal.Name != requested[i] {
			t.Fatalf("unexpected signal name at index %d: got=%q want=%q", i, signal.Name, requested[i])
		}
	}
}
