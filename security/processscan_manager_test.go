package security

import (
	"errors"
	"testing"
)

func TestRunRemoteProcessScanDisabled(t *testing.T) {
	t.Setenv(RemoteProcessScanEnabledEnv, "0")
	ResetSecurityTelemetry()

	called := false
	original := scanRemoteProcesses
	scanRemoteProcesses = func(cfg RemoteScanConfig) ([]ProcessRiskVerdict, error) {
		called = true
		return nil, nil
	}
	defer func() {
		scanRemoteProcesses = original
	}()

	verdicts, enabled, err := RunRemoteProcessScan("test-stage")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if enabled {
		t.Fatalf("expected disabled=false")
	}
	if verdicts != nil {
		t.Fatalf("expected nil verdicts when disabled")
	}
	if called {
		t.Fatalf("scanner should not be called when disabled")
	}

	snap := SecurityTelemetrySnapshot()
	if snap["remote_process_scan_invoked"] != 0 {
		t.Fatalf("expected no invocation counter increment when disabled")
	}
}

func TestRunRemoteProcessScanRecordsTelemetry(t *testing.T) {
	t.Setenv(RemoteProcessScanEnabledEnv, "1")
	t.Setenv(RemoteProcessScanModeEnv, RemoteScanModeObserve)
	ResetSecurityTelemetry()

	original := scanRemoteProcesses
	scanRemoteProcesses = func(cfg RemoteScanConfig) ([]ProcessRiskVerdict, error) {
		return []ProcessRiskVerdict{
			{PID: 10, Name: "a", FinalScore: 72, RiskBand: "high"},
			{PID: 11, Name: "b", FinalScore: 90, RiskBand: "critical"},
		}, nil
	}
	defer func() {
		scanRemoteProcesses = original
	}()

	_, enabled, err := RunRemoteProcessScan("test-stage")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !enabled {
		t.Fatalf("expected enabled=true")
	}

	snap := SecurityTelemetrySnapshot()
	if snap["remote_process_scan_invoked"] != 1 {
		t.Fatalf("expected invoked=1 got=%d", snap["remote_process_scan_invoked"])
	}
	if snap["remote_process_suspicious"] != 1 {
		t.Fatalf("expected suspicious=1 got=%d", snap["remote_process_suspicious"])
	}
	if snap["remote_process_critical"] != 1 {
		t.Fatalf("expected critical=1 got=%d", snap["remote_process_critical"])
	}
}

func TestRunRemoteProcessScanNormalizesVerdictsFromSignals(t *testing.T) {
	t.Setenv(RemoteProcessScanEnabledEnv, "1")
	t.Setenv(RemoteProcessScanModeEnv, RemoteScanModeObserve)
	ResetSecurityTelemetry()

	original := scanRemoteProcesses
	scanRemoteProcesses = func(cfg RemoteScanConfig) ([]ProcessRiskVerdict, error) {
		return []ProcessRiskVerdict{
			{
				PID:  77,
				Name: "proc-a",
				Signals: []RemoteProcessSignal{
					{Detected: true, Weight: 60},
					{Detected: true, Weight: 30},
				},
			},
		}, nil
	}
	defer func() {
		scanRemoteProcesses = original
	}()

	verdicts, enabled, err := RunRemoteProcessScan("test-stage")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !enabled {
		t.Fatalf("expected enabled=true")
	}
	if len(verdicts) != 1 {
		t.Fatalf("expected one verdict, got %d", len(verdicts))
	}
	if verdicts[0].FinalScore != 90 {
		t.Fatalf("expected normalized score=90, got %d", verdicts[0].FinalScore)
	}
	if verdicts[0].RiskBand != "critical" {
		t.Fatalf("expected critical risk band, got %q", verdicts[0].RiskBand)
	}
}

func TestRunRemoteProcessScanError(t *testing.T) {
	t.Setenv(RemoteProcessScanEnabledEnv, "1")
	t.Setenv(RemoteProcessScanModeEnv, RemoteScanModeObserve)
	ResetSecurityTelemetry()

	original := scanRemoteProcesses
	scanRemoteProcesses = func(cfg RemoteScanConfig) ([]ProcessRiskVerdict, error) {
		return nil, errors.New("scan failed")
	}
	defer func() {
		scanRemoteProcesses = original
	}()

	_, enabled, err := RunRemoteProcessScan("test-stage")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !enabled {
		t.Fatalf("expected enabled=true")
	}

	snap := SecurityTelemetrySnapshot()
	if snap["remote_process_scan_error"] != 1 {
		t.Fatalf("expected error counter increment, got=%d", snap["remote_process_scan_error"])
	}
}
