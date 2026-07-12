package security

import (
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

const SecurityAuditEnv = "MUTANT_SECURITY_AUDIT"
const SecurityTelemetryFileEnv = "MUTANT_SECURITY_TELEMETRY_FILE"

var (
	telemetryDebuggerDetected uint64
	telemetryIntegrityFailed  uint64
	telemetrySignatureFailed  uint64
	telemetrySandboxDetected  uint64
	telemetryProcessProtect   uint64
	telemetryProbeInvoked     uint64
	telemetryProbeError       uint64
	telemetryRemoteScanInvoke uint64
	telemetryRemoteScanError  uint64
	telemetryRemoteSuspicious uint64
	telemetryRemoteCritical   uint64
	telemetryCommandAttempt   uint64
	telemetryCommandBlocked   uint64
	telemetryCommandSucceeded uint64
	telemetryCommandFailed    uint64
)

func RecordDebuggerDetected(stage string) {
	atomic.AddUint64(&telemetryDebuggerDetected, 1)
	auditEvent("debugger_detected", stage)
}

func RecordIntegrityFailure(stage string) {
	atomic.AddUint64(&telemetryIntegrityFailed, 1)
	auditEvent("integrity_failed", stage)
}

func RecordSignatureFailure(stage string) {
	atomic.AddUint64(&telemetrySignatureFailed, 1)
	auditEvent("signature_failed", stage)
}

func RecordSandboxDetected(stage string) {
	atomic.AddUint64(&telemetrySandboxDetected, 1)
	auditEvent("sandbox_detected", stage)
}

func RecordProcessProtectionDetected(stage string) {
	atomic.AddUint64(&telemetryProcessProtect, 1)
	auditEvent("process_protection_detected", stage)
}

func RecordProbeInvoked(stage string) {
	atomic.AddUint64(&telemetryProbeInvoked, 1)
	auditEvent("anti_tamper_probe_invoked", stage)
}

func RecordProbeError(stage string) {
	atomic.AddUint64(&telemetryProbeError, 1)
	auditEvent("anti_tamper_probe_error", stage)
}

func RecordRemoteProcessScanInvoked(stage string) {
	atomic.AddUint64(&telemetryRemoteScanInvoke, 1)
	auditEvent("remote_process_scan_invoked", stage)
}

func RecordRemoteProcessScanError(stage string) {
	atomic.AddUint64(&telemetryRemoteScanError, 1)
	auditEvent("remote_process_scan_error", stage)
}

func RecordRemoteProcessSuspicious(stage string) {
	atomic.AddUint64(&telemetryRemoteSuspicious, 1)
	auditEvent("remote_process_suspicious", stage)
}

func RecordRemoteProcessCritical(stage string) {
	atomic.AddUint64(&telemetryRemoteCritical, 1)
	auditEvent("remote_process_critical", stage)
}

func RecordCommandAttempt(stage string) {
	atomic.AddUint64(&telemetryCommandAttempt, 1)
	auditEvent("command_attempt", stage)
}

func RecordCommandBlocked(stage string) {
	atomic.AddUint64(&telemetryCommandBlocked, 1)
	auditEvent("command_blocked", stage)
}

func RecordCommandSucceeded(stage string) {
	atomic.AddUint64(&telemetryCommandSucceeded, 1)
	auditEvent("command_succeeded", stage)
}

func RecordCommandFailed(stage string) {
	atomic.AddUint64(&telemetryCommandFailed, 1)
	auditEvent("command_failed", stage)
}

func SecurityTelemetrySnapshot() map[string]uint64 {
	return map[string]uint64{
		"debugger_detected":           atomic.LoadUint64(&telemetryDebuggerDetected),
		"integrity_failed":            atomic.LoadUint64(&telemetryIntegrityFailed),
		"signature_failed":            atomic.LoadUint64(&telemetrySignatureFailed),
		"sandbox_detected":            atomic.LoadUint64(&telemetrySandboxDetected),
		"process_protection_detected": atomic.LoadUint64(&telemetryProcessProtect),
		"anti_tamper_probe_invoked":   atomic.LoadUint64(&telemetryProbeInvoked),
		"anti_tamper_probe_error":     atomic.LoadUint64(&telemetryProbeError),
		"remote_process_scan_invoked": atomic.LoadUint64(&telemetryRemoteScanInvoke),
		"remote_process_scan_error":   atomic.LoadUint64(&telemetryRemoteScanError),
		"remote_process_suspicious":   atomic.LoadUint64(&telemetryRemoteSuspicious),
		"remote_process_critical":     atomic.LoadUint64(&telemetryRemoteCritical),
		"command_attempt":             atomic.LoadUint64(&telemetryCommandAttempt),
		"command_blocked":             atomic.LoadUint64(&telemetryCommandBlocked),
		"command_succeeded":           atomic.LoadUint64(&telemetryCommandSucceeded),
		"command_failed":              atomic.LoadUint64(&telemetryCommandFailed),
	}
}

func SecurityTelemetryJSON() ([]byte, error) {
	snapshot := SecurityTelemetrySnapshot()
	return json.Marshal(snapshot)
}

func ExportSecurityTelemetry(path string) error {
	if path == "" {
		return nil
	}

	data, err := SecurityTelemetryJSON()
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func ResetSecurityTelemetry() {
	atomic.StoreUint64(&telemetryDebuggerDetected, 0)
	atomic.StoreUint64(&telemetryIntegrityFailed, 0)
	atomic.StoreUint64(&telemetrySignatureFailed, 0)
	atomic.StoreUint64(&telemetrySandboxDetected, 0)
	atomic.StoreUint64(&telemetryProcessProtect, 0)
	atomic.StoreUint64(&telemetryProbeInvoked, 0)
	atomic.StoreUint64(&telemetryProbeError, 0)
	atomic.StoreUint64(&telemetryRemoteScanInvoke, 0)
	atomic.StoreUint64(&telemetryRemoteScanError, 0)
	atomic.StoreUint64(&telemetryRemoteSuspicious, 0)
	atomic.StoreUint64(&telemetryRemoteCritical, 0)
	atomic.StoreUint64(&telemetryCommandAttempt, 0)
	atomic.StoreUint64(&telemetryCommandBlocked, 0)
	atomic.StoreUint64(&telemetryCommandSucceeded, 0)
	atomic.StoreUint64(&telemetryCommandFailed, 0)
}

func auditEvent(event, stage string) {
	if os.Getenv(SecurityAuditEnv) != "1" {
		return
	}

	fmt.Fprintf(os.Stderr, "[security-audit] ts=%d event=%s stage=%s\n", time.Now().Unix(), event, stage)
}
