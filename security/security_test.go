package security

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestIsDebuggerPresent tests basic debugger detection
func TestIsDebuggerPresent(t *testing.T) {
	// This test simply calls the function and logs the result
	// It should return false when running normally (not under a debugger)
	result := IsDebuggerPresent()

	t.Logf("IsDebuggerPresent() returned: %v", result)

	// We don't assert a specific value because it depends on test environment
	// If running under a debugger (e.g., delve), it should be true
	// If running normally, it should be false
}

// TestSecureCompare tests constant-time comparison
func TestSecureCompare(t *testing.T) {
	a := []byte("password123")
	b := []byte("password123")
	c := []byte("password456")

	// Should return true
	if !SecureCompare(a, b) {
		t.Error("SecureCompare failed for equal values")
	}

	// Should return false
	if SecureCompare(a, c) {
		t.Error("SecureCompare returned true for different values")
	}
}

// TestSecureZero tests memory zeroing
func TestSecureZero(t *testing.T) {
	data := []byte("sensitive data")

	// Verify data is not zero
	for _, b := range data {
		if b == 0 {
			t.Error("Data already contains zeros before zeroing")
			break
		}
	}

	// Zero the data
	SecureZero(data)

	// Verify all bytes are zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d was not zeroed: %d", i, b)
		}
	}
}

// TestSecureRandBytes tests secure random generation
func TestSecureRandBytes(t *testing.T) {
	size := 32
	bytes1, err := SecureRandBytes(size)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}

	bytes2, err := SecureRandBytes(size)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}

	// Should be different
	if string(bytes1) == string(bytes2) {
		t.Error("Two random byte sequences are identical (extremely unlikely)")
	}

	// Should be correct length
	if len(bytes1) != size {
		t.Errorf("Expected %d bytes, got %d", size, len(bytes1))
	}
}

// BenchmarkSecureCompare benchmarks constant-time comparison
func BenchmarkSecureCompare(b *testing.B) {
	a := []byte("this is a test password")
	c := []byte("this is a test password")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SecureCompare(a, c)
	}
}

func TestVerifyCodeWithTrustedPublicKey(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	payload := "test-payload"
	signedCode, err := SignCode(payload, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	trustedPublicKeyHex := hex.EncodeToString(keyPair.PublicKey)
	if err := VerifyCodeWithTrustedPublicKey(signedCode, trustedPublicKeyHex); err != nil {
		t.Fatalf("expected trusted verification success, got: %v", err)
	}
}

func TestVerifyCodeWithTrustedPublicKeyRejectsUntrustedSigner(t *testing.T) {
	trustedKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate trusted key pair: %v", err)
	}

	untrustedKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate untrusted key pair: %v", err)
	}

	signedCode, err := SignCode("tampered-payload", untrustedKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	trustedPublicKeyHex := hex.EncodeToString(trustedKeyPair.PublicKey)
	err = VerifyCodeWithTrustedPublicKey(signedCode, trustedPublicKeyHex)
	if !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("expected ErrUntrustedSigner, got: %v", err)
	}
}

func TestVerifyCodeWithTrustedPublicKeyRequiresTrustedKey(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	signedCode, err := SignCode("payload", keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	if err := VerifyCodeWithTrustedPublicKey(signedCode, ""); err == nil {
		t.Fatalf("expected error when trusted public key is empty")
	}
}

func TestValidateArgon2Params(t *testing.T) {
	if err := ValidateArgon2Params(DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads); err != nil {
		t.Fatalf("expected default params to be valid, got: %v", err)
	}

	if err := ValidateArgon2Params(0, DefaultArgon2Memory, DefaultArgon2Threads); err == nil {
		t.Fatalf("expected invalid time to be rejected")
	}

	if err := ValidateArgon2Params(DefaultArgon2Time, MinArgon2Memory-1, DefaultArgon2Threads); err == nil {
		t.Fatalf("expected invalid memory to be rejected")
	}

	if err := ValidateArgon2Params(DefaultArgon2Time, DefaultArgon2Memory, 0); err == nil {
		t.Fatalf("expected invalid threads to be rejected")
	}
}

func TestSecureXORRoundTrip(t *testing.T) {
	plain := []byte("hello-secure-stream")
	seed := int64(12345)
	password := "Str0ng!Passw0rd"

	enc, err := SecureXOR(plain, seed, password)
	if err != nil {
		t.Fatalf("SecureXOR encrypt failed: %v", err)
	}

	dec, err := SecureXOR(enc, seed, password)
	if err != nil {
		t.Fatalf("SecureXOR decrypt failed: %v", err)
	}

	if !reflect.DeepEqual(plain, dec) {
		t.Fatalf("round-trip mismatch: got=%q want=%q", string(dec), string(plain))
	}
}

func TestSecureXOROneAtMatchesSliceDecrypt(t *testing.T) {
	plain := []byte("offset-sensitive-bytes")
	seed := int64(999)
	password := "Str0ng!Passw0rd"

	enc, err := SecureXOR(plain, seed, password)
	if err != nil {
		t.Fatalf("SecureXOR encrypt failed: %v", err)
	}

	for i := range plain {
		decByte, err := SecureXOROneAt(enc[i], seed, password, int64(i))
		if err != nil {
			t.Fatalf("SecureXOROneAt failed at index %d: %v", i, err)
		}
		if decByte != plain[i] {
			t.Fatalf("byte mismatch at index %d: got=%d want=%d", i, decByte, plain[i])
		}
	}
}

func TestSecurityTelemetryCounters(t *testing.T) {
	ResetSecurityTelemetry()

	RecordDebuggerDetected("test-stage")
	RecordIntegrityFailure("test-stage")
	RecordSignatureFailure("test-stage")
	RecordSandboxDetected("test-stage")
	RecordProbeInvoked("test-stage")
	RecordProbeError("test-stage")

	snapshot := SecurityTelemetrySnapshot()
	if snapshot["debugger_detected"] != 1 {
		t.Fatalf("expected debugger_detected=1, got %d", snapshot["debugger_detected"])
	}
	if snapshot["integrity_failed"] != 1 {
		t.Fatalf("expected integrity_failed=1, got %d", snapshot["integrity_failed"])
	}
	if snapshot["signature_failed"] != 1 {
		t.Fatalf("expected signature_failed=1, got %d", snapshot["signature_failed"])
	}
	if snapshot["sandbox_detected"] != 1 {
		t.Fatalf("expected sandbox_detected=1, got %d", snapshot["sandbox_detected"])
	}
	if snapshot["anti_tamper_probe_invoked"] != 1 {
		t.Fatalf("expected anti_tamper_probe_invoked=1, got %d", snapshot["anti_tamper_probe_invoked"])
	}
	if snapshot["anti_tamper_probe_error"] != 1 {
		t.Fatalf("expected anti_tamper_probe_error=1, got %d", snapshot["anti_tamper_probe_error"])
	}
	if snapshot["anti_tamper_probe_invoked"] != 1 {
		t.Fatalf("expected anti_tamper_probe_invoked=1, got %d", snapshot["anti_tamper_probe_invoked"])
	}
	if snapshot["anti_tamper_probe_error"] != 1 {
		t.Fatalf("expected anti_tamper_probe_error=1, got %d", snapshot["anti_tamper_probe_error"])
	}

	ResetSecurityTelemetry()
	snapshot = SecurityTelemetrySnapshot()
	if snapshot["debugger_detected"] != 0 || snapshot["integrity_failed"] != 0 || snapshot["signature_failed"] != 0 || snapshot["sandbox_detected"] != 0 || snapshot["anti_tamper_probe_invoked"] != 0 || snapshot["anti_tamper_probe_error"] != 0 {
		t.Fatalf("expected counters to reset to zero, got %+v", snapshot)
	}
}

func TestSecurityTelemetryJSONAndExport(t *testing.T) {
	ResetSecurityTelemetry()
	RecordDebuggerDetected("test-stage")
	RecordIntegrityFailure("test-stage")

	jsonBytes, err := SecurityTelemetryJSON()
	if err != nil {
		t.Fatalf("expected telemetry json, got error: %v", err)
	}

	var snapshot map[string]uint64
	if err := json.Unmarshal(jsonBytes, &snapshot); err != nil {
		t.Fatalf("expected valid telemetry json, got: %v", err)
	}

	if snapshot["debugger_detected"] != 1 || snapshot["integrity_failed"] != 1 {
		t.Fatalf("unexpected telemetry values: %+v", snapshot)
	}
	if snapshot["sandbox_detected"] != 0 {
		t.Fatalf("expected sandbox_detected=0, got %+v", snapshot)
	}
	if snapshot["anti_tamper_probe_invoked"] != 0 || snapshot["anti_tamper_probe_error"] != 0 {
		t.Fatalf("expected canonical anti-tamper probe counters to be zero, got %+v", snapshot)
	}

	tmpFile := filepath.Join(t.TempDir(), "telemetry.json")
	if err := ExportSecurityTelemetry(tmpFile); err != nil {
		t.Fatalf("expected telemetry export success, got: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed reading exported telemetry: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("expected non-empty telemetry export file")
	}
}

func TestSandboxDetectionAPIs(t *testing.T) {
	typ, confidence, _ := DetectSandboxType()
	if confidence < 0 || confidence > 100 {
		t.Fatalf("expected confidence in [0,100], got %d", confidence)
	}
	if typ == "" {
		t.Fatalf("expected non-empty sandbox type")
	}

	indicators, _ := GetSandboxIndicators()
	for _, indicator := range indicators {
		if indicator == "" {
			t.Fatalf("expected non-empty indicator entries")
		}
	}

	isSandboxed := IsSandboxed()
	if isSandboxed && confidence < sandboxDetectedThreshold {
		t.Fatalf("expected confidence >= %d when sandboxed, got %d", sandboxDetectedThreshold, confidence)
	}
	if !isSandboxed && confidence >= sandboxDetectedThreshold {
		t.Fatalf("expected confidence < %d when not sandboxed, got %d", sandboxDetectedThreshold, confidence)
	}
}

func TestResolveTamperResponseDefaultsAndOverrides(t *testing.T) {
	t.Setenv(ProtectionProfileEnv, "")
	t.Setenv(TamperResponseEnv, "")
	if got := ResolveTamperResponse(true); got != TamperResponseTerminate {
		t.Fatalf("expected secure default terminate, got %q", got)
	}
	if got := ResolveTamperResponse(false); got != TamperResponseWarn {
		t.Fatalf("expected compat default warn, got %q", got)
	}

	t.Setenv(TamperResponseEnv, TamperResponseDelay)
	if got := ResolveTamperResponse(true); got != TamperResponseDelay {
		t.Fatalf("expected override delay, got %q", got)
	}

	t.Setenv(TamperResponseEnv, "invalid")
	if got := ResolveTamperResponse(true); got != TamperResponseTerminate {
		t.Fatalf("expected fallback terminate for invalid override, got %q", got)
	}
}

func TestResolveTamperResponseFollowsProtectionProfile(t *testing.T) {
	t.Setenv(TamperResponseEnv, "")

	t.Setenv(ProtectionProfileEnv, ProtectionProfileMinimal)
	if got := ResolveTamperResponse(true); got != TamperResponseWarn {
		t.Fatalf("expected minimal profile to warn, got %q", got)
	}

	t.Setenv(ProtectionProfileEnv, ProtectionProfileParanoid)
	if got := ResolveTamperResponse(false); got != TamperResponseTerminate {
		t.Fatalf("expected paranoid profile to terminate, got %q", got)
	}
}

func TestDefaultBuiltinCapabilityPolicyFollowsProtectionProfile(t *testing.T) {
	t.Setenv(ProtectionProfileEnv, ProtectionProfileMinimal)
	policy := DefaultBuiltinCapabilityPolicy()
	if _, ok := policy["all"]; !ok {
		t.Fatalf("expected minimal profile to default-allow all builtins")
	}

	t.Setenv(ProtectionProfileEnv, ProtectionProfileStandard)
	policy = DefaultBuiltinCapabilityPolicy()
	if len(policy) != 0 {
		t.Fatalf("expected standard profile to default-deny builtins, got %+v", policy)
	}
}

func TestApplyTamperResponse(t *testing.T) {
	t.Setenv(TamperResponseEnv, TamperResponseWarn)
	if err := ApplyTamperResponse("debugger_detected", "test", true, ErrDebuggerDetected); err != nil {
		t.Fatalf("expected warn mode to continue, got error: %v", err)
	}

	t.Setenv(TamperResponseEnv, TamperResponseDelay)
	t.Setenv(TamperDelayMsEnv, "0")
	if err := ApplyTamperResponse("integrity_failed", "test", true, ErrDebuggerDetected); err != nil {
		t.Fatalf("expected delay mode to continue, got error: %v", err)
	}

	t.Setenv(TamperResponseEnv, TamperResponseTerminate)
	if err := ApplyTamperResponse("signature_failed", "test", true, ErrUntrustedSigner); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("expected terminate mode to return base error, got: %v", err)
	}
}

func TestCompatibilityPolicyMixedArtifacts(t *testing.T) {
	t.Setenv(TamperResponseEnv, "")

	// New-format signed payload should verify successfully.
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	signed, err := SignCode("new-format-payload", keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	trustedPubHex := hex.EncodeToString(keyPair.PublicKey)
	if err := VerifyCodeWithTrustedPublicKey(signed, trustedPubHex); err != nil {
		t.Fatalf("expected secure verification success for new artifact, got: %v", err)
	}

	if err := VerifyCode(signed); err != nil {
		t.Fatalf("expected compatibility verification success for new artifact, got: %v", err)
	}

	// Legacy/malformed artifact should fail verification.
	legacy := []byte("legacy-artifact-format")
	legacyErr := VerifyCode(legacy)
	if legacyErr == nil {
		t.Fatalf("expected legacy artifact to fail compatibility verification")
	}

	// Compatibility mode defaults to warn (continue).
	if err := ApplyTamperResponse("signature_failed", "compat-mode-verify", false, legacyErr); err != nil {
		t.Fatalf("expected compatibility policy to continue on legacy artifact, got: %v", err)
	}

	// Secure mode defaults to terminate.
	if err := ApplyTamperResponse("signature_failed", "secure-mode-verify", true, legacyErr); err == nil {
		t.Fatalf("expected secure policy to terminate on legacy artifact")
	}
}

func TestWindowsAntiDebugSignalWeighting(t *testing.T) {
	if !shouldTriggerDebuggerByWeight(true, 0, 2) {
		t.Fatalf("expected high-confidence hit to trigger detection")
	}

	if shouldTriggerDebuggerByWeight(false, 1, 2) {
		t.Fatalf("expected one weak hit to be insufficient when threshold is 2")
	}

	if !shouldTriggerDebuggerByWeight(false, 2, 2) {
		t.Fatalf("expected two weak hits to trigger when threshold is 2")
	}

	if !shouldTriggerDebuggerByWeight(false, 1, 1) {
		t.Fatalf("expected one weak hit to trigger when threshold is 1")
	}
}
