package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/compiler"
	"mutant/errrs"
	"mutant/object"
	"mutant/security"
)

func TestExtractStandaloneSignedCodeValidTrailer(t *testing.T) {
	payload := []byte("signed-payload")
	binaryData := makeStandaloneBinaryBlob(t, payload)

	extracted, err := extractStandaloneSignedCode(binaryData)
	if err != nil {
		t.Fatalf("expected extraction to succeed: %v", err)
	}

	if !bytes.Equal(extracted, payload) {
		t.Fatalf("unexpected payload extracted")
	}
}

func TestExtractStandaloneSignedCodeRejectsChecksumMismatch(t *testing.T) {
	payload := []byte("signed-payload")
	binaryData := makeStandaloneBinaryBlob(t, payload)
	binaryData[len(binaryData)-73] = 0x42

	_, err := extractStandaloneSignedCode(binaryData)
	if err == nil {
		t.Fatalf("expected checksum mismatch error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch error, got: %v", err)
	}
}

func TestExtractStandaloneSignedCodeRejectsCanaryMismatch(t *testing.T) {
	payload := []byte("signed-payload")
	binaryData := makeStandaloneBinaryBlob(t, payload)
	binaryData[len(binaryData)-41] ^= 0x01

	_, err := extractStandaloneSignedCode(binaryData)
	if err == nil {
		t.Fatalf("expected canary mismatch error")
	}
	if !strings.Contains(err.Error(), "canary mismatch") {
		t.Fatalf("expected canary mismatch error, got: %v", err)
	}
}

func TestHasStandalonePayloadReportsPresence(t *testing.T) {
	payload := []byte("signed-payload")
	binaryData := makeStandaloneBinaryBlob(t, payload)

	path := writeTempPayload(t, binaryData)
	hasPayload, err := HasStandalonePayload(path)
	if err != nil {
		t.Fatalf("expected payload check to succeed: %v", err)
	}
	if !hasPayload {
		t.Fatalf("expected standalone payload to be detected")
	}
}

func TestRunSecureModeBootstrapsLocalKeysWhenTrustedEnvMissing(t *testing.T) {
	keyDir := t.TempDir()

	path := writeTempPayload(t, []byte("legacy-format-payload"))
	err, errType := Run(path, "", true, true)
	if err == nil {
		t.Fatalf("expected malformed payload to fail")
	}
	if errType != errrs.ERROR {
		t.Fatalf("expected errrs.ERROR, got %q", errType)
	}
	if !errors.Is(err, security.ErrWrongSignature) {
		t.Fatalf("expected ErrWrongSignature, got: %v", err)
	}

	privatePath := filepath.Join(keyDir, security.LocalSigningPrivateKeyFileName)
	publicPath := filepath.Join(keyDir, security.LocalSigningPublicKeyFileName)

	if _, statErr := os.Stat(privatePath); statErr != nil {
		t.Fatalf("expected bootstrapped private key file: %v", statErr)
	}
	if _, statErr := os.Stat(publicPath); statErr != nil {
		t.Fatalf("expected bootstrapped public key file: %v", statErr)
	}
}

func TestRunCompatModeWarnsAndContinuesOnMalformedPayload(t *testing.T) {
	path := writeTempPayload(t, []byte("legacy-format-payload"))
	err, errType := Run(path, "", false, false)
	if err == nil {
		t.Fatalf("expected compat mode to fail later during decode")
	}
	if errType != errrs.ERROR {
		t.Fatalf("expected errrs.ERROR, got %q", errType)
	}
	if errors.Is(err, security.ErrWrongSignature) {
		t.Fatalf("expected compatibility mode to continue past signature failure")
	}
}

func TestRunSecureModeRejectsTamperedSignedPayload(t *testing.T) {
	keyPair, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	signed, err := security.SignCode("not-valid-metadata", keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	tampered := tamperSignedPublicKey(t, string(signed))
	path := writeTempPayload(t, []byte(tampered))

	err, errType := Run(path, "", true, true)
	if err == nil {
		t.Fatalf("expected secure mode to reject tampered signed payload")
	}
	if errType != errrs.ERROR {
		t.Fatalf("expected errrs.ERROR, got %q", errType)
	}
	if !errors.Is(err, security.ErrUntrustedSigner) {
		t.Fatalf("expected ErrUntrustedSigner, got: %v", err)
	}
}

func TestRunSecureModeAcceptsSignatureThenFailsDecode(t *testing.T) {
	keyPair, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	signed, err := security.SignCode("not-valid-metadata", keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	path := writeTempPayload(t, signed)
	err, errType := Run(path, "", true, true)
	if err == nil {
		t.Fatalf("expected decode failure after signature verification")
	}
	if errType != errrs.ERROR {
		t.Fatalf("expected errrs.ERROR, got %q", errType)
	}
	if errors.Is(err, security.ErrUntrustedSigner) || errors.Is(err, security.ErrWrongSignature) {
		t.Fatalf("expected non-signature decode error after successful signature verification, got: %v", err)
	}
}

func TestRunSecureModeWithoutSignerAuthFlagSkipsSignatureVerification(t *testing.T) {
	path := writeTempPayload(t, []byte("legacy-format-payload"))
	err, errType := Run(path, "", true, false)
	if err == nil {
		t.Fatalf("expected malformed payload to fail decode")
	}
	if errType != errrs.ERROR {
		t.Fatalf("expected errrs.ERROR, got %q", errType)
	}
	if errors.Is(err, security.ErrWrongSignature) || errors.Is(err, security.ErrUntrustedSigner) {
		t.Fatalf("expected secure mode to skip signer verification by default, got: %v", err)
	}
}

func TestExtractStandaloneSignedCodeRejectsProvenanceMismatch(t *testing.T) {
	payload := []byte("signed-payload")
	binaryData := makeStandaloneBinaryBlob(t, payload)
	binaryData[len(binaryData)-1] ^= 0x01

	_, err := extractStandaloneSignedCode(binaryData)
	if err == nil {
		t.Fatalf("expected provenance mismatch error")
	}
	if !strings.Contains(err.Error(), "provenance mismatch") {
		t.Fatalf("expected provenance mismatch error, got: %v", err)
	}
}

func TestEnforceAntiSandboxSecureModeTerminates(t *testing.T) {
	originalSandbox := isSandboxed
	isSandboxed = func() bool { return true }
	defer func() {
		isSandboxed = originalSandbox
	}()

	err := enforceAntiSandbox(true, "test-stage")
	if err == nil {
		t.Fatalf("expected secure mode to terminate on sandbox detection")
	}
	if !errors.Is(err, security.ErrSandboxDetected) {
		t.Fatalf("expected ErrSandboxDetected, got: %v", err)
	}
}

func TestEnforceAntiSandboxCompatModeWarnsAndContinues(t *testing.T) {
	originalSandbox := isSandboxed
	isSandboxed = func() bool { return true }
	defer func() {
		isSandboxed = originalSandbox
	}()

	err := enforceAntiSandbox(false, "test-stage")
	if err != nil {
		t.Fatalf("expected compat warn mode to continue, got: %v", err)
	}
}

func TestEnforceProcessProtectionSecureModeTerminatesOnHighConfidence(t *testing.T) {
	originalProbe := runAntiTamperProbe
	runAntiTamperProbe = func(requested []string, stage string) ([]security.AntiTamperSignal, bool, error) {
		return []security.AntiTamperSignal{{
			Name:       "trampoline",
			Detected:   true,
			Confidence: processProtectionTerminateConfidence,
			Detail:     "test",
		}}, true, nil
	}
	defer func() {
		runAntiTamperProbe = originalProbe
	}()

	err := enforceProcessProtection(true, "test-stage")
	if err == nil {
		t.Fatalf("expected secure mode to terminate on high-confidence process protection signal")
	}
	if !errors.Is(err, security.ErrProcessProtectionDetected) {
		t.Fatalf("expected ErrProcessProtectionDetected, got: %v", err)
	}
}

func TestEnforceProcessProtectionIgnoresLowConfidence(t *testing.T) {
	originalProbe := runAntiTamperProbe
	runAntiTamperProbe = func(requested []string, stage string) ([]security.AntiTamperSignal, bool, error) {
		return []security.AntiTamperSignal{{
			Name:       "process_injection",
			Detected:   true,
			Confidence: processProtectionTerminateConfidence - 1,
			Detail:     "test",
		}}, true, nil
	}
	defer func() {
		runAntiTamperProbe = originalProbe
	}()

	err := enforceProcessProtection(true, "test-stage")
	if err != nil {
		t.Fatalf("expected low-confidence process protection signal to be advisory, got: %v", err)
	}
}

func TestEnforceProcessProtectionDisabledByEnv(t *testing.T) {
	originalProbe := runAntiTamperProbe
	called := false
	runAntiTamperProbe = func(requested []string, stage string) ([]security.AntiTamperSignal, bool, error) {
		called = true
		return []security.AntiTamperSignal{{
			Name:       "trampoline",
			Detected:   true,
			Confidence: processProtectionTerminateConfidence,
			Detail:     "test",
		}}, true, nil
	}
	defer func() {
		runAntiTamperProbe = originalProbe
	}()

	err := enforceProcessProtection(true, "test-stage")
	if err != nil {
		t.Fatalf("expected disabled process protection to skip enforcement, got: %v", err)
	}
	if called {
		t.Fatalf("expected probe not to run when process protection is disabled")
	}
}

func TestIsProcessProtectionEnabledDefaultsToTrue(t *testing.T) {
	if !isProcessProtectionEnabled() {
		t.Fatalf("expected process protection enabled by default")
	}
}

func TestEnforceProcessProtectionGateMatrix(t *testing.T) {
	tests := []struct {
		name            string
		processEnv      string
		probeEnabled    bool
		probeErr        error
		signals         []security.AntiTamperSignal
		expectProbeCall bool
		expectErr       bool
	}{
		{
			name:            "process protection disabled by env",
			processEnv:      "0",
			probeEnabled:    true,
			expectProbeCall: false,
			expectErr:       false,
		},
		{
			name:         "probe framework disabled",
			processEnv:   "1",
			probeEnabled: false,
			signals: []security.AntiTamperSignal{{
				Name:       "trampoline",
				Detected:   true,
				Confidence: processProtectionTerminateConfidence,
			}},
			expectProbeCall: true,
			expectErr:       false,
		},
		{
			name:            "probe returns error",
			processEnv:      "1",
			probeEnabled:    true,
			probeErr:        errors.New("probe failure"),
			expectProbeCall: true,
			expectErr:       false,
		},
		{
			name:         "high confidence signal terminates in secure mode",
			processEnv:   "1",
			probeEnabled: true,
			signals: []security.AntiTamperSignal{{
				Name:       "process_injection",
				Detected:   true,
				Confidence: processProtectionTerminateConfidence,
			}},
			expectProbeCall: true,
			expectErr:       true,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			called := false
			originalProbe := runAntiTamperProbe
			runAntiTamperProbe = func(requested []string, stage string) ([]security.AntiTamperSignal, bool, error) {
				called = true
				return tc.signals, tc.probeEnabled, tc.probeErr
			}
			defer func() {
				runAntiTamperProbe = originalProbe
			}()

			err := enforceProcessProtection(true, "test-stage")
			if tc.expectErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.expectErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if called != tc.expectProbeCall {
				t.Fatalf("probe call mismatch. got=%t want=%t", called, tc.expectProbeCall)
			}
		})
	}
}

func TestEnforceRemoteProcessProtectionObserveDoesNotBlock(t *testing.T) {
	originalScan := runRemoteProcessScan
	runRemoteProcessScan = func(stage string) ([]security.ProcessRiskVerdict, bool, error) {
		return []security.ProcessRiskVerdict{{
			PID:        123,
			Name:       "target",
			FinalScore: 95,
			RiskBand:   "critical",
		}}, true, nil
	}
	defer func() {
		runRemoteProcessScan = originalScan
	}()

	err := enforceRemoteProcessProtection(true, "test-stage")
	if err != nil {
		t.Fatalf("expected observe mode not to block, got: %v", err)
	}
}

func TestEnforceRemoteProcessProtectionScanErrorDoesNotBlock(t *testing.T) {
	originalScan := runRemoteProcessScan
	runRemoteProcessScan = func(stage string) ([]security.ProcessRiskVerdict, bool, error) {
		return nil, true, errors.New("scan failure")
	}
	defer func() {
		runRemoteProcessScan = originalScan
	}()

	err := enforceRemoteProcessProtection(true, "test-stage")
	if err != nil {
		t.Fatalf("expected scan errors to be non-blocking in observe-first mode, got: %v", err)
	}
}

func TestEnforceRemoteProcessProtectionEnforceModeBlocksOnCritical(t *testing.T) {
	originalScan := runRemoteProcessScan
	runRemoteProcessScan = func(stage string) ([]security.ProcessRiskVerdict, bool, error) {
		return []security.ProcessRiskVerdict{{
			PID:        222,
			Name:       "critical-target",
			FinalScore: 95,
			RiskBand:   "critical",
		}}, true, nil
	}
	defer func() {
		runRemoteProcessScan = originalScan
	}()

	err := enforceRemoteProcessProtection(true, "test-stage")
	if err == nil {
		t.Fatalf("expected enforce mode to block on critical verdict")
	}
	if !errors.Is(err, security.ErrProcessProtectionDetected) {
		t.Fatalf("expected ErrProcessProtectionDetected, got: %v", err)
	}
}

func TestEnforceRemoteProcessProtectionEnforceModeHighNonCriticalDoesNotBlock(t *testing.T) {
	originalScan := runRemoteProcessScan
	runRemoteProcessScan = func(stage string) ([]security.ProcessRiskVerdict, bool, error) {
		return []security.ProcessRiskVerdict{{
			PID:        333,
			Name:       "high-target",
			FinalScore: 80,
			RiskBand:   "high",
		}}, true, nil
	}
	defer func() {
		runRemoteProcessScan = originalScan
	}()

	err := enforceRemoteProcessProtection(true, "test-stage")
	if err != nil {
		t.Fatalf("expected non-critical enforce-mode verdict to continue, got: %v", err)
	}
}

func TestExecuteLuaPatchesBeforeVMSucceeds(t *testing.T) {
	plaintext := []byte("return mutant.version()")
	password := "runner-lua-success"
	inslen := 128
	encrypted, err := security.SecureXOR(plaintext, int64(inslen), password)
	if err != nil {
		t.Fatalf("failed to encrypt test patch: %v", err)
	}

	bytecode := &compiler.ByteCode{
		Instructions: make([]byte, inslen),
		LuaPatches: map[string]*object.LuaPatch{
			"ok": {
				Name:             "ok",
				EncryptedPayload: encrypted,
				ChecksumExpected: object.ComputeChecksum(plaintext),
			},
		},
	}

	err = executeLuaPatchesBeforeVM(bytecode, password, true)
	if err != nil {
		t.Fatalf("expected patch execution to succeed, got: %v", err)
	}
}

func writeTempPayload(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "payload-*.mu")
	if err != nil {
		t.Fatalf("failed creating temp payload: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatalf("failed writing temp payload: %v", err)
	}
	return f.Name()
}

func tamperSignedPublicKey(t *testing.T, signed string) string {
	t.Helper()
	parts := strings.Split(signed, security.OUTER_SEPERATOR)
	if len(parts) < 5 {
		t.Fatalf("unexpected signed payload format")
	}
	pub := parts[len(parts)-2]
	if len(pub) == 0 {
		t.Fatalf("unexpected empty public key")
	}
	if pub[0] == 'a' {
		pub = "b" + pub[1:]
	} else {
		pub = "a" + pub[1:]
	}
	parts[len(parts)-2] = pub
	return strings.Join(parts, security.OUTER_SEPERATOR)
}

func toHex(t *testing.T, b []byte) string {
	t.Helper()
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}

func makeStandaloneBinaryBlob(t *testing.T, payload []byte) []byte {
	t.Helper()
	prefix := []byte("runtime-binary")
	checksum := sha256.Sum256(payload)
	canary := deriveStandaloneTailCanary(payload, checksum[:])
	profileCode := security.ResolveProtectionProfileCode()
	provenance := security.DeriveStandaloneProvenance(payload, checksum[:], profileCode)

	trailer := make([]byte, 0, security.StandaloneTailV3Size)
	trailer = append(trailer, []byte(security.StandaloneTailMarker)...)
	trailer = append(trailer, security.StandaloneTailV3)

	lenBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBuf, uint64(len(payload)))
	trailer = append(trailer, lenBuf...)
	trailer = append(trailer, checksum[:]...)
	trailer = append(trailer, canary...)
	trailer = append(trailer, profileCode)
	trailer = append(trailer, provenance[:]...)

	blob := make([]byte, 0, len(prefix)+len(payload)+len(trailer))
	blob = append(blob, prefix...)
	blob = append(blob, payload...)
	blob = append(blob, trailer...)

	return blob
}
