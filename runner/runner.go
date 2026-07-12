package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"mutant/builtin"
	"mutant/compiler"
	"mutant/errrs"
	"mutant/global"
	"mutant/object"
	luaruntime "mutant/runtime/lua"
	"mutant/security"
	"mutant/vm"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

var (
	isDebuggerPresent    = security.IsDebuggerPresent
	isSandboxed          = security.IsSandboxed
	executeLuaPatches    = luaruntime.ExecutePatches
	runAntiTamperProbe   = security.RunAntiTamperProbe
	runRemoteProcessScan = security.RunRemoteProcessScan
)

const processProtectionTerminateConfidence = 80

func Run(srcpath string, password string, secureMode bool, enforceSignerAuth bool) (error, errrs.ErrorType) {
	telemetryPath := os.Getenv(security.SecurityTelemetryFileEnv)
	if telemetryPath != "" {
		defer func() {
			_ = security.ExportSecurityTelemetry(telemetryPath)
		}()
	}

	signedCode, err := os.ReadFile(srcpath)
	if err != nil {
		return err, errrs.ERROR
	}

	signedCode, err = extractStandaloneSignedCode(signedCode)
	if err != nil {
		return err, errrs.ERROR
	}
	defer security.SecureZero(signedCode)

	if secureMode && enforceSignerAuth {
		trustedPublicKey, generated, keyDir, keyErr := security.ResolveTrustedPublicKeyHex()
		if keyErr != nil {
			return fmt.Errorf("failed to resolve trusted public key: %w", keyErr), errrs.ERROR
		}

		if generated {
			privatePath, publicPath := security.LocalKeyPairPaths(keyDir)
			fmt.Fprintf(os.Stderr,
				"[security] generated local keypair for secure mode bootstrap\n[security] private=%s\n[security] public=%s\n[security] optional: set %s to the public key for explicit pinning\n",
				filepath.Clean(privatePath),
				filepath.Clean(publicPath),
				security.TrustedPublicKeyEnv,
			)
		}

		if err := security.VerifyCodeWithTrustedPublicKey(signedCode, trustedPublicKey); err != nil {
			security.RecordSignatureFailure("secure-mode-verify")
			if responseErr := security.ApplyTamperResponse("signature_failed", "secure-mode-verify", secureMode, err); responseErr != nil {
				return responseErr, errrs.ERROR
			}
		}
	} else if !secureMode {
		if err := security.VerifyCode(signedCode); err != nil {
			security.RecordSignatureFailure("compat-mode-verify")
			if responseErr := security.ApplyTamperResponse("signature_failed", "compat-mode-verify", secureMode, err); responseErr != nil {
				return responseErr, errrs.ERROR
			}
		}
	}

	if err := enforceAntiRev(secureMode, "pre-decode"); err != nil {
		return err, errrs.ERROR
	}

	bytecode, err := decode(signedCode, password)
	if err != nil {
		return err, errrs.ERROR
	}

	if err := enforceAntiRev(secureMode, "pre-execution"); err != nil {
		return err, errrs.ERROR
	}

	return runvm(bytecode, password, secureMode)
}

func enforceAntiRev(secureMode bool, stage string) error {
	if err := enforceAntiDebug(secureMode, stage); err != nil {
		return err
	}
	if err := enforceAntiSandbox(secureMode, stage); err != nil {
		return err
	}
	if err := enforceProcessProtection(secureMode, stage); err != nil {
		return err
	}
	if err := enforceRemoteProcessProtection(secureMode, stage); err != nil {
		return err
	}
	return nil
}

func enforceAntiDebug(secureMode bool, stage string) error {
	if !isDebuggerPresent() {
		return nil
	}
	security.RecordDebuggerDetected(stage)

	return security.ApplyTamperResponse("debugger_detected", stage, secureMode, security.ErrDebuggerDetected)
}

func enforceAntiSandbox(secureMode bool, stage string) error {
	if !isSandboxed() {
		return nil
	}
	security.RecordSandboxDetected(stage)

	return security.ApplyTamperResponse("sandbox_detected", stage, secureMode, security.ErrSandboxDetected)
}

func enforceProcessProtection(secureMode bool, stage string) error {
	if !isProcessProtectionEnabled() {
		return nil
	}

	probes := []string{"process_injection", "trampoline", "iat_got", "module_integrity", "memory_page_anomaly"}
	signals, enabled, err := runAntiTamperProbe(probes, "runner:"+stage)
	if err != nil {
		security.RecordProbeError("runner:" + stage)
		return nil
	}
	if !enabled {
		return nil
	}

	for _, signal := range signals {
		if !signal.Detected || signal.Confidence < processProtectionTerminateConfidence {
			continue
		}

		security.RecordProcessProtectionDetected(stage)
		return security.ApplyTamperResponse(
			"process_protection_detected",
			stage,
			secureMode,
			security.ErrProcessProtectionDetected,
		)
	}

	return nil
}

func isProcessProtectionEnabled() bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(security.ProcessProtectionEnabledEnv)))
	if raw == "" {
		return true
	}

	switch raw {
	case "0", "false", "off", "no":
		return false
	default:
		return true
	}
}

func enforceRemoteProcessProtection(secureMode bool, stage string) error {
	verdicts, enabled, err := runRemoteProcessScan("runner:" + stage)
	if err != nil || !enabled {
		return nil
	}
	cfg := security.ResolveRemoteScanConfig()
	if cfg.Mode != security.RemoteScanModeEnforce {
		return nil
	}

	for _, verdict := range verdicts {
		if verdict.FinalScore < cfg.CriticalScore {
			continue
		}

		security.RecordProcessProtectionDetected(stage)
		return security.ApplyTamperResponse(
			"remote_process_protection_detected",
			stage,
			secureMode,
			security.ErrProcessProtectionDetected,
		)
	}

	return nil
}

func decode(data []byte, password string) (*compiler.ByteCode, error) {
	decodedData, err := decryptCode(data, password)
	if err != nil {
		return nil, err
	}
	defer security.SecureZero(decodedData)

	inflatedData, err := maybeDecompressEncodedByteCode(decodedData)
	if err != nil {
		return nil, err
	}
	defer security.SecureZero(inflatedData)

	reader := bytes.NewReader(inflatedData)

	var bytecode *compiler.ByteCode
	registerTypes()
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&bytecode); err != nil {
		return nil, err
	}

	return bytecode, nil
}

func maybeDecompressEncodedByteCode(data []byte) ([]byte, error) {
	if len(data) < 4 || data[0] != 0x28 || data[1] != 0xb5 || data[2] != 0x2f || data[3] != 0xfd {
		return data, nil
	}

	decoder, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()

	inflated, err := io.ReadAll(decoder)
	if err != nil {
		return nil, err
	}

	return inflated, nil
}

func decryptCode(signedCode []byte, password string) ([]byte, error) {
	encryptedMetadata := security.GetEncryptedCode(signedCode)

	// Decrypt using the new secure method
	var xorEncryptedData []byte
	var err error

	xorEncryptedData, err = security.AESDecrypt(encryptedMetadata, password)
	if err != nil {
		return nil, err
	}
	defer security.SecureZero(xorEncryptedData)

	// Decrypt the XOR layer (key is embedded in the data)
	decodedData, err := security.SecureXORDecrypt(xorEncryptedData)
	if err != nil {
		return nil, err
	}

	return decodedData, nil
}

func extractStandaloneSignedCode(binaryData []byte) ([]byte, error) {
	payload, found, err := validateStandalonePayload(binaryData)
	if err != nil {
		return nil, err
	}
	if !found {
		return binaryData, nil
	}

	return payload, nil
}

func HasStandalonePayload(srcpath string) (bool, error) {
	binaryData, err := os.ReadFile(srcpath)
	if err != nil {
		return false, err
	}

	_, found, err := validateStandalonePayload(binaryData)
	if err != nil {
		return false, err
	}

	return found, nil
}

func validateStandalonePayload(binaryData []byte) ([]byte, bool, error) {
	if payload, found, err := validateStandaloneTrailer(binaryData, security.StandaloneTailV3, security.StandaloneTailV3Size); found || err != nil {
		return payload, found, err
	}

	if payload, found, err := validateStandaloneTrailer(binaryData, security.StandaloneTailV2, security.StandaloneTailV2Size); found || err != nil {
		return payload, found, err
	}

	return validateStandaloneTrailer(binaryData, security.StandaloneTailV1, security.StandaloneTailV1Size)
}

func validateStandaloneTrailer(binaryData []byte, version byte, trailerSize int) ([]byte, bool, error) {
	if len(binaryData) < trailerSize {
		return nil, false, nil
	}

	trailerStart := len(binaryData) - trailerSize
	trailer := binaryData[trailerStart:]
	markerBytes := []byte(security.StandaloneTailMarker)
	if !bytes.Equal(trailer[:len(markerBytes)], markerBytes) {
		return nil, false, nil
	}

	versionOffset := len(markerBytes)
	if trailer[versionOffset] != version {
		return nil, true, fmt.Errorf("unsupported standalone trailer version: %d", trailer[versionOffset])
	}

	lengthStart := versionOffset + 1
	lengthEnd := lengthStart + 8
	payloadLength := binary.BigEndian.Uint64(trailer[lengthStart:lengthEnd])
	if payloadLength == 0 {
		return nil, true, errors.New("invalid standalone payload length: 0")
	}
	if payloadLength > uint64(trailerStart) {
		return nil, true, fmt.Errorf("invalid standalone payload length: %d", payloadLength)
	}

	payloadStart := trailerStart - int(payloadLength)
	payload := binaryData[payloadStart:trailerStart]
	checksumStart := lengthEnd
	checksumEnd := checksumStart + sha256.Size
	expectedChecksum := trailer[checksumStart:checksumEnd]
	actualChecksum := sha256.Sum256(payload)
	if !bytes.Equal(expectedChecksum, actualChecksum[:]) {
		return nil, true, errors.New("standalone payload checksum mismatch")
	}

	if version == security.StandaloneTailV2 {
		canary := trailer[checksumEnd:]
		expectedCanary := deriveStandaloneTailCanary(payload, expectedChecksum)
		if !bytes.Equal(canary, expectedCanary) {
			return nil, true, errors.New("standalone payload canary mismatch")
		}
	}

	if version == security.StandaloneTailV3 {
		canary := trailer[checksumEnd : checksumEnd+8]
		profileOffset := checksumEnd + 8
		profileCode := trailer[profileOffset]
		provenance := trailer[profileOffset+1:]

		if _, ok := security.ProtectionProfileFromCode(profileCode); !ok {
			return nil, true, fmt.Errorf("invalid standalone protection profile code: %d", profileCode)
		}

		expectedCanary := deriveStandaloneTailCanary(payload, expectedChecksum)
		if !bytes.Equal(canary, expectedCanary) {
			return nil, true, errors.New("standalone payload canary mismatch")
		}

		expectedProvenance := security.DeriveStandaloneProvenance(payload, expectedChecksum, profileCode)
		if !bytes.Equal(provenance, expectedProvenance[:]) {
			return nil, true, errors.New("standalone payload provenance mismatch")
		}
	}

	return payload, true, nil
}

func deriveStandaloneTailCanary(payload []byte, checksum []byte) []byte {
	seed := make([]byte, 0, len(payload)+len(checksum)+len(security.StandaloneTailMarker)+1)
	seed = append(seed, payload...)
	seed = append(seed, checksum...)
	seed = append(seed, []byte(security.StandaloneTailMarker)...)
	seed = append(seed, security.StandaloneTailV2)
	digest := sha256.Sum256(seed)
	return digest[:8]
}

func runvm(bytecode *compiler.ByteCode, password string, secureMode bool) (error, errrs.ErrorType) {
	if err := executeLuaPatchesBeforeVM(bytecode, password, secureMode); err != nil {
		return err, errrs.ERROR
	}

	globals := make([]object.Object, global.GlobalSize)
	machine := vm.NewWithPasswordAndGlobalStoreMode(bytecode, password, globals, secureMode)
	defer machine.CleanupSensitiveData(true)

	if err := machine.Run(); err != nil {
		return err, errrs.VM_ERROR
	}

	last := machine.LastPoppedStackElement()
	if multi, ok := last.(*object.MultiValue); ok && multi.IsVoid() {
		return nil, ""
	}
	io.WriteString(os.Stdout, last.Inspect())
	io.WriteString(os.Stdout, "\n")

	return nil, ""
}

func executeLuaPatchesBeforeVM(bytecode *compiler.ByteCode, password string, secureMode bool) error {
	if bytecode == nil || len(bytecode.LuaPatches) == 0 {
		return nil
	}

	ctx := &luaruntime.APIContext{
		Globals:             map[string]object.Object{},
		BuiltinCapabilities: resolveLuaBuiltinCapabilities(),
	}

	if err := executeLuaPatches(bytecode.LuaPatches, password, len(bytecode.Instructions), ctx); err != nil {
		security.RecordIntegrityFailure("lua-patch-execution")
		return security.ApplyTamperResponse("lua_patch_failed", "pre-vm", secureMode, err)
	}

	return nil
}

func resolveLuaBuiltinCapabilities() []string {
	defaults := security.DefaultBuiltinCapabilityPolicy()
	caps := make([]string, 0, len(defaults))
	for capability := range defaults {
		caps = append(caps, capability)
	}
	return caps
}

func registerTypes() {
	gob.Register(&object.Float{})
	gob.Register(&object.Integer{})
	gob.Register(&object.Boolean{})
	gob.Register(&object.Null{})
	gob.Register(&object.ReturnValue{})
	gob.Register(&object.MultiValue{})
	gob.Register(&object.Error{})
	gob.Register(&object.Function{})
	gob.Register(&object.String{})
	gob.Register(&builtin.BuiltIn{})
	gob.Register(&object.Array{})
	gob.Register(&object.Hash{})
	gob.Register(&object.Quote{})
	gob.Register(&object.Macro{})
	gob.Register(&object.CompiledFunction{})
	gob.Register(&object.Closure{})
	gob.Register(&object.Encrypted{})
	gob.Register(&object.Struct{})
	gob.Register(&object.EnumValue{})
	gob.Register(&object.LuaPatch{})
}
