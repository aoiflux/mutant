package lua

import (
	"testing"

	"mutant/object"
	"mutant/security"
)

func TestExecutePatchesRunsEncryptedPatch(t *testing.T) {
	password := "lua-exec-test"
	inslen := 321
	plaintext := []byte("return mutant.patch_name()")

	encrypted, err := security.SecureXOR(plaintext, int64(inslen), password)
	if err != nil {
		t.Fatalf("failed to encrypt patch payload: %v", err)
	}

	patches := map[string]*object.LuaPatch{
		"patch_a": {
			Name:             "patch_a",
			EncryptedPayload: encrypted,
			ChecksumExpected: object.ComputeChecksum(plaintext),
		},
	}

	ctx := &APIContext{
		Globals:             map[string]object.Object{},
		BuiltinCapabilities: []string{"network"},
	}

	if err := ExecutePatches(patches, password, inslen, ctx); err != nil {
		t.Fatalf("expected patch execution to succeed, got: %v", err)
	}
}

func TestExecutePatchesRejectsUnsafeGlobals(t *testing.T) {
	password := "lua-sandbox-test"
	inslen := 123
	plaintext := []byte("return io.open('/tmp/x', 'r')")

	encrypted, err := security.SecureXOR(plaintext, int64(inslen), password)
	if err != nil {
		t.Fatalf("failed to encrypt patch payload: %v", err)
	}

	patches := map[string]*object.LuaPatch{
		"unsafe_patch": {
			Name:             "unsafe_patch",
			EncryptedPayload: encrypted,
			ChecksumExpected: object.ComputeChecksum(plaintext),
		},
	}

	err = ExecutePatches(patches, password, inslen, &APIContext{Globals: map[string]object.Object{}})
	if err == nil {
		t.Fatalf("expected unsafe patch to fail")
	}
}

func TestExecutePatchesRejectsInvalidMetadata(t *testing.T) {
	patches := map[string]*object.LuaPatch{
		"bad": {
			Name:             "",
			EncryptedPayload: []byte{1, 2, 3},
			ChecksumExpected: "abcd",
		},
	}

	err := ExecutePatches(patches, "password", 10, nil)
	if err == nil {
		t.Fatalf("expected invalid metadata to fail")
	}
	if err != ErrLuaPatchExecution {
		t.Fatalf("expected canonical scrubbed error, got: %v", err)
	}
}

func TestExecutePatchesReturnsCanonicalError(t *testing.T) {
	password := "lua-error-test"
	inslen := 123
	plaintext := []byte("error('boom')")

	encrypted, err := security.SecureXOR(plaintext, int64(inslen), password)
	if err != nil {
		t.Fatalf("failed to encrypt patch payload: %v", err)
	}

	patches := map[string]*object.LuaPatch{
		"err_patch": {
			Name:             "err_patch",
			EncryptedPayload: encrypted,
			ChecksumExpected: object.ComputeChecksum(plaintext),
		},
	}

	err = ExecutePatches(patches, password, inslen, &APIContext{Globals: map[string]object.Object{}})
	if err == nil {
		t.Fatalf("expected execution failure")
	}
	if err != ErrLuaPatchExecution {
		t.Fatalf("expected canonical scrubbed error, got: %v", err)
	}
}

func TestSandboxedVMExecutionTimeout(t *testing.T) {
	v := NewSandboxedVM(SandboxConfig{
		MaxMemoryMB:    64,
		MaxExecutionMS: 10,
		AllowedLibs:    []string{"math", "string", "table", "base"},
	})

	if err := v.Open(); err != nil {
		t.Fatalf("failed to open sandbox: %v", err)
	}
	defer v.Close()

	if err := v.LoadBytecode([]byte("while true do end"), "timeout_patch"); err != nil {
		t.Fatalf("failed to load patch source: %v", err)
	}

	_, err := v.Execute()
	if err == nil {
		t.Fatalf("expected timeout error")
	}
}
