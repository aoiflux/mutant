package builtin

import (
	"testing"

	"mutant/object"
	"mutant/security"
)

func TestDebugStatusBuiltin(t *testing.T) {
	security.ResetSecurityTelemetry()

	result := DebugStatus()
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("debug_status() result is not Hash. got=%T", payload)
	}

	assertHashHasKeyType(t, hash, "detected", object.BOOLEAN_OBJ)
	assertHashHasKeyType(t, hash, "type", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "confidence", object.INTEGER_OBJ)
	assertHashHasKeyType(t, hash, "indicators", object.ARRAY_OBJ)
	assertHashHasKeyType(t, hash, "probe_signals", object.ARRAY_OBJ)
	assertHashHasKeyType(t, hash, "probe_enabled", object.BOOLEAN_OBJ)
	assertHashHasKeyType(t, hash, "probe_error", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "source", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "advisory", object.BOOLEAN_OBJ)
	assertHashHasKeyType(t, hash, "event_count", object.INTEGER_OBJ)
	assertHashHasKeyType(t, hash, "error", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "schema_version", object.INTEGER_OBJ)
}

func TestSandboxStatusBuiltin(t *testing.T) {
	security.ResetSecurityTelemetry()

	result := SandboxStatus()
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("sandbox_status() result is not Hash. got=%T", payload)
	}

	assertHashHasKeyType(t, hash, "detected", object.BOOLEAN_OBJ)
	assertHashHasKeyType(t, hash, "type", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "confidence", object.INTEGER_OBJ)
	assertHashHasKeyType(t, hash, "indicators", object.ARRAY_OBJ)
	assertHashHasKeyType(t, hash, "probe_signals", object.ARRAY_OBJ)
	assertHashHasKeyType(t, hash, "probe_enabled", object.BOOLEAN_OBJ)
	assertHashHasKeyType(t, hash, "probe_error", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "source", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "advisory", object.BOOLEAN_OBJ)
	assertHashHasKeyType(t, hash, "event_count", object.INTEGER_OBJ)
	assertHashHasKeyType(t, hash, "error", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "schema_version", object.INTEGER_OBJ)
}

func TestSecurityDiagnosticsBuiltin(t *testing.T) {
	security.ResetSecurityTelemetry()

	result := SecurityDiagnostics()
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("security_diagnostics() result is not Hash. got=%T", payload)
	}

	assertHashHasKeyType(t, hash, "debugger", object.HASH_OBJ)
	assertHashHasKeyType(t, hash, "sandbox", object.HASH_OBJ)
	assertHashHasKeyType(t, hash, "source", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "schema_version", object.INTEGER_OBJ)

	debuggerHash := getHashField(t, hash, "debugger")
	assertHashHasKeyType(t, debuggerHash, "detected", object.BOOLEAN_OBJ)
	assertHashHasKeyType(t, debuggerHash, "methods", object.ARRAY_OBJ)
	assertHashHasKeyType(t, debuggerHash, "event_count", object.INTEGER_OBJ)
	assertHashHasKeyType(t, debuggerHash, "schema_version", object.INTEGER_OBJ)

	sandboxHash := getHashField(t, hash, "sandbox")
	assertHashHasKeyType(t, sandboxHash, "detected", object.BOOLEAN_OBJ)
	assertHashHasKeyType(t, sandboxHash, "type", object.STRING_OBJ)
	assertHashHasKeyType(t, sandboxHash, "confidence", object.INTEGER_OBJ)
	assertHashHasKeyType(t, sandboxHash, "indicators", object.ARRAY_OBJ)
	assertHashHasKeyType(t, sandboxHash, "event_count", object.INTEGER_OBJ)
	assertHashHasKeyType(t, sandboxHash, "error", object.STRING_OBJ)
	assertHashHasKeyType(t, sandboxHash, "schema_version", object.INTEGER_OBJ)
}

func TestSecurityStatusBuiltinWrongArgs(t *testing.T) {
	debugErr := DebugStatus(&object.Integer{Value: 1})
	_, debugErrObj := unwrapPair(t, debugErr)
	if debugErrObj == nil {
		t.Fatalf("expected error for debug_status wrong args")
	}

	sandboxErr := SandboxStatus(&object.Integer{Value: 1})
	_, sandboxErrObj := unwrapPair(t, sandboxErr)
	if sandboxErrObj == nil {
		t.Fatalf("expected error for sandbox_status wrong args")
	}

	diagnosticsErr := SecurityDiagnostics(&object.Integer{Value: 1})
	_, diagnosticsErrObj := unwrapPair(t, diagnosticsErr)
	if diagnosticsErrObj == nil {
		t.Fatalf("expected error for security_diagnostics wrong args")
	}
}

func getHashField(t *testing.T, h *object.Hash, key string) *object.Hash {
	t.Helper()

	keyObj := &object.String{Value: key}
	pair, ok := h.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing key %q", key)
	}

	value, ok := pair.Value.(*object.Hash)
	if !ok {
		t.Fatalf("key %q is not Hash. got=%T", key, pair.Value)
	}

	return value
}

func assertHashHasKeyType(t *testing.T, h *object.Hash, key string, expected object.ObjectType) {
	t.Helper()

	keyObj := &object.String{Value: key}
	pair, ok := h.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing key %q", key)
	}

	if pair.Value.Type() != expected {
		t.Fatalf("wrong value type for key %q. got=%s, want=%s", key, pair.Value.Type(), expected)
	}
}
