package builtin

import (
	"testing"

	"mutant/object"
	"mutant/security"
)

func TestExecStringBuiltinDisabledByDefault(t *testing.T) {
	security.ResetSecurityTelemetry()

	result := ExecString(&object.String{Value: "Write-Output 'mutant'"})
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("exec_string() result is not Hash. got=%T", payload)
	}

	assertHashHasKeyType(t, hash, "ok", object.BOOLEAN_OBJ)
	assertHashHasKeyType(t, hash, "allowed", object.BOOLEAN_OBJ)
	assertHashHasKeyType(t, hash, "policy_decision", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "exit_code", object.INTEGER_OBJ)
	assertHashHasKeyType(t, hash, "stdout", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "stderr", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "timed_out", object.BOOLEAN_OBJ)
	assertHashHasKeyType(t, hash, "error", object.STRING_OBJ)
	assertHashHasKeyType(t, hash, "schema_version", object.INTEGER_OBJ)

	decisionObj, ok := hashValueByKey(hash, "policy_decision").(*object.String)
	if !ok {
		t.Fatalf("policy_decision is not String")
	}
	if decisionObj.Value != "blocked_disabled" {
		t.Fatalf("unexpected policy decision. got=%q, want=%q", decisionObj.Value, "blocked_disabled")
	}
}

func TestCommandBuilderRoundTrip(t *testing.T) {
	builderPair := CmdBuilder(&object.String{Value: "powershell"})
	builder, errObj := unwrapPair(t, builderPair)
	if errObj != nil {
		t.Fatalf("unexpected error from cmd_builder: %s", errObj.Inspect())
	}

	builderPair = CmdAdd(builder, &object.String{Value: "$x='a'"})
	builder, errObj = unwrapPair(t, builderPair)
	if errObj != nil {
		t.Fatalf("unexpected error from cmd_add: %s", errObj.Inspect())
	}

	builderPair = CmdAdd(builder, &object.String{Value: "Write-Output $x"})
	builder, errObj = unwrapPair(t, builderPair)
	if errObj != nil {
		t.Fatalf("unexpected error from cmd_add: %s", errObj.Inspect())
	}

	hash, ok := builder.(*object.Hash)
	if !ok {
		t.Fatalf("builder is not Hash. got=%T", builder)
	}

	linesObj := hashValueByKey(hash, "lines")
	lines, ok := linesObj.(*object.Array)
	if !ok {
		t.Fatalf("lines is not Array. got=%T", linesObj)
	}
	if len(lines.Elements) != 2 {
		t.Fatalf("wrong line count. got=%d, want=2", len(lines.Elements))
	}
}

func TestCmdRunEmptyBuilderErrors(t *testing.T) {
	builderPair := CmdBuilder()
	builder, errObj := unwrapPair(t, builderPair)
	if errObj != nil {
		t.Fatalf("unexpected error from cmd_builder: %s", errObj.Inspect())
	}

	result := CmdRun(builder)
	_, errObj = unwrapPair(t, result)
	if errObj == nil {
		t.Fatalf("expected error in pair slot, got nil")
	}
}

func TestExecStringBlockedWhenExecutionExplicitlyDisabled(t *testing.T) {
	t.Setenv(security.CommandExecEnabledEnv, "0")

	result := ExecString(&object.String{Value: "Write-Output 'mutant'"})
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("exec_string() result is not Hash. got=%T", payload)
	}

	decisionObj, ok := hashValueByKey(hash, "policy_decision").(*object.String)
	if !ok {
		t.Fatalf("policy_decision is not String")
	}
	if decisionObj.Value != "blocked_disabled" {
		t.Fatalf("unexpected policy decision. got=%q, want=%q", decisionObj.Value, "blocked_disabled")
	}

	errMsgObj, ok := hashValueByKey(hash, "error").(*object.String)
	if !ok {
		t.Fatalf("error is not String")
	}
	if errMsgObj.Value != "command execution disabled" {
		t.Fatalf("unexpected error message. got=%q, want=%q", errMsgObj.Value, "command execution disabled")
	}
}
