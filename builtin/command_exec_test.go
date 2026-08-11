package builtin

import (
	"testing"

	"mutant/object"
)

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
