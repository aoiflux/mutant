package vm

import (
	"testing"

	"mutant/object"
)

// evalTail compiles src with positions, runs it sealed, and returns the last
// value the program produced.
func evalTail(t *testing.T, src string) object.Object {
	t.Helper()

	machine, err := runSealed(t, compilePositioned(t, src))
	if err != nil {
		t.Fatalf("run %q: %v", src, err)
	}
	return machine.LastPoppedStackElement()
}

// A failing builtin's error is produced rather than constructed, because
// nothing in the language constructs one yet -- and because a builtin's error is
// the only kind a .mut program can hold today.
const raisingProgram = "let d, err = fs_read(\"/mutant/vm/no/such/path\");\n"

func TestErrorFieldsReadThroughDotAndIndex(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{"err.context", "builtin.fs_read"},
		{`err["context"]`, "builtin.fs_read"},
	}

	for _, tc := range cases {
		got, ok := evalTail(t, raisingProgram+tc.expr).(*object.String)
		if !ok {
			t.Fatalf("%s did not yield a string", tc.expr)
		}
		if got.Value != tc.want {
			t.Errorf("%s = %q, want %q", tc.expr, got.Value, tc.want)
		}
	}

	// message is not compared verbatim: the wording comes from the OS.
	message, ok := evalTail(t, raisingProgram+"err.message").(*object.String)
	if !ok || message.Value == "" {
		t.Errorf("err.message did not yield a non-empty string")
	}
	indexed, ok := evalTail(t, raisingProgram+`err["message"]`).(*object.String)
	if !ok || indexed.Value != message.Value {
		t.Errorf(`err["message"] and err.message disagree`)
	}
}

// The two composite fields hand back a fresh hash and array rather than a view
// of the error, so a program is free to mutate what it reads.
func TestErrorCompositeFieldsHaveTheRightShape(t *testing.T) {
	if _, ok := evalTail(t, raisingProgram+"err.related").(*object.Hash); !ok {
		t.Error("err.related is not a hash")
	}
	if _, ok := evalTail(t, raisingProgram+"err.stack").(*object.Array); !ok {
		t.Error("err.stack is not an array")
	}
}

// An unknown field name is null, exactly as it is on a struct. This is the rule
// that lets a program probe a field without knowing how the program was built.
func TestUnknownErrorFieldIsNullNotAFault(t *testing.T) {
	for _, expr := range []string{"err.no_such_field", `err["no_such_field"]`} {
		if got := evalTail(t, raisingProgram+expr); got.Type() != object.NULL_OBJ {
			t.Errorf("%s = %s, want NULL", expr, got.Type())
		}
	}
}

// Position is stamped by the VM out of the line table, so on a program that
// carries one the stamp lands on the error the builtin returned.
func TestErrorCarriesTheStampedPosition(t *testing.T) {
	line, ok := evalTail(t, raisingProgram+"err.line").(*object.Integer)
	if !ok {
		t.Fatal("err.line is not an integer")
	}
	if line.Value != 1 {
		t.Errorf("err.line = %d, want 1", line.Value)
	}

	file, ok := evalTail(t, raisingProgram+"err.file").(*object.String)
	if !ok || file.Value != "prog.mut" {
		t.Errorf("err.file = %v, want prog.mut", file)
	}
}

// The shape must not depend on the build. StripDebugInfo removes the line table,
// so a stripped program stamps nothing -- but every field still reads, as 0 or
// "". If a stripped build answered "no such field" instead, every program that
// touches position would become build-mode-dependent, which is exactly what the
// debug-info policy says must not happen: strip removes the table, never the
// shape.
func TestStrippedBuildKeepsTheErrorShape(t *testing.T) {
	zeroed := []struct {
		expr string
		want int64
	}{
		{"err.line", 0},
		{"err.column", 0},
		{"err.end_line", 0},
		{"err.end_column", 0},
	}

	for _, tc := range zeroed {
		bytecode := compilePositioned(t, raisingProgram+tc.expr)
		bytecode.StripDebugInfo()

		machine, err := runSealed(t, bytecode)
		if err != nil {
			t.Fatalf("stripped run of %q: %v", tc.expr, err)
		}

		got, ok := machine.LastPoppedStackElement().(*object.Integer)
		if !ok {
			t.Fatalf("%s on a stripped build is %T, want an INTEGER",
				tc.expr, machine.LastPoppedStackElement())
		}
		if got.Value != tc.want {
			t.Errorf("%s on a stripped build = %d, want %d", tc.expr, got.Value, tc.want)
		}
	}

	emptied := []string{"err.file", "err.source_line"}
	for _, expr := range emptied {
		bytecode := compilePositioned(t, raisingProgram+expr)
		bytecode.StripDebugInfo()

		machine, err := runSealed(t, bytecode)
		if err != nil {
			t.Fatalf("stripped run of %q: %v", expr, err)
		}

		got, ok := machine.LastPoppedStackElement().(*object.String)
		if !ok {
			t.Fatalf("%s on a stripped build is %T, want a STRING",
				expr, machine.LastPoppedStackElement())
		}
		if got.Value != "" {
			t.Errorf("%s on a stripped build = %q, want empty", expr, got.Value)
		}
	}

	// message and context come from the raiser, not the line table, so stripping
	// must not touch them. An error with no message would be the worst possible
	// release-mode behaviour.
	bytecode := compilePositioned(t, raisingProgram+"err.message")
	bytecode.StripDebugInfo()

	machine, err := runSealed(t, bytecode)
	if err != nil {
		t.Fatalf("stripped run: %v", err)
	}
	if got, ok := machine.LastPoppedStackElement().(*object.String); !ok || got.Value == "" {
		t.Error("a stripped build lost the error message")
	}
}

// Assignment stays refused. Reading a field of an error is inspection; writing
// one would let a program forge the position the VM stamped.
func TestErrorFieldsAreReadOnly(t *testing.T) {
	bytecode := compilePositioned(t, raisingProgram+"err.message = \"forged\";\n")

	if _, err := runSealed(t, bytecode); err == nil {
		t.Error("assigning to an error field was allowed")
	}
}
