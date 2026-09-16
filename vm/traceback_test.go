package vm

import (
	"errors"
	"strings"
	"testing"

	"mutant/code"
	"mutant/compiler"
	"mutant/object"
)

// compilePositioned compiles src with a source file name, the way the generator
// does, so the resulting program carries positions.
func compilePositioned(t *testing.T, src string) *compiler.ByteCode {
	t.Helper()

	comp := compiler.New()
	comp.SetSourceFile("prog.mut")
	if err := comp.Compile(parse(src)); err != nil {
		t.Fatalf("compile: %v", err)
	}
	return comp.ByteCode()
}

func runtimeErrorFrom(t *testing.T, err error) *RuntimeError {
	t.Helper()

	if err == nil {
		t.Fatal("the program was expected to fail and did not")
	}
	var runtimeErr *RuntimeError
	if !errors.As(err, &runtimeErr) {
		t.Fatalf("error carries no traceback: %v", err)
	}
	return runtimeErr
}

// The done_when: a runtime error in a multi-function program reports file, line,
// column and a frame list.
func TestTracebackNamesEveryFrameInACallChain(t *testing.T) {
	src := "let inner = fn(x) {\n" + // 1
		"\treturn x / 0;\n" + //        2
		"};\n" + //                     3
		"let middle = fn(x) {\n" + //   4
		"\treturn inner(x);\n" + //     5
		"};\n" + //                     6
		"let outer = fn(x) {\n" + //    7
		"\treturn middle(x);\n" + //    8
		"};\n" + //                     9
		"outer(5);\n" //               10

	_, err := runSealed(t, compilePositioned(t, src))
	frames := runtimeErrorFrom(t, err).Frames

	want := []struct {
		function string
		line     int
	}{
		{"inner", 2},
		{"middle", 5},
		{"outer", 8},
		{"<main>", 10},
	}

	if len(frames) != len(want) {
		t.Fatalf("got %d frames, want %d: %v", len(frames), len(want), frames)
	}
	for i, expected := range want {
		got := frames[i]
		if got.Function != expected.function {
			t.Errorf("frame %d function = %q, want %q", i, got.Function, expected.function)
		}
		if got.Line != expected.line {
			t.Errorf("frame %d (%s) line = %d, want %d", i, expected.function, got.Line, expected.line)
		}
		if got.File != "prog.mut" {
			t.Errorf("frame %d file = %q, want %q", i, got.File, "prog.mut")
		}
		if got.Column <= 0 {
			t.Errorf("frame %d column = %d, want a 1-based column", i, got.Column)
		}
	}
}

// Innermost first, so the failure site sits next to the message rather than at
// the end of a list.
func TestTracebackRendersInnermostFirst(t *testing.T) {
	src := "let boom = fn() {\n\treturn 1 / 0;\n};\nboom();\n"

	_, err := runSealed(t, compilePositioned(t, src))
	rendered := runtimeErrorFrom(t, err).Traceback()

	lines := strings.Split(rendered, "\n")
	if len(lines) < 2 {
		t.Fatalf("traceback has %d lines, want at least 2:\n%s", len(lines), rendered)
	}
	if !strings.Contains(lines[0], "boom") {
		t.Errorf("first line is %q, want the innermost frame (boom)", lines[0])
	}
	if !strings.Contains(lines[len(lines)-1], mainFrameName) {
		t.Errorf("last line is %q, want %s", lines[len(lines)-1], mainFrameName)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "\t") {
			t.Errorf("frame line is not indented: %q", line)
		}
	}
}

// Error() must stay the bare message: everything that formats or matches VM
// errors today reads it, and the traceback is asked for separately.
func TestRuntimeErrorMessageIsUnchanged(t *testing.T) {
	src := "let f = fn() {\n\treturn 1 / 0;\n};\nf();\n"

	_, err := runSealed(t, compilePositioned(t, src))
	runtimeErr := runtimeErrorFrom(t, err)

	if strings.Contains(runtimeErr.Error(), "at ") || strings.Contains(runtimeErr.Error(), "prog.mut") {
		t.Errorf("Error() leaked traceback detail into the message: %q", runtimeErr.Error())
	}
	if !strings.Contains(runtimeErr.Error(), "division by zero") {
		t.Errorf("Error() = %q, want the underlying message", runtimeErr.Error())
	}
	if !errors.Is(err, runtimeErr.Err) {
		t.Error("the underlying error is not reachable through Unwrap")
	}
}

// A program compiled without positions still reports its frames, by name. The
// stack shape is worth having even when the lines are gone.
func TestTracebackWithoutPositionsStillNamesFrames(t *testing.T) {
	src := "let f = fn() {\n\treturn 1 / 0;\n};\nf();\n"

	bytecode := compilePositioned(t, src)
	bytecode.StripDebugInfo()

	_, err := runSealed(t, bytecode)
	frames := runtimeErrorFrom(t, err).Frames

	if len(frames) < 2 {
		t.Fatalf("got %d frames, want the call and main", len(frames))
	}
	for _, frame := range frames {
		if frame.Line != 0 {
			t.Errorf("frame %q reported line %d from a stripped program", frame.Function, frame.Line)
		}
		if frame.File != "" {
			t.Errorf("frame %q reported file %q from a stripped program", frame.Function, frame.File)
		}
	}
	// The name of a stripped function is gone too, so it renders as anonymous.
	if frames[len(frames)-1].Function != mainFrameName {
		t.Errorf("bottom frame = %q, want %s", frames[len(frames)-1].Function, mainFrameName)
	}
}

// A fault -- raised by panic from inside an instruction, not returned -- gets
// the same treatment as an ordinary failure. Which of the two happened must not
// decide whether the user is told where it happened.
func TestFaultCarriesATraceback(t *testing.T) {
	bytecode := compilePositioned(t, "let f = fn() {\n\treturn 1;\n};\nf();\n")

	// One pop too many: the stack floor is reached in the middle of an
	// instruction, which is exactly the shape a corrupted or hand-rewritten
	// artifact produces, and it is raised by panic rather than returned.
	bytecode.Instructions = append(bytecode.Instructions, code.Make(code.OpPop)...)

	_, err := runSealed(t, bytecode)
	runtimeErr := runtimeErrorFrom(t, err)

	if !strings.Contains(runtimeErr.Error(), "stack underflow") {
		t.Fatalf("expected a stack underflow fault, got: %v", err)
	}
	if len(runtimeErr.Frames) == 0 {
		t.Fatal("fault traceback has no frames")
	}
	if runtimeErr.Frames[len(runtimeErr.Frames)-1].Function != mainFrameName {
		t.Errorf("bottom frame = %q, want %s",
			runtimeErr.Frames[len(runtimeErr.Frames)-1].Function, mainFrameName)
	}
}

// An error a builtin returns is stamped with where it was called from. This is
// the (value, err) idiom's half of the same problem: the error is a value, so it
// never travels through the VM's error return at all.
func TestBuiltinErrorsCarryTheirCallSite(t *testing.T) {
	// json_parse reports a parse failure as an *object.Error value, bound to the
	// second name. Ending on `err` leaves it as the last popped value.
	src := "let value, err = json_parse(\"{not json\");\nerr;\n"

	bytecode := compilePositioned(t, src)
	machine, err := runSealed(t, bytecode)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	errObj := findError(machine.LastPoppedStackElement())
	if errObj == nil {
		t.Fatalf("json_parse did not return an error value; got %T", machine.LastPoppedStackElement())
	}

	if errObj.Line == 0 {
		t.Error("a builtin error carries no line")
	}
	if errObj.File != "prog.mut" {
		t.Errorf("error file = %q, want %q", errObj.File, "prog.mut")
	}
	if len(errObj.Stack) == 0 {
		t.Error("a builtin error carries no stack")
	}
	if !strings.Contains(errObj.Inspect(), "prog.mut:1:") {
		t.Errorf("Inspect() does not report the position: %s", errObj.Inspect())
	}
}

func findError(obj object.Object) *object.Error {
	switch value := obj.(type) {
	case *object.Error:
		return value
	case *object.MultiValue:
		for _, inner := range value.Values {
			if errObj, ok := inner.(*object.Error); ok {
				return errObj
			}
		}
	}
	return nil
}
