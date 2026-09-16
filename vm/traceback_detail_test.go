package vm

import (
	"strings"
	"testing"

	"mutant/compiler"
)

// compileWithSource compiles src the way the generator does, embedded source
// text and all, so the traceback can quote the lines it names.
func compileWithSource(t *testing.T, src string) *compiler.ByteCode {
	t.Helper()

	comp := compiler.New()
	comp.SetSourceFile("prog.mut")
	comp.SetSourceText(src)
	if err := comp.Compile(parse(src)); err != nil {
		t.Fatalf("compile: %v", err)
	}
	return comp.ByteCode()
}

// The report an analyst actually reads: every frame named, with the arguments
// it received, the line it is on, and a caret under the failing span.
func TestTracebackQuotesSourceAndNamesArguments(t *testing.T) {
	src := "let inner = fn(n, d) {\n" + // 1
		"\treturn n / d;\n" + //           2
		"};\n" + //                        3
		"let outer = fn(v) {\n" + //       4
		"\treturn inner(v, 0);\n" + //     5
		"};\n" + //                        6
		"outer(7);\n" //                   7

	_, err := runSealed(t, compileWithSource(t, src))
	rendered := runtimeErrorFrom(t, err).Traceback()

	for _, want := range []string{
		"inner(n=7, d=0)", // the values, not just the names
		"outer(v=7)",
		"2 |", // the quoted line
		"^",   // the underline
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("traceback is missing %q:\n%s", want, rendered)
		}
	}

	// The caret must sit under `n / d`, not under the whole return statement.
	// The quoted line is tab-indented, so the underline row is too.
	if !strings.Contains(rendered, "^^^^^") {
		t.Errorf("the failing span is not underlined:\n%s", rendered)
	}
	if strings.Contains(rendered, "^^^^^^^^^^^^^") {
		t.Errorf("the underline covers the whole statement rather than the operation:\n%s", rendered)
	}
}

// Argument rendering reads decrypted values off the stack, so it must be gated
// on the same debug info everything else is: a stripped program prints its
// frames without printing its data.
func TestStrippedProgramsPrintNoArgumentValues(t *testing.T) {
	src := "let secret = fn(token) {\n\treturn token / 0;\n};\nsecret(1234);\n"

	bytecode := compileWithSource(t, src)
	bytecode.StripDebugInfo()

	_, err := runSealed(t, bytecode)
	rendered := runtimeErrorFrom(t, err).Traceback()

	if strings.Contains(rendered, "1234") {
		t.Errorf("a stripped build printed a runtime value:\n%s", rendered)
	}
	if strings.Contains(rendered, "token") {
		t.Errorf("a stripped build printed a parameter name:\n%s", rendered)
	}
	if !strings.Contains(rendered, anonymousFrameName) {
		t.Errorf("a stripped build lost its frame list entirely:\n%s", rendered)
	}
}

// A deep recursion produces hundreds of identical frames. Collapsing them is
// what keeps the report readable; the count is what keeps it honest.
func TestRepeatedFramesCollapse(t *testing.T) {
	src := "let down = fn(n) {\n" + //  1
		"\tif (n == 0) {\n" + //        2
		"\t\treturn 1 / n;\n" + //      3
		"\t}\n" + //                    4
		"\treturn down(n - 1);\n" + //  5
		"};\n" + //                     6
		"down(60);\n" //                7

	_, err := runSealed(t, compileWithSource(t, src))
	runtimeErr := runtimeErrorFrom(t, err)

	if len(runtimeErr.Frames) < 60 {
		t.Fatalf("expected a deep stack, got %d frames", len(runtimeErr.Frames))
	}

	rendered := runtimeErr.Traceback()
	if !strings.Contains(rendered, "repeated") {
		t.Errorf("a 60-deep recursion rendered without collapsing:\n%s", rendered)
	}

	// Four frames plus two snippet lines each, plus the note, is the shape;
	// anything near sixty means the collapse did not happen.
	if lines := strings.Count(rendered, "\n") + 1; lines > 20 {
		t.Errorf("collapsed traceback is still %d lines long:\n%s", lines, rendered)
	}

	// Both ends survive: the failure and the entry point.
	if !strings.Contains(rendered, mainFrameName) {
		t.Errorf("collapsing lost the entry point:\n%s", rendered)
	}
	if !strings.Contains(rendered, "down(n=0)") {
		t.Errorf("collapsing lost the innermost frame:\n%s", rendered)
	}
}

// Collapsing must not fire on a stack that merely repeats a name; two passes
// through a pair of functions is something a reader wants in full.
func TestShortRepeatsAreNotCollapsed(t *testing.T) {
	frames := []TracebackFrame{
		{Function: "a", Line: 1, Column: 1},
		{Function: "b", Line: 2, Column: 1},
		{Function: "a", Line: 1, Column: 1},
		{Function: "b", Line: 2, Column: 1},
		{Function: mainFrameName, Line: 9, Column: 1},
	}

	rendered := renderFrames(frames, "")
	if strings.Contains(rendered, "repeated") {
		t.Errorf("two passes through a cycle were collapsed:\n%s", rendered)
	}
	if got := strings.Count(rendered, "\n") + 1; got != len(frames) {
		t.Errorf("rendered %d lines for %d frames:\n%s", got, len(frames), rendered)
	}
}

// A mutually recursive cycle collapses as the cycle, not as its parts.
func TestMutualRecursionCollapsesAsAPair(t *testing.T) {
	frames := []TracebackFrame{{Function: "boom", Line: 1, Column: 1}}
	for i := 0; i < 8; i++ {
		frames = append(frames,
			TracebackFrame{Function: "ping", Line: 2, Column: 1},
			TracebackFrame{Function: "pong", Line: 3, Column: 1},
		)
	}
	frames = append(frames, TracebackFrame{Function: mainFrameName, Line: 9, Column: 1})

	rendered := renderFrames(frames, "")
	if !strings.Contains(rendered, "2 frames repeated 7 more times") {
		t.Errorf("the ping/pong cycle did not collapse as a pair:\n%s", rendered)
	}
}

// A stack that is deep without repeating still has to end somewhere.
func TestVeryDeepStacksAreTruncated(t *testing.T) {
	frames := make([]TracebackFrame, 0, 300)
	for i := 0; i < 300; i++ {
		frames = append(frames, TracebackFrame{Function: "f", Line: i + 1, Column: 1})
	}

	rendered := renderFrames(frames, "")
	if !strings.Contains(rendered, "frames omitted") {
		t.Errorf("a 300-frame stack rendered without truncation:\n%s", rendered)
	}
	if lines := strings.Count(rendered, "\n") + 1; lines > maxRenderedFrames+2 {
		t.Errorf("truncated traceback is %d lines, want at most %d", lines, maxRenderedFrames+2)
	}
	// The failure and the entry point are the two ends worth keeping.
	if !strings.Contains(rendered, "line 1:1") || !strings.Contains(rendered, "line 300:1") {
		t.Errorf("truncation dropped one end of the stack:\n%s", rendered)
	}
}

// A program with no embedded source still reports positions; it just cannot
// quote them.
func TestPositionsWithoutSourceRenderWithoutSnippets(t *testing.T) {
	frames := []TracebackFrame{{Function: "f", File: "prog.mut", Line: 3, Column: 5, EndLine: 3, EndColumn: 9}}

	rendered := renderFrames(frames, "")
	if !strings.Contains(rendered, "prog.mut:3:5") {
		t.Errorf("position lost without source:\n%s", rendered)
	}
	if strings.Contains(rendered, "^") {
		t.Errorf("an underline was drawn with no line to draw it under:\n%s", rendered)
	}
}

// A builtin error picks up the span and the source line as well as the
// position, so a caught error can still show what produced it long after the
// frame it came from is gone.
func TestBuiltinErrorsCarryTheirSourceLine(t *testing.T) {
	src := "let value, err = json_parse(\"{not json\");\nerr;\n"

	machine, err := runSealed(t, compileWithSource(t, src))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	errObj := findError(machine.LastPoppedStackElement())
	if errObj == nil {
		t.Fatalf("json_parse did not return an error value; got %T", machine.LastPoppedStackElement())
	}

	if !strings.Contains(errObj.SourceLine, "json_parse") {
		t.Errorf("SourceLine = %q, want the line the call is on", errObj.SourceLine)
	}
	if errObj.EndColumn <= errObj.Column {
		t.Errorf("error span %d-%d covers nothing", errObj.Column, errObj.EndColumn)
	}
	if !strings.Contains(errObj.Snippet(), "^") {
		t.Errorf("the error renders no underline:\n%s", errObj.Snippet())
	}
}
