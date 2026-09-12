package vm

import (
	"strings"
	"testing"

	"mutant/compiler"
)

// compileLinked compiles src as if it were the concatenation of several
// modules, with spans describing where each one begins. It is the shape
// module.Link produces, built by hand so this package does not depend on the
// linker to test what the linker makes possible.
func compileLinked(t *testing.T, src string, spans []compiler.ModuleSpan) *compiler.ByteCode {
	t.Helper()

	comp := compiler.New()
	comp.SetSourceFile(spans[len(spans)-1].Path)
	comp.SetSourceText(src)
	comp.SetModuleSpans(spans)
	if err := comp.Compile(parse(src)); err != nil {
		t.Fatalf("compile: %v", err)
	}
	return comp.ByteCode()
}

// TestTracebackNamesTheModuleEachFrameCameFrom is the whole point of module
// spans. Before them every frame was stamped with the program's single source
// file name, so a fault inside lib.mut was reported as main.mut.
func TestTracebackNamesTheModuleEachFrameCameFrom(t *testing.T) {
	// lib.mut occupies lines 1-3, main.mut lines 4-7.
	src := "let boom = fn(x) {\n" + //  1  lib.mut:1
		"\treturn x / 0;\n" + //        2  lib.mut:2
		"};\n" + //                     3  lib.mut:3
		"let caller = fn() {\n" + //    4  main.mut:1
		"\treturn boom(1);\n" + //      5  main.mut:2
		"};\n" + //                     6  main.mut:3
		"caller();\n" //                7  main.mut:4

	spans := []compiler.ModuleSpan{
		{Path: "lib.mut", StartLine: 1},
		{Path: "main.mut", StartLine: 4},
	}

	_, runErr := runSealed(t, compileLinked(t, src, spans))
	frames := runtimeErrorFrom(t, runErr).Frames
	if len(frames) < 2 {
		t.Fatalf("expected at least two frames, got %d", len(frames))
	}

	inner := frames[0]
	if inner.File != "lib.mut" {
		t.Fatalf("the failing frame is attributed to %q, want lib.mut", inner.File)
	}
	if inner.Line != 2 {
		t.Fatalf("the failing frame is at line %d of lib.mut, want 2", inner.Line)
	}
	if inner.AbsLine != 2 {
		t.Fatalf("the failing frame's blob line is %d, want 2", inner.AbsLine)
	}

	caller, ok := frameNamed(frames, "caller")
	if !ok {
		t.Fatalf("no frame for caller in %v", frameNames(frames))
	}
	if caller.File != "main.mut" {
		t.Fatalf("caller is attributed to %q, want main.mut", caller.File)
	}
	// caller's call to boom is on blob line 5, which is main.mut's line 2.
	if caller.Line != 2 {
		t.Fatalf("caller is at line %d of main.mut, want 2", caller.Line)
	}
	if caller.AbsLine != 5 {
		t.Fatalf("caller's blob line is %d, want 5", caller.AbsLine)
	}
}

func frameNamed(frames []TracebackFrame, name string) (TracebackFrame, bool) {
	for _, f := range frames {
		if f.Function == name {
			return f, true
		}
	}
	return TracebackFrame{}, false
}

func frameNames(frames []TracebackFrame) []string {
	names := make([]string, 0, len(frames))
	for _, f := range frames {
		names = append(names, f.Function)
	}
	return names
}

// TestTracebackQuotesTheRightSourceLine is the failure the plan singles out as
// the worst one available: a correct-looking file:line header over a quoted
// line from a different file. The header is built from Line and the quote from
// AbsLine, so this fails the moment they are conflated again.
func TestTracebackQuotesTheRightSourceLine(t *testing.T) {
	src := "let boom = fn(x) {\n" + //  1  lib.mut:1
		"\treturn x / 0;\n" + //        2  lib.mut:2
		"};\n" + //                     3  lib.mut:3
		"let decoy = 111;\n" + //       4  main.mut:1
		"let alsodecoy = 222;\n" + //   5  main.mut:2
		"boom(1);\n" //                 6  main.mut:3

	spans := []compiler.ModuleSpan{
		{Path: "lib.mut", StartLine: 1},
		{Path: "main.mut", StartLine: 4},
	}

	_, runErr := runSealed(t, compileLinked(t, src, spans))
	rendered := runtimeErrorFrom(t, runErr).Traceback()

	if !strings.Contains(rendered, "lib.mut:2") {
		t.Fatalf("traceback does not name lib.mut:2:\n%s", rendered)
	}
	if !strings.Contains(rendered, "x / 0") {
		t.Fatalf("traceback does not quote the failing line:\n%s", rendered)
	}
	// The decoys are what a blob-line lookup labelled with a file line, or a
	// file-line lookup into the blob, would surface instead.
	for _, decoy := range []string{"111", "222"} {
		if strings.Contains(rendered, decoy) {
			t.Fatalf("traceback quoted an unrelated module's line (%s):\n%s", decoy, rendered)
		}
	}
}

// TestStampedErrorQuotesTheRightSourceLine covers the same split on the other
// path: an error a builtin produced, stamped with a position by the VM.
func TestStampedErrorQuotesTheRightSourceLine(t *testing.T) {
	src := "let fail = fn() {\n" + //   1  lib.mut:1
		"\treturn error(\"nope\");\n" + // 2  lib.mut:2
		"};\n" + //                     3  lib.mut:3
		"let decoy = 111;\n" + //       4  main.mut:1
		"let e = fail();\n" //          5  main.mut:2

	spans := []compiler.ModuleSpan{
		{Path: "lib.mut", StartLine: 1},
		{Path: "main.mut", StartLine: 4},
	}

	machine, err := runSealed(t, compileLinked(t, src, spans))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// The stamped position must name lib.mut, and the quoted line must be
	// lib.mut's, not whatever sits at that offset in the blob.
	errObj := findError(machine.LastPoppedStackElement())
	if errObj == nil {
		t.Fatalf("expected an error value, got %T", machine.LastPoppedStackElement())
	}
	if errObj.File != "lib.mut" {
		t.Fatalf("error stamped with file %q, want lib.mut", errObj.File)
	}
	if errObj.Line != 2 {
		t.Fatalf("error stamped at line %d, want 2", errObj.Line)
	}
	if strings.Contains(errObj.SourceLine, "111") {
		t.Fatalf("error quoted an unrelated module's line: %q", errObj.SourceLine)
	}
	if !strings.Contains(errObj.SourceLine, "error(") {
		t.Fatalf("error quoted %q, want the line that raised it", errObj.SourceLine)
	}
}

// TestSingleFileProgramsAreUnaffected pins that nothing changes for a program
// with no spans: Line and AbsLine agree and the file is the program's own.
func TestSingleFileProgramsAreUnaffected(t *testing.T) {
	src := "let boom = fn(x) {\n" +
		"\treturn x / 0;\n" +
		"};\n" +
		"boom(1);\n"

	_, runErr := runSealed(t, compilePositioned(t, src))
	frames := runtimeErrorFrom(t, runErr).Frames

	for _, frame := range frames {
		if frame.File != "prog.mut" {
			t.Fatalf("frame %s attributed to %q, want prog.mut", frame.Function, frame.File)
		}
		if frame.Line > 0 && frame.AbsLine != frame.Line {
			t.Fatalf("frame %s: AbsLine %d != Line %d for a single-file program",
				frame.Function, frame.AbsLine, frame.Line)
		}
	}
}

// TestSameSiteDistinguishesModules guards collapseCycles. Two same-named
// functions on the same line of two different files are two call sites, and
// folding them into a "repeated" note would hide a real chain.
func TestSameSiteDistinguishesModules(t *testing.T) {
	a := TracebackFrame{Function: "helper", File: "a.mut", Line: 3, Column: 5}
	b := TracebackFrame{Function: "helper", File: "b.mut", Line: 3, Column: 5}

	if a.sameSite(b) {
		t.Fatal("frames in different modules must not read as the same call site")
	}
	if !a.sameSite(a) {
		t.Fatal("a frame must be the same site as itself")
	}
}
