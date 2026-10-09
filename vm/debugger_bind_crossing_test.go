package vm

import (
	"strings"
	"testing"

	"mutant/compiler"
)

// Binding a breakpoint forward is allowed to cross a blank line. It is not
// allowed to cross a file.
//
// The fixture is the one TestABreakpointInAModuleUsesThatModulesLines uses:
// lib.mut is blob lines 1-3, main.mut is 4-7. lib.mut:3 is the bare `};` that
// closes the function literal, so it emits nothing -- and neither does anything
// after it in lib.mut, because there is nothing after it. The next instruction
// in the blob is main.mut's first line.
//
// Measured at abb42b4 before the fix, through the real debugger: the breakpoint
// came back Verified, Bound at blob 4, and reported as lib.mut:1. An editor
// shows a solid marker on line 1 of the file the user opened, and it fires in
// another file. ModuleLine's own bound refuses line 4 of that three-line file
// with a precise sentence, which made the refusal at 4 and the confident wrong
// answer at 3 neighbours.
func TestBindingDoesNotCrossOutOfTheRequestedFile(t *testing.T) {
	src := "let helper = fn(x) {\n" + // 1  lib.mut:1
		"\treturn x + 1;\n" + //         2  lib.mut:2
		"};\n" + //                      3  lib.mut:3  emits nothing
		"let call = fn() {\n" + //       4  main.mut:1
		"\treturn helper(1);\n" + //     5  main.mut:2
		"};\n" + //                      6  main.mut:3
		"call();\n" //                   7  main.mut:4

	spans := []compiler.ModuleSpan{
		{Path: "lib.mut", StartLine: 1},
		{Path: "main.mut", StartLine: 4},
	}

	bc := compileLinked(t, src, spans)
	s := newSessionFromBytecode(t, bc, DebugOptions{})

	bps := s.breakAt("lib.mut", 3)
	if len(bps) != 1 {
		t.Fatalf("got %d breakpoints", len(bps))
	}
	bp := bps[0]

	if bp.Verified {
		path, local, _ := bc.ModuleAt(bp.Bound)
		t.Fatalf("lib.mut:3 was verified and bound to blob %d, which is %s:%d", bp.Bound, path, local)
	}
	if !strings.Contains(bp.Message, "lib.mut") || !strings.Contains(bp.Message, "main.mut") {
		t.Errorf("the reason names neither the file asked about nor the one the code belongs to: %q", bp.Message)
	}

	s.expect(StopExited)
}

// The refusal has to stay as narrow as the defect. Crossing a file is refused;
// walking forward WITHIN one is what binding is for and must still work.
func TestBindingStillWalksForwardInsideOneFile(t *testing.T) {
	// main.mut:3 is `};` and emits nothing; main.mut:4 is `call();` and does.
	// Both are in the same file, so the walk is allowed and lands on 4.
	src := "let helper = fn(x) {\n" +
		"\treturn x + 1;\n" +
		"};\n" +
		"let call = fn() {\n" +
		"\treturn helper(1);\n" +
		"};\n" +
		"call();\n"

	spans := []compiler.ModuleSpan{
		{Path: "lib.mut", StartLine: 1},
		{Path: "main.mut", StartLine: 4},
	}

	bc := compileLinked(t, src, spans)
	s := newSessionFromBytecode(t, bc, DebugOptions{})

	bps := s.breakAt("main.mut", 3)
	if !bps[0].Verified {
		t.Fatalf("main.mut:3 was not bound: %+v", bps[0])
	}
	if bps[0].Line != 4 {
		t.Errorf("bound and reported at main.mut:%d, want 4 -- the next line of the same file that holds code", bps[0].Line)
	}

	s.expect(StopBreakpoint)
	frames, err := s.dbg.Frames()
	if err != nil {
		t.Fatalf("frames: %v", err)
	}
	if frames[0].File != "main.mut" || frames[0].Line != 4 {
		t.Errorf("stopped at %s:%d, want main.mut:4", frames[0].File, frames[0].Line)
	}
	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// A single-module program has no spans, so there is no file to cross out of and
// the blob line IS the file line. The guard must not make these unverifiable.
func TestBindingInASingleModuleProgramIsUnaffected(t *testing.T) {
	s := newSession(t, "let a = 1;\n\na;\n", DebugOptions{})

	bps := s.breakAt("prog.mut", 2) // blank, so it walks to 3
	if !bps[0].Verified {
		t.Fatalf("a breakpoint on a blank line of a one-module program was not bound: %+v", bps[0])
	}
	if bps[0].Line != 3 {
		t.Errorf("bound at line %d, want 3", bps[0].Line)
	}

	s.expect(StopBreakpoint)
	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// Two modules with one base name: moduleSpanFor refuses to guess, and the
// refusal has to say that rather than deny the file is in the program.
func TestARefusalSaysWhenABaseNameIsAmbiguous(t *testing.T) {
	src := "let a = 1;\n" + //  1  one/util.mut:1
		"a;\n" + //              2  one/util.mut:2
		"let b = 2;\n" + //      3  two/util.mut:1
		"b;\n" //                4  two/util.mut:2

	spans := []compiler.ModuleSpan{
		{Path: "one/util.mut", StartLine: 1},
		{Path: "two/util.mut", StartLine: 3},
	}

	bc := compileLinked(t, src, spans)
	s := newSessionFromBytecode(t, bc, DebugOptions{})

	if n := bc.ModulesNamed("util.mut"); n != 2 {
		t.Fatalf("ModulesNamed(util.mut) = %d, want 2", n)
	}

	bps := s.breakAt("util.mut", 1)
	if bps[0].Verified {
		t.Error("an ambiguous base name was bound to one of the candidates")
	}
	if strings.Contains(bps[0].Message, "not one of the files") {
		t.Errorf("the refusal denies the file is in the program, which it is -- twice: %q", bps[0].Message)
	}
	if !strings.Contains(bps[0].Message, "util.mut") {
		t.Errorf("the refusal does not name the file: %q", bps[0].Message)
	}

	// An unambiguous full path still binds, so the refusal above is about the
	// ambiguity and not about the file.
	more := s.breakAt("two/util.mut", 1)
	if !more[len(more)-1].Verified {
		t.Errorf("the full path was not bound either: %+v", more[len(more)-1])
	}

	s.expect(StopBreakpoint)
	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}
