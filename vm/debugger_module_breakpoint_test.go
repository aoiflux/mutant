package vm

import (
	"strings"
	"testing"

	"mutant/compiler"
)

// linkedBreakSession attaches a debugger to a two-module program: lib.mut on
// blob lines 1-3 and main.mut on 4-7. It is the shape module.Link produces,
// built by hand so this package does not depend on the linker.
func linkedBreakSession(t *testing.T) *session {
	t.Helper()

	src := "let boom = fn(x) {\n" + //  1  lib.mut:1
		"\treturn x + 1;\n" + //        2  lib.mut:2
		"};\n" + //                     3  lib.mut:3
		"let caller = fn() {\n" + //    4  main.mut:1
		"\treturn boom(1);\n" + //      5  main.mut:2
		"};\n" + //                     6  main.mut:3
		"caller();\n" //                7  main.mut:4

	spans := []compiler.ModuleSpan{
		{Path: "lib.mut", StartLine: 1},
		{Path: "main.mut", StartLine: 4},
	}
	return newSessionFromBytecode(t, compileLinked(t, src, spans), DebugOptions{})
}

// TestABreakpointWithNoFileBindsIntoTheEntryModule is what a DAP client asking
// without a Source.Path gets. The entry is the last span, not the first, so
// this used to bind into lib.mut and report a line of it as verified.
func TestABreakpointWithNoFileBindsIntoTheEntryModule(t *testing.T) {
	s := linkedBreakSession(t)

	// main.mut:4 is `caller();`, the only top-level statement in the entry.
	bps := s.breakAt("", 4)
	if len(bps) != 1 {
		t.Fatalf("expected one breakpoint, got %d", len(bps))
	}
	bp := bps[0]
	if !bp.Verified {
		t.Fatalf("the breakpoint was refused: %s", bp.Message)
	}
	if bp.Bound != 7 {
		t.Fatalf("bound to blob line %d, want 7 (main.mut:4)", bp.Bound)
	}
	if bp.Line != 4 {
		t.Fatalf("reported at line %d, want 4 of the entry module", bp.Line)
	}
}

// TestABreakpointPastTheEndOfAModuleIsRefused is the stale-marker case: lib.mut
// has three lines, and line 4 of it is main.mut's first. Binding it used to
// report Verified at a line of main.mut while File still said lib.mut.
func TestABreakpointPastTheEndOfAModuleIsRefused(t *testing.T) {
	s := linkedBreakSession(t)

	bps := s.breakAt("lib.mut", 4)
	if len(bps) != 1 {
		t.Fatalf("expected one breakpoint, got %d", len(bps))
	}
	bp := bps[0]
	if bp.Verified {
		t.Fatalf("lib.mut has three lines; line 4 was bound to blob %d (reported line %d)",
			bp.Bound, bp.Line)
	}
	// And the refusal has to say which refusal it is. "not one of the files
	// this program was built from" would send a reader looking for a build
	// problem they do not have.
	if !strings.Contains(bp.Message, "past the end of lib.mut") {
		t.Fatalf("the refusal reads %q, which does not say the line is past the file's end", bp.Message)
	}
}

// TestABreakpointInAFileTheProgramLacksStillSaysSo keeps the other refusal
// distinct: an unknown file is a different problem from an over-long line, and
// one message for both would be wrong half the time.
func TestABreakpointInAFileTheProgramLacksStillSaysSo(t *testing.T) {
	s := linkedBreakSession(t)

	bp := s.breakAt("nowhere.mut", 1)[0]
	if bp.Verified {
		t.Fatal("a file the program was not built from must not bind")
	}
	if !strings.Contains(bp.Message, "not one of the files") {
		t.Fatalf("the refusal reads %q", bp.Message)
	}
}

// TestARefusalWithNoFileNamedNamesTheEntry: a caller that sent no path still
// has to be told which file was out of range, and the empty string it sent is
// not an answer.
func TestARefusalWithNoFileNamedNamesTheEntry(t *testing.T) {
	s := linkedBreakSession(t)

	bp := s.breakAt("", 9)[0]
	if bp.Verified {
		t.Fatalf("main.mut has four lines; line 9 bound to blob %d", bp.Bound)
	}
	if !strings.Contains(bp.Message, "past the end of main.mut") {
		t.Fatalf("the refusal reads %q, which does not name the entry module", bp.Message)
	}
}
