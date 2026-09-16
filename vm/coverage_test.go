package vm

import (
	"fmt"
	"sort"
	"testing"

	"mutant/compiler"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
)

// runCovered compiles and runs a program with coverage on and returns what it
// recorded, flattened to "line:hit" pairs for the program's single file.
func runCovered(t *testing.T, source string) map[int]bool {
	t.Helper()

	program := parse(source)
	comp := compiler.New()
	comp.EnableSecurityOpcodeInjection()
	// Coverage attributes every line to a file, so the program needs a name.
	// generator.CompileForTest always sets one; a hand-built ByteCode does not.
	comp.SetSourceFile("prog.mut")
	if err := comp.Compile(program); err != nil {
		t.Fatalf("compiler error: %s", err)
	}

	byteCode := comp.ByteCode()
	password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
	byteCode = mutil.EncryptByteCode(byteCode, password)

	machine := NewWithPasswordAndGlobalStoreMode(byteCode, password, make([]object.Object, global.GlobalSize), false)
	machine.EnableCoverage()
	if err := machine.Run(); err != nil {
		t.Fatalf("run error: %s", err)
	}

	report := machine.CoverageReport()
	if report == nil {
		t.Fatal("coverage was enabled but no report came back")
	}
	if len(report.Files) != 1 {
		t.Fatalf("expected one file, got %d", len(report.Files))
	}
	return report.Files[0].Lines
}

func sortedLines(lines map[int]bool) []int {
	out := make([]int, 0, len(lines))
	for line := range lines {
		out = append(out, line)
	}
	sort.Ints(out)
	return out
}

// A run with coverage off reports nothing at all, which is a different answer
// from a run that covered nothing.
func TestCoverageIsNilWhenItWasNeverEnabled(t *testing.T) {
	machine := runTestLedger(t, `let x = 1;`)
	if report := machine.CoverageReport(); report != nil {
		t.Fatalf("expected no report, got %+v", report)
	}
}

// The line that did not run is in the denominator and marked missed. A report
// built only from what executed would call this file fully covered.
func TestABranchThatDidNotRunIsCountedAndMissed(t *testing.T) {
	lines := runCovered(t, "let f = fn(x) {\n"+
		"    if (x > 0) {\n"+
		"        1\n"+
		"    } else {\n"+
		"        2\n"+
		"    }\n"+
		"};\n"+
		"f(5);\n")

	if ran, known := lines[3]; !known || !ran {
		t.Errorf("line 3 (the taken branch) known=%v ran=%v, want known and run", known, ran)
	}
	if ran, known := lines[5]; !known || ran {
		t.Errorf("line 5 (the branch not taken) known=%v ran=%v, want known and not run", known, ran)
	}
}

// A function nobody calls still counts. Its lines are in the program whether or
// not a test reached them, which is the whole thing coverage is for.
func TestAnUncalledFunctionIsStillCounted(t *testing.T) {
	// The BODY gets its own line. A one-line `let f = fn() { 2 };` runs that
	// line either way -- the declaration is on it too -- which is a true answer
	// about the line and a useless one about the function.
	lines := runCovered(t, "let used = fn() { 1 };\n"+
		"let unused = fn() {\n"+
		"    2\n"+
		"};\n"+
		"used();\n")

	if ran, known := lines[2]; !known || !ran {
		t.Errorf("line 2 (the declaration, which does run) known=%v ran=%v, want known and run", known, ran)
	}
	if ran, known := lines[3]; !known || ran {
		t.Errorf("line 3 (the uncalled body) known=%v ran=%v, want known and not run", known, ran)
	}
}

// Lines that produced no instructions are not in the denominator. Counting a
// blank line or a comment would measure the shape of the file rather than what
// the tests reached.
func TestLinesWithNoCodeAreNotCounted(t *testing.T) {
	lines := runCovered(t, "let x = 1;\n"+
		"\n"+
		"// a comment\n"+
		"x;\n")

	for _, line := range []int{2, 3} {
		if _, known := lines[line]; known {
			t.Errorf("line %d has no code but appears in the report (lines: %v)", line, sortedLines(lines))
		}
	}
	if _, known := lines[1]; !known {
		t.Errorf("line 1 has code but is missing from the report (lines: %v)", sortedLines(lines))
	}
}
