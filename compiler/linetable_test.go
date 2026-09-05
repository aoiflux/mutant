package compiler

import (
	"bytes"
	"encoding/gob"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"mutant/ast"
	"mutant/evaluator"
	"mutant/object"
)

// parseWithMacros runs the same define-then-expand pass the generator runs
// before compiling, which is where macro origins get recorded.
func parseWithMacros(t *testing.T, src string) *ast.Program {
	t.Helper()

	program, ok := parse(src).(*ast.Program)
	if !ok {
		t.Fatal("parse did not return a program")
	}

	env := object.NewEnvironment()
	evaluator.DefineMacros(program, env)
	expanded, err := evaluator.ExpandMacros(program, env)
	if err != nil {
		t.Fatalf("expand macros: %s", err)
	}

	out, ok := expanded.(*ast.Program)
	if !ok {
		t.Fatal("macro expansion did not return a program")
	}
	return out
}

// compileWithPositions compiles src the way the generator does and hands back
// the bytecode, so a test can ask what line an instruction came from.
func compileWithPositions(t *testing.T, src string) *ByteCode {
	t.Helper()

	program := parse(src)
	c := New()
	c.SetSourceFile("prog.mut")
	if err := c.Compile(program); err != nil {
		t.Fatalf("compile: %s", err)
	}
	return c.ByteCode()
}

var registerConstantTypes sync.Once

// linesIn returns every distinct line the table attributes an instruction to.
func linesIn(table interface{ At(int) (int, int, bool) }, streamLen int) map[int]bool {
	lines := map[int]bool{}
	for ip := 0; ip < streamLen; ip++ {
		if line, _, ok := table.At(ip); ok {
			lines[line] = true
		}
	}
	return lines
}

func TestByteCodeCarriesLinePositions(t *testing.T) {
	src := "let a = 1;\nlet b = 2;\nlet c = a + b;\n"

	bytecode := compileWithPositions(t, src)

	if bytecode.SourceFile != "prog.mut" {
		t.Errorf("SourceFile = %q, want %q", bytecode.SourceFile, "prog.mut")
	}
	if bytecode.LineTable.Empty() {
		t.Fatal("LineTable is empty: no instruction was attributed to a line")
	}

	lines := linesIn(bytecode.LineTable, len(bytecode.Instructions))
	for _, want := range []int{1, 2, 3} {
		if !lines[want] {
			t.Errorf("no instruction attributed to line %d; got lines %v", want, lines)
		}
	}
}

// The first instruction of the program must resolve, otherwise a failure in the
// very first statement reports no position.
func TestFirstInstructionHasAPosition(t *testing.T) {
	bytecode := compileWithPositions(t, "putln(\"hello\");\n")

	line, col, ok := bytecode.LineTable.At(0)
	if !ok {
		t.Fatal("ip 0 resolved to no position")
	}
	if line != 1 {
		t.Errorf("ip 0 is at line %d, want 1", line)
	}
	if col <= 0 {
		t.Errorf("ip 0 is at column %d, want a 1-based column", col)
	}
}

// Each function gets its own table over its own instruction stream, so a frame
// resolves against the function it is running rather than the whole program.
func TestCompiledFunctionsCarryTheirOwnTable(t *testing.T) {
	src := "let noop = fn() {\n\tlet x = 1;\n\treturn x;\n};\nnoop();\n"

	bytecode := compileWithPositions(t, src)

	var fn *object.CompiledFunction
	for _, constant := range bytecode.Constants {
		if candidate, ok := constant.(*object.CompiledFunction); ok {
			fn = candidate
			break
		}
	}
	if fn == nil {
		t.Fatal("no compiled function in the constant pool")
	}

	if fn.Name != "noop" {
		t.Errorf("function name = %q, want %q", fn.Name, "noop")
	}
	if fn.LineTable.Empty() {
		t.Fatal("the function carries no line table")
	}

	lines := linesIn(fn.LineTable, len(fn.Instructions))
	if !lines[2] || !lines[3] {
		t.Errorf("function body lines = %v, want the body's lines 2 and 3", lines)
	}
	if lines[5] {
		t.Errorf("function table claims line 5, which is outside its body: %v", lines)
	}
}

// What the position tables actually cost, measured on real programs by encoding
// the same artifact twice.
//
// This measures the tables alone; the embedded source text is not set here and
// is measured end to end in the generator, where it roughly doubles a local
// artifact on its own. The tables come to about a fifth of one: an end position
// per entry is close to the cost of a start position, and anchoring infix and
// index expressions roughly doubles the number of entries. Both were bought
// deliberately -- they are what turn "line 74" into an underline under the
// division that failed -- and both are gone from a release build.
//
// The "single-digit percent" this was first budgeted at described the
// start-position-only table it began as. Against the instruction stream rather than the artifact these
// tables run well over 100%: Mutant instructions are two or three bytes, so a
// source line buys far fewer of them than a line of Go buys machine
// instructions.
func TestDebugInfoIsASmallShareOfTheArtifact(t *testing.T) {
	for _, rel := range []string{
		filepath.Join("..", "examples", "binary", "static_bin_analysis.mut"),
		filepath.Join("..", "examples", "basics", "code.mut"),
	} {
		source, err := os.ReadFile(rel)
		if err != nil {
			t.Skipf("example program unavailable: %s", err)
		}

		bytecode := compileWithPositions(t, string(source))
		if bytecode.LineTable.Empty() {
			t.Fatalf("%s compiled without positions", rel)
		}

		full := encodedSize(t, bytecode)
		bytecode.StripDebugInfo()
		bare := encodedSize(t, bytecode)

		cost := (full - bare) * 100 / full
		t.Logf("%s: %d -> %d bytes, position tables cost %d%%", filepath.Base(rel), full, bare, cost)
		if cost >= 30 {
			t.Errorf("%s: position tables cost %d%% of the artifact, want under 30%%",
				filepath.Base(rel), cost)
		}
	}
}

func encodedSize(t *testing.T, bytecode *ByteCode) int {
	t.Helper()

	// The constant pool holds objects behind an interface, so gob needs the
	// concrete types the same way the generator registers them.
	registerConstantTypes.Do(func() {
		gob.Register(&object.CompiledFunction{})
		gob.Register(&object.String{})
		gob.Register(&object.Bytes{})
		gob.Register(&object.Integer{})
		gob.Register(&object.Float{})
		gob.Register(&object.Boolean{})
		gob.Register(&object.Null{})
		gob.Register(&object.Array{})
		gob.Register(&object.Hash{})
	})

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(bytecode); err != nil {
		t.Fatalf("encode: %s", err)
	}
	return buf.Len()
}

func TestStripDebugInfoRemovesEveryPosition(t *testing.T) {
	src := "let f = fn() {\n\treturn 1;\n};\nf();\n"

	bytecode := compileWithPositions(t, src)
	if bytecode.LineTable.Empty() {
		t.Fatal("nothing to strip: the program compiled without positions")
	}

	bytecode.StripDebugInfo()

	if bytecode.SourceFile != "" {
		t.Errorf("SourceFile survived stripping: %q", bytecode.SourceFile)
	}
	if !bytecode.LineTable.Empty() || !bytecode.MacroTable.Empty() {
		t.Error("a table on the main stream survived stripping")
	}
	for _, constant := range bytecode.Constants {
		fn, ok := constant.(*object.CompiledFunction)
		if !ok {
			continue
		}
		if fn.Name != "" || !fn.LineTable.Empty() || !fn.MacroTable.Empty() {
			t.Errorf("compiled function kept debug info after stripping: name=%q", fn.Name)
		}
	}
}

// Polymorphism moves every instruction, and mutation is on by default -- an
// ordinary `mutant prog.mut` compiles at level 5. So the tables have to survive
// the engine rather than be dropped by it, or no ordinary run would ever report
// a line.
func TestPolymorphicBytecodeKeepsUsablePositions(t *testing.T) {
	src := "let g = fn(x) {\n\treturn x + 1;\n};\nlet a = g(1);\nputln(a);\n"

	plain := compileWithPositions(t, src)

	program := parse(src)
	c := New()
	c.SetSourceFile("prog.mut")
	c.EnablePolymorphismWithSeed(10, 42)
	if err := c.Compile(program); err != nil {
		t.Fatalf("compile: %s", err)
	}
	mutated := c.ByteCode()

	if len(mutated.Instructions) <= len(plain.Instructions) {
		t.Fatalf("mutation did not lengthen the stream (%d -> %d); the test proves nothing",
			len(plain.Instructions), len(mutated.Instructions))
	}
	if mutated.LineTable.Empty() {
		t.Fatal("the mutated program lost its line table")
	}

	// Same source, so the same set of lines -- the instructions moved, the
	// program did not.
	if got, want := linesIn(mutated.LineTable, len(mutated.Instructions)),
		linesIn(plain.LineTable, len(plain.Instructions)); !sameLines(got, want) {
		t.Errorf("mutated lines = %v, unmutated = %v", got, want)
	}

	if mutated.SourceFile != "prog.mut" {
		t.Errorf("mutated program lost its source file name: %q", mutated.SourceFile)
	}

	for _, constant := range mutated.Constants {
		if fn, ok := constant.(*object.CompiledFunction); ok && fn.LineTable.Empty() {
			t.Error("a mutated compiled function lost its line table")
		}
	}
}

func sameLines(a, b map[int]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for line := range a {
		if !b[line] {
			return false
		}
	}
	return true
}

// A macro's expansion reports the line the user wrote, and separately the line
// the macro was defined on -- without which macro-heavy code is undebuggable.
func TestMacroExpansionRecordsBothSites(t *testing.T) {
	src := "let twice = macro(x) {\n\tquote(unquote(x) + unquote(x));\n};\nlet a = 1;\nlet b = twice(a);\n"

	program := parseWithMacros(t, src)

	c := New()
	c.SetSourceFile("prog.mut")
	if err := c.Compile(program); err != nil {
		t.Fatalf("compile: %s", err)
	}
	bytecode := c.ByteCode()

	if bytecode.MacroTable.Empty() {
		t.Fatal("no instruction was attributed to a macro definition")
	}

	lines := linesIn(bytecode.LineTable, len(bytecode.Instructions))
	if !lines[5] {
		t.Errorf("no instruction attributed to the call site on line 5; got %v", lines)
	}

	// Line 1 is where the macro is declared, which is the definition site a
	// reader needs; the body block's range starts on the same line as its
	// opening brace.
	macroLines := linesIn(bytecode.MacroTable, len(bytecode.Instructions))
	if !macroLines[1] {
		t.Errorf("macro table = %v, want the definition on line 1", macroLines)
	}
}
