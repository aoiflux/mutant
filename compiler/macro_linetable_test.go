package compiler

import (
	"testing"

	"mutant/code"
)

// A macro expansion has to be bounded at both ends. A table reports the last
// entry recorded at or before an offset, so an expansion with nothing recording
// where it ends becomes the origin of every instruction compiled after it: a
// fault on line 7 of the program below named a macro defined on line 1, which
// contains none of the arithmetic that failed.
func TestMacroTableStopsAtTheEndOfTheExpansion(t *testing.T) {
	// Line 5 expands the macro; lines 6 and 7 are ordinary code below it, and
	// line 7 is where this program faults at runtime.
	src := "let twice = macro(x) {\n\tquote(unquote(x) + unquote(x));\n};\nlet a = 1;\nlet b = twice(a);\nlet z = 0;\nlet d = b / z;\n"

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

	// For each source line, the macro definition lines the tables attribute
	// that line's instructions to. An empty set is the right answer for every
	// line of this program except the one that expands the macro.
	origins := map[int]map[int]bool{}
	for ip := 0; ip < len(bytecode.Instructions); ip++ {
		line, _, ok := bytecode.LineTable.At(ip)
		if !ok {
			continue
		}
		if origins[line] == nil {
			origins[line] = map[int]bool{}
		}
		if definition, _, fromMacro := bytecode.MacroTable.At(ip); fromMacro {
			origins[line][definition] = true
		}
	}

	if !origins[5][1] {
		t.Errorf("line 5 expands the macro; its recorded origins = %v, want the definition on line 1", origins[5])
	}
	for _, line := range []int{6, 7} {
		if len(origins[line]) > 0 {
			t.Errorf("line %d is below the expansion and is not from a macro, yet its instructions report origins %v",
				line, origins[line])
		}
	}
}

// The end table has the same shape as the macro table and the same hazard: a
// construct the parser gave a start but no end must not be underlined with the
// span of the construct before it. Nothing the parser produces today is
// half-ranged -- recordRange fills both endpoints from tokens -- so the case is
// driven through the compiler's position state directly, which is what the end
// table is built from either way.
func TestEndTableDoesNotInheritAPreviousConstructsEnd(t *testing.T) {
	c := New()
	c.SetSourceFile("prog.mut")

	c.posLine, c.posCol = 4, 1
	c.posEndLine, c.posEndCol = 4, 14
	c.emit(code.OpTrue)

	c.posLine, c.posCol = 9, 1
	c.posEndLine, c.posEndCol = 0, 0
	second := c.emit(code.OpFalse)

	bytecode := c.ByteCode()

	if line, col, ok := bytecode.EndTable.At(0); !ok || line != 4 || col != 14 {
		t.Errorf("EndTable.At(0) = %d:%d (ok=%v), want 4:14", line, col, ok)
	}
	if line, col, ok := bytecode.EndTable.At(second); ok {
		t.Errorf("EndTable.At(%d) = %d:%d, want unknown: line 9 has no recorded end and must not borrow line 4's",
			second, line, col)
	}
	if line, _, ok := bytecode.LineTable.At(second); !ok || line != 9 {
		t.Errorf("LineTable.At(%d) = line %d (ok=%v), want 9: the start is still recorded", second, line, ok)
	}
}
