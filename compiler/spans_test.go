package compiler

import (
	"strings"
	"testing"

	"mutant/object"
)

// compileWithSource compiles src the way the generator does, embedded source
// text and all.
func compileWithSource(t *testing.T, src string) *ByteCode {
	t.Helper()

	c := New()
	c.SetSourceFile("prog.mut")
	c.SetSourceText(src)
	if err := c.Compile(parse(src)); err != nil {
		t.Fatalf("compile: %s", err)
	}
	return c.ByteCode()
}

// spanAt resolves both ends of the construct covering ip.
func spanAt(fn *object.CompiledFunction, ip int) (startLine, startCol, endLine, endCol int, ok bool) {
	startLine, startCol, ok = fn.LineTable.At(ip)
	if !ok {
		return 0, 0, 0, 0, false
	}
	endLine, endCol, _ = fn.EndTable.At(ip)
	return startLine, startCol, endLine, endCol, true
}

// functionNamed digs a compiled function out of the constant pool.
func functionNamed(t *testing.T, bytecode *ByteCode, name string) *object.CompiledFunction {
	t.Helper()

	for _, constant := range bytecode.Constants {
		if fn, ok := constant.(*object.CompiledFunction); ok && fn.Name == name {
			return fn
		}
	}
	t.Fatalf("no compiled function named %q", name)
	return nil
}

// An end position is what separates "line 2" from an underline under the
// division that failed, so every instruction that has a start must have an end
// that closes over it.
func TestEveryPositionedInstructionCarriesAnEnd(t *testing.T) {
	bytecode := compileWithSource(t, "let f = fn(a, b) {\n\treturn a / b;\n};\nf(1, 0);\n")
	fn := functionNamed(t, bytecode, "f")

	if fn.EndTable.Empty() {
		t.Fatal("the function carries no end positions")
	}

	var checked int
	for ip := 0; ip < len(fn.Instructions); ip++ {
		startLine, startCol, endLine, endCol, ok := spanAt(fn, ip)
		if !ok {
			continue
		}
		checked++

		if endLine < startLine {
			t.Errorf("ip %d ends on line %d before it starts on line %d", ip, endLine, startLine)
		}
		if endLine == startLine && endCol <= startCol {
			t.Errorf("ip %d spans %d:%d-%d:%d, which covers nothing",
				ip, startLine, startCol, endLine, endCol)
		}
	}
	if checked == 0 {
		t.Fatal("no instruction in the function resolved to a position")
	}
}

// The reason infix expressions anchor: the caret has to land on the operator
// that failed, not on the statement containing it.
func TestInfixExpressionsAnchorTheirOwnSpan(t *testing.T) {
	// Column 9 is the `a` of `a / b` on line 2; the statement starts at 2.
	bytecode := compileWithSource(t, "let f = fn(a, b) {\n\treturn a / b;\n};\nf(1, 0);\n")
	fn := functionNamed(t, bytecode, "f")

	var found bool
	for ip := 0; ip < len(fn.Instructions); ip++ {
		startLine, startCol, endLine, endCol, ok := spanAt(fn, ip)
		if !ok || startLine != 2 {
			continue
		}
		if startCol == 9 && endLine == 2 && endCol == 14 {
			found = true
			break
		}
	}

	if !found {
		t.Error("no instruction is attributed to the span of `a / b` itself; " +
			"the caret would underline the whole return statement")
	}
}

// Index expressions anchor for the same reason: an out-of-range index should
// underline the subscript, not the line it sits on.
func TestIndexExpressionsAnchorTheirOwnSpan(t *testing.T) {
	bytecode := compileWithSource(t, "let xs = [1, 2];\nlet pick = fn(i) {\n\treturn xs[i];\n};\npick(9);\n")
	fn := functionNamed(t, bytecode, "pick")

	var narrowest int
	for ip := 0; ip < len(fn.Instructions); ip++ {
		startLine, startCol, endLine, endCol, ok := spanAt(fn, ip)
		if !ok || startLine != 3 || endLine != 3 {
			continue
		}
		width := endCol - startCol
		if narrowest == 0 || width < narrowest {
			narrowest = width
		}
	}

	// `xs[i]` is five columns; the enclosing `return xs[i];` is thirteen.
	if narrowest == 0 || narrowest > 6 {
		t.Errorf("narrowest span on the indexing line is %d columns, want the index expression's five", narrowest)
	}
}

// The source travels with the program so a failing artifact can quote itself
// without reading anything off disk.
func TestSourceTextIsCarriedAndStripped(t *testing.T) {
	const src = "let f = fn(a, b) {\n\treturn a / b;\n};\nf(1, 0);\n"
	bytecode := compileWithSource(t, src)

	if bytecode.SourceText != src {
		t.Errorf("SourceText = %q, want the program's own source", bytecode.SourceText)
	}

	bytecode.StripDebugInfo()
	if bytecode.SourceText != "" {
		t.Error("a stripped program still carries its source")
	}
	if !bytecode.EndTable.Empty() {
		t.Error("a stripped program still carries end positions")
	}
}

// Parameter names are what let a traceback say inner(n=10, d=0). They are debug
// info, and their absence is what stops a release build from printing a
// program's own runtime values back out.
func TestParameterNamesAreCarriedAndStripped(t *testing.T) {
	bytecode := compileWithSource(t, "let f = fn(alpha, beta) {\n\treturn alpha / beta;\n};\nf(1, 0);\n")
	fn := functionNamed(t, bytecode, "f")

	if strings.Join(fn.Params, ",") != "alpha,beta" {
		t.Errorf("Params = %v, want [alpha beta]", fn.Params)
	}
	if len(fn.Params) != fn.NumParams {
		t.Errorf("%d names for %d parameters", len(fn.Params), fn.NumParams)
	}

	bytecode.StripDebugInfo()
	if fn.Params != nil {
		t.Errorf("a stripped function still names its parameters: %v", fn.Params)
	}
}

// An anonymous literal has no name to report and must still compile, carry
// spans, and strip cleanly.
func TestAnonymousFunctionsStillCarrySpans(t *testing.T) {
	bytecode := compileWithSource(t, "let apply = fn(g) { return g(1); };\napply(fn(x) { return x / 0; });\n")

	var anonymous int
	for _, constant := range bytecode.Constants {
		fn, ok := constant.(*object.CompiledFunction)
		if !ok || fn.Name != "" {
			continue
		}
		anonymous++
		if fn.EndTable.Empty() {
			t.Error("an anonymous function carries no end positions")
		}
	}
	if anonymous == 0 {
		t.Fatal("the program produced no anonymous function")
	}
}
