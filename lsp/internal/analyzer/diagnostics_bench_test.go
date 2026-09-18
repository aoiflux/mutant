package analyzer

import (
	"strconv"
	"strings"
	"testing"
)

// The keystroke path, on the shape that used to be worst for it.
//
// The unused-declaration rules ask "is this name used anywhere?" once per
// top-level declaration, and that question used to be answered by walking the
// whole file: a document with four hundred declarations paid four hundred full
// recursive descents of its own AST, on every analysis, and analysis runs on
// every change.
//
// It is now one walk -- sema.BuildFile, built lazily on the first question --
// and four hundred scans of a flat list of references. The cost of the walk
// stopped scaling with how many questions are asked of it.
//
// The fixture is deliberately half-used: a declaration that IS used and one
// that is not exercise different paths through the rule, and a file where
// nothing is used would let an implementation that gives up early look fast.
func buildDiagnosticsSource(declarations int) string {
	var sb strings.Builder
	sb.WriteString("struct Point { x; y; };\n")
	for i := 0; i < declarations; i++ {
		n := strconv.Itoa(i)
		sb.WriteString("let v" + n + " = fn(a, b) {\n")
		sb.WriteString("  let p = Point{x: a, y: b};\n")
		sb.WriteString("  return p.x + p.y;\n")
		sb.WriteString("};\n")
		if i%2 == 0 {
			sb.WriteString("v" + n + "(1, 2);\n")
		}
	}
	return sb.String()
}

func BenchmarkDiagnosticsLargeDocument(b *testing.B) {
	for _, declarations := range []int{50, 400} {
		b.Run(strconv.Itoa(declarations)+"-declarations", func(b *testing.B) {
			src := buildDiagnosticsSource(declarations)
			analyzer := New()
			b.ResetTimer()
			for b.Loop() {
				// A fresh snapshot each time: that is what a keystroke
				// produces, and it is what makes the lazily-built graph a cost
				// paid per change rather than once per process.
				if len(Diagnostics(analyzer.Analyze(src), LintConfig{})) == 0 {
					b.Fatal("the fixture should report its unused declarations")
				}
			}
		})
	}
}
