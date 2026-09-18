package sema

import (
	"strconv"
	"strings"
	"testing"

	"mutant/ast"
	"mutant/lexer"
	"mutant/parser"
)

// What the one walk costs.
//
// It replaces five, but not one-for-one: the old walks each ran per query and
// stopped early, while this one runs once per document version and finishes.
// The trade is deliberate -- a query is then a lookup -- and the number worth
// watching is the build, because it is what a document pays on the first
// position question after every edit.
func buildSource(functions int) string {
	var sb strings.Builder
	sb.WriteString("import lib \"lib/shared.mut\";\n")
	sb.WriteString("struct Point { x; y; };\n")
	sb.WriteString("enum Colour { Red, Green, Blue };\n")
	for i := 0; i < functions; i++ {
		n := strconv.Itoa(i)
		sb.WriteString("let v" + n + " = fn(a, b) {\n")
		sb.WriteString("  let scaled = a + b;\n")
		sb.WriteString("  for (item in [a, b]) { scaled = scaled + item; }\n")
		sb.WriteString("  return v0(scaled, Colour.Red) + lib.helper(scaled);\n")
		sb.WriteString("};\n")
	}
	return sb.String()
}

func BenchmarkBuildFile(b *testing.B) {
	for _, functions := range []int{50, 400} {
		b.Run(strconv.Itoa(functions)+"-functions", func(b *testing.B) {
			program := parseForBench(b, buildSource(functions))
			b.ResetTimer()
			for b.Loop() {
				BuildFile("bench", program, nil, nil)
			}
		})
	}
}

// A query after the build. Find-references walks every reference in the file
// once, which is the cost of not keeping a reverse index -- and not keeping one
// is what makes an edit cost nothing to undo.
func BenchmarkUsesOf(b *testing.B) {
	g := BuildFile("bench", parseForBench(b, buildSource(400)), nil, nil)
	var target DeclID
	for _, node := range g.Declarations() {
		if node.Name == "v0" {
			target = node.ID
		}
	}

	b.ResetTimer()
	for b.Loop() {
		if len(g.UsesOf(target)) != 400 {
			b.Fatalf("v0 is called once per function; got %d", len(g.UsesOf(target)))
		}
	}
}

func BenchmarkVisibleAt(b *testing.B) {
	source := buildSource(400)
	g := BuildFile("bench", parseForBench(b, source), nil, nil)
	line := strings.Count(source, "\n") - 2

	b.ResetTimer()
	for b.Loop() {
		if len(g.VisibleAt(line, 3)) == 0 {
			b.Fatal("nothing is visible near the end of the file")
		}
	}
}

func parseForBench(b *testing.B, src string) *ast.Program {
	b.Helper()
	p := parser.New(lexer.New(src))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		b.Fatalf("benchmark fixture did not parse: %v", errs)
	}
	return program
}
