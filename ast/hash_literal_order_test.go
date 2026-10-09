package ast_test

import (
	"testing"

	"mutant/ast"
	"mutant/lexer"
	"mutant/parser"
)

// A hash literal keeps its pairs in the order they were written, and every
// rendering of one has to show that order. It matters here because Clone and
// Modify carry the pairs over and a tree compared against its own copy through
// String() is how this package tests itself: while the pairs were a Go map,
// ranging it directly made both clone tests coin flips -- they failed on
// Windows, Linux and macOS CI on different runs and passed locally, which reads
// like a platform bug and is not one.
//
// These pin the property directly, so a regression fails here with a plain
// message instead of resurfacing as an intermittent clone failure.
func hashLiteralFrom(t *testing.T, source string) *ast.HashLiteral {
	t.Helper()

	p := parser.New(lexer.New(source))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("source did not parse: %s", errs[0])
	}

	let, ok := program.Statements[0].(*ast.LetStatement)
	if !ok {
		t.Fatalf("expected a let statement, got %T", program.Statements[0])
	}
	hash, ok := let.Value.(*ast.HashLiteral)
	if !ok {
		t.Fatalf("expected a hash literal, got %T", let.Value)
	}
	return hash
}

const hashOrderSource = `let table = {"c": 3, "a": 1, "b": 2, "d": 4, "e": 5, "f": 6};`

// Written order, which is the order both engines evaluate the pairs in. This
// wanted `{a:1, b:2, c:3, d:4, e:5, f:6}` until M26-CMP-010 -- the pairs sorted
// by key, because they lived in a map and the compiler sorted them before
// emitting them. Sorting was never the language rule, only the one order a map
// could be made to produce twice in a row.
func TestHashLiteralPrintsItsPairsInSourceOrder(t *testing.T) {
	const want = "{c:3, a:1, b:2, d:4, e:5, f:6}"

	if got := hashLiteralFrom(t, hashOrderSource).String(); got != want {
		t.Fatalf("hash literal printed %s, want %s", got, want)
	}
}

// One tree, printed repeatedly. This was the first symptom: the pairs lived in
// a Go map, Go randomises map iteration per range, and six pairs rendered
// without a sort disagree with themselves almost immediately.
func TestHashLiteralPrintsTheSameStringEveryTime(t *testing.T) {
	hash := hashLiteralFrom(t, hashOrderSource)

	first := hash.String()
	for i := 0; i < 100; i++ {
		if got := hash.String(); got != first {
			t.Fatalf("rendering %d printed %s, first printed %s", i, got, first)
		}
	}
}

// Two trees parsed separately from one source. Each used to hold its own map,
// seeded independently, so this catches an ordering that is stable within one
// tree but not between two of them -- which is the case Clone actually creates.
func TestTwoParsesOfOneHashLiteralPrintAlike(t *testing.T) {
	first := hashLiteralFrom(t, hashOrderSource).String()
	second := hashLiteralFrom(t, hashOrderSource).String()

	if first != second {
		t.Fatalf("two parses of one source printed differently: first %s, second %s", first, second)
	}
}

// And the clone, which is the path that failed in CI.
func TestACloneOfAHashLiteralPrintsLikeItsOriginal(t *testing.T) {
	hash := hashLiteralFrom(t, hashOrderSource)

	clone, ok := ast.Clone(hash).(*ast.HashLiteral)
	if !ok || clone == nil {
		t.Fatal("cloning a hash literal did not return a hash literal")
	}
	if got, want := clone.String(), hash.String(); got != want {
		t.Fatalf("the clone printed %s, the original printed %s", got, want)
	}
}
