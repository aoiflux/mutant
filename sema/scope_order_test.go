package sema

import (
	"strconv"
	"strings"
	"testing"

	"mutant/lexer"
	"mutant/parser"
)

// Scopes are held in source order, and scopeAt depends on it.
//
// Finding the scope that covers a position used to be a scan: look at every
// child of every scope on the way down and take the first that contains the
// position. That is correct whatever order the children are in, and it costs a
// pass over every function in the file, once per name any caller asks about --
// which is once per call site, because the builtin rules ask about each call
// they see. Over four hundred functions one such question cost 1.9us; it now
// costs 70ns and does not grow with the file.
//
// The search that makes it flat needs the children sorted, and the walk does
// not produce them sorted: ast.HashLiteral.Pairs is a Go map, so a function
// literal written inside one is reached whenever the map hands it over. That
// same non-determinism already made HashLiteral.String disagree with itself and
// find-references return shuffled locations, and BuildFile already sorts the
// references it produces because of it.
//
// So this is a test about an invariant rather than about an answer. An
// unsorted build does not fail outright -- it finds the right scope on the runs
// where the map happened to agree with the source, and an enclosing one on the
// rest, which reads as the editor intermittently forgetting a parameter. That
// is the worst shape a defect can have, and it is why the property is asserted
// directly instead of through a query that would usually pass.

// hashOfFunctions is the fixture: sibling function scopes reachable only
// through a map. Twelve of them, so that a build which left them in walk order
// would have to draw the sorted permutation of twelve to pass once.
func hashOfFunctions(pairs int) string {
	var sb strings.Builder
	sb.WriteString("let table = {\n")
	for i := 0; i < pairs; i++ {
		n := strconv.Itoa(i)
		sb.WriteString("  \"k" + n + "\": fn(arg" + n + ") { return arg" + n + " + " + n + "; },\n")
	}
	sb.WriteString("};\n")
	return sb.String()
}

func TestEveryScopeHoldsItsChildrenInSourceOrder(t *testing.T) {
	source := hashOfFunctions(12)

	// Rebuilt several times because the order being tested is drawn afresh on
	// every walk. One build that happened to come out sorted proves nothing.
	for attempt := 0; attempt < 8; attempt++ {
		program := parser.New(lexer.New(source)).ParseProgram()
		g := BuildFile("k", program, nil, nil)

		var check func(scope *Scope)
		check = func(scope *Scope) {
			for i := 1; i < len(scope.Children); i++ {
				previous, current := scope.Children[i-1], scope.Children[i]
				if startsBefore(current.Range, previous.Range) {
					t.Fatalf("scope %q holds its children out of source order: %q starts at "+
						"%d:%d, after %q at %d:%d.\n\nscopeAt binary-searches them, so an "+
						"unsorted scope sends a query to an ancestor of the one it wanted.",
						scope.Path, current.Path, current.Range.Start.Line, current.Range.Start.Column,
						previous.Path, previous.Range.Start.Line, previous.Range.Start.Column)
				}
			}
			for _, child := range scope.Children {
				check(child)
			}
		}
		check(g.Root)
	}
}

// TestAParameterIsFoundInsideAFunctionReachedThroughAMap is the answer the
// invariant above exists to protect, asked directly.
//
// Each function in the table binds one parameter and nothing else binds it, so
// a query that landed in the wrong scope -- or in the root -- reports it
// unbound. It is the same question the builtin rules ask before deciding a call
// is a builtin call.
func TestAParameterIsFoundInsideAFunctionReachedThroughAMap(t *testing.T) {
	const pairs = 12
	source := hashOfFunctions(pairs)
	program := parser.New(lexer.New(source)).ParseProgram()
	g := BuildFile("k", program, nil, nil)

	for i := 0; i < pairs; i++ {
		name := "arg" + strconv.Itoa(i)
		// The body is written on the pair's own line, which is the second line
		// of the file plus however many pairs precede it.
		line := 2 + i
		column := strings.Index(strings.Split(source, "\n")[line-1], "return") + 1

		if !g.LocalScopeAt(line, column).Bound(name) {
			t.Fatalf("%s is not bound inside the function that declares it, at %d:%d",
				name, line, column)
		}
		// And it is bound there and nowhere else: a query in a sibling must not
		// find it, or the scopes are not telling the positions apart at all.
		other := 2 + (i+1)%pairs
		if g.LocalScopeAt(other, column).Bound(name) {
			t.Fatalf("%s is bound inside a different function's body, at line %d", name, other)
		}
	}
}
