package sema

import "testing"

// Node.FullRange's doc promised "the whole declaration -- the statement, not
// the name", and declare passed one range in twice, so for everything except an
// import it held the name. The doc was right about the intent and wrong about
// the scope, and one consumer was visibly wrong because of it: a call hierarchy
// item's Range and SelectionRange were the same few characters.
//
// The rule these tests pin is per-kind, because it is not one answer for every
// declaration. The four statements that declare -- `let`, `struct`, `enum`,
// `import` -- reach over the statement. A parameter and a loop binding are
// made by an expression and a loop header rather than by a statement; a field
// and a variant are parts of the type their statement declares. Those four are
// their own name and no more.

func TestFullRangeReachesPastTheNameForEveryStatementThatDeclares(t *testing.T) {
	g := graphOf(t, "let total = fn(xs) {\n\tlet n = 0;\n\treturn n;\n};\n"+
		"struct Point {\n\tx,\n\ty\n}\n"+
		"enum Colour {\n\tRed,\n\tBlue\n}\n"+
		"import rep \"lib/report.mut\";\n")

	// The three multi-line statements: the declaration outlives its own name by
	// at least a line, which is the whole point of having two ranges.
	for _, name := range []string{"total", "Point", "Colour"} {
		node := find(t, g, name)
		if !node.DeclRange.IsValid() || !node.FullRange.IsValid() {
			t.Fatalf("%s: both ranges should exist; decl=%+v full=%+v",
				name, node.DeclRange, node.FullRange)
		}
		if node.FullRange == node.DeclRange {
			t.Fatalf("%s: FullRange equals DeclRange (%+v), so it is the name and "+
				"not the declaration -- an editor asking for this symbol's range "+
				"gets back its selectionRange", name, node.DeclRange)
		}
		if node.FullRange.End.Line <= node.DeclRange.End.Line {
			t.Fatalf("%s: the declaration spans several lines but FullRange ends on "+
				"line %d, the same line as the name", name, node.FullRange.End.Line)
		}
	}

	// A `let` binding several names is one declaration of all of them, so each
	// reaches over the statement they share. This is the row that decides the
	// rule: read as "nothing wider declares this one name" it would come out
	// the other way, and the code, Grouped, and an editor framing the
	// declaration all want the statement.
	grouped := graphOf(t, "let value, err = read(\"p\");\n")
	for _, name := range []string{"value", "err"} {
		node := find(t, grouped, name)
		if !node.Grouped {
			t.Fatalf("%s came from a let binding two names and is not marked Grouped", name)
		}
		if node.FullRange == node.DeclRange {
			t.Fatalf("%s: FullRange is the name %+v -- the one `let` is the "+
				"declaration of both names it binds", name, node.DeclRange)
		}
		if node.FullRange.Start.Column != 1 {
			t.Fatalf("%s: the declaration starts at column %d, want 1 -- the `let`",
				name, node.FullRange.Start.Column)
		}
	}

	// The import is one line, so the reach shows in the column: the statement
	// starts at `import`, the name eight characters later.
	alias := find(t, g, "rep")
	if alias.FullRange.Start.Column != 1 {
		t.Fatalf("the import's FullRange starts at column %d, want 1 -- the "+
			"`import`, not the alias after it", alias.FullRange.Start.Column)
	}
	if alias.DeclRange.Start.Column <= alias.FullRange.Start.Column {
		t.Fatalf("the alias should start after the statement does; decl=%+v full=%+v",
			alias.DeclRange, alias.FullRange)
	}
}

func TestFullRangeIsTheNameWhereNoStatementDeclaresIt(t *testing.T) {
	g := graphOf(t, "let f = fn(a, b) {\n\tfor (k, v in [1]) {\n\t\tk;\n\t\tv;\n\t\ta;\n\t\tb;\n\t}\n};\n"+
		"struct Point {\n\tx\n}\n"+
		"enum Colour {\n\tRed\n}\n")

	// A parameter, a loop binding, a field and a variant. `fn(a, b)` is a value
	// and `for (k, v in ...)` is a loop, so neither is a declaration; `x` and
	// `Red` are parts of the type their statement declares, not declarations
	// standing beside it.
	for _, name := range []string{"a", "b", "k", "v", "x", "Red"} {
		node := find(t, g, name)
		if node.FullRange != node.DeclRange {
			t.Fatalf("%s: FullRange %+v is wider than the name %+v. The construct "+
				"around this name declares more than one name, so it is not this "+
				"one's declaration -- see Node.FullRange",
				name, node.FullRange, node.DeclRange)
		}
	}
}

// The protocol requires a symbol's selectionRange to be contained by its range,
// and go-to-definition points inside the span the outline highlights. Both come
// out of these two fields, so containment is the invariant, not a formality.
func TestEveryDeclarationIsContainedByItsOwnFullRange(t *testing.T) {
	g := graphOf(t, "import rep \"lib/report.mut\";\n"+
		"import \"lib/derived.mut\";\n"+
		"struct Point {\n\tx,\n\ty\n}\n"+
		"enum Colour {\n\tRed,\n\tBlue\n}\n"+
		"let value, err = read(\"p\");\n"+
		"let f = fn(a, b) {\n\tlet inner = 1;\n\tfor (k, v in [1]) {\n\t\tinner;\n\t}\n\treturn a;\n};\n")

	declarations := g.Declarations()
	if len(declarations) < 12 {
		t.Fatalf("only %d declarations were found, so this is not exercising the "+
			"kinds it means to: %v", len(declarations), declaredNames(g))
	}

	for _, node := range declarations {
		if !node.FullRange.IsValid() {
			t.Fatalf("%s(%s) has no FullRange, so nothing can point at it",
				node.Name, node.Kind)
		}
		if !node.DeclRange.IsValid() {
			// A derived import binds a name that was never written. Anchor falls
			// back to the statement, which is why FullRange has to exist.
			continue
		}
		if before(node.DeclRange.Start.Line, node.DeclRange.Start.Column,
			node.FullRange.Start.Line, node.FullRange.Start.Column) {
			t.Fatalf("%s(%s): the name starts before the declaration does; decl=%+v full=%+v",
				node.Name, node.Kind, node.DeclRange, node.FullRange)
		}
		if before(node.FullRange.End.Line, node.FullRange.End.Column,
			node.DeclRange.End.Line, node.DeclRange.End.Column) {
			t.Fatalf("%s(%s): the name ends after the declaration does; decl=%+v full=%+v",
				node.Name, node.Kind, node.DeclRange, node.FullRange)
		}
	}
}

// Widening FullRange cannot change what a position means, because DeclarationAt
// keys off DeclRange and ReferenceAt off UseRange. That is worth a test rather
// than a comment: it is exactly the kind of fact that stays true until someone
// unifies the two fields for tidiness, and the failure would be a cursor inside
// a function body resolving to the function.
func TestAPositionInsideADeclarationStillResolvesToWhatIsWrittenThere(t *testing.T) {
	g := graphOf(t, "let f = fn(a) {\n\tlet inner = a;\n\treturn inner;\n};\n")

	enclosing := find(t, g, "f")
	if enclosing.FullRange.End.Line < 4 {
		t.Fatalf("this test is meaningless unless f reaches over the body; full=%+v",
			enclosing.FullRange)
	}

	for _, name := range []string{"a", "inner"} {
		declared := find(t, g, name)
		uses := g.UsesOf(declared.ID)
		if len(uses) == 0 {
			t.Fatalf("%s is used in the body but the graph recorded no use", name)
		}
		for _, use := range uses {
			resolved, ok := g.Resolve(use.Start.Line, use.Start.Column)
			if !ok {
				t.Fatalf("a use of %s at %+v resolved to nothing", name, use.Start)
			}
			if resolved.ID != declared.ID {
				t.Fatalf("a use of %s at %+v resolved to %s(%s) -- a position inside "+
					"f's FullRange must still mean what is written at it",
					name, use.Start, resolved.Name, resolved.Kind)
			}
		}
	}
}
