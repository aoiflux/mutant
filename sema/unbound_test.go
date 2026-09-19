package sema

import "testing"

// What the graph records for a name it cannot bind, and what it refuses to
// record.
//
// The walk used to drop these on the floor, and the language server kept a
// second scope chain of its own to find them again. The list exists so that it
// does not have to -- and it is a list of its own, not a Ref with no target,
// because everything that reads a Ref jumps somewhere.

func unboundNames(g *Graph) []string {
	names := make([]string, 0, 4)
	for _, miss := range g.UnboundUses() {
		names = append(names, miss.Name+"("+miss.Kind.String()+")")
	}
	return names
}

func onlyUnbound(t *testing.T, g *Graph, want string) Unbound {
	t.Helper()
	misses := g.UnboundUses()
	if len(misses) != 1 || misses[0].Name != want {
		t.Fatalf("unbound = %v, want exactly [%s]", unboundNames(g), want)
	}
	return misses[0]
}

func TestANameWithNoDeclarationIsRecordedAsAMissAndNotAsAReference(t *testing.T) {
	g := graphOf(t, "nope;\n")

	if refs := g.References(); len(refs) != 0 {
		t.Fatalf("an unbound name produced %d references; a reference is something "+
			"go-to-definition will follow", len(refs))
	}
	miss := onlyUnbound(t, g, "nope")
	if miss.Kind != UnboundValue {
		t.Fatalf("kind = %s, want value", miss.Kind)
	}
	if !miss.UseRange.IsValid() {
		t.Fatal("the miss has no range, so nothing could point at it")
	}
}

func TestANameTheFileDeclaresIsNotAMiss(t *testing.T) {
	for _, src := range []string{
		"let x = 1;\nx;\n",
		"let f = fn(p) { p; };\n",
		"for (v in [1]) { v; }\n",
		"import util \"lib/util.mut\";\nutil;\n",
		"let f = fn() { f(); };\n",
	} {
		if g := graphOf(t, src); len(g.UnboundUses()) != 0 {
			t.Fatalf("%v reported for\n\n%s", unboundNames(g), src)
		}
	}
}

// A builtin is declared in no file, so it is a miss here. That is the contract,
// and the language server filters the registry out -- see sema.Unbound. If this
// ever stops being true, the rule that reads the list stops reporting names the
// compiler refuses, silently.
func TestABuiltinIsAMissBecauseNoFileDeclaresIt(t *testing.T) {
	onlyUnbound(t, graphOf(t, "len([1]);\n"), "len")
}

func TestTheLeftOfAFieldAccessKeepsTheMemberBesideIt(t *testing.T) {
	miss := onlyUnbound(t, graphOf(t, "hash.blake3(\"a\");\n"), "hash")

	if miss.Kind != UnboundReceiver {
		t.Fatalf("kind = %s, want receiver", miss.Kind)
	}
	if miss.Member != "blake3" {
		t.Fatalf("member = %q, want blake3 -- without it `hash.blake3` cannot be "+
			"told from a bare `hash`, and one of those is a real builtin", miss.Member)
	}
	if !miss.WholeRange.IsValid() {
		t.Fatal("the whole expression has no range, so a complaint about the " +
			"member could only be pointed at the receiver")
	}
	if miss.WholeRange == miss.UseRange {
		t.Fatal("the whole expression and the receiver have the same range")
	}
}

// An enum declared ABOVE the use resolves; the same enum declared below does
// not. The compiler refuses the second -- "undefined variable: Colour" -- and a
// whole-file answer would call them both fine.
func TestAnEnumIsBoundOnlyBelowItsDeclaration(t *testing.T) {
	if g := graphOf(t, "enum Colour { Red };\nColour.Red;\n"); len(g.UnboundUses()) != 0 {
		t.Fatalf("%v reported for an enum used after it is declared", unboundNames(g))
	}
	miss := onlyUnbound(t, graphOf(t, "Colour.Red;\nenum Colour { Red };\n"), "Colour")
	if miss.Kind != UnboundReceiver {
		t.Fatalf("kind = %s, want receiver", miss.Kind)
	}
}

// A struct literal names a type, which lives in a different table from values.
// `let Point = 1;` binds the name and does not give the literal a type, which
// is what the compiler says too: "undefined struct type: Point".
func TestAStructLiteralAsksTheTypeTableAndNotTheValueTable(t *testing.T) {
	if g := graphOf(t, "struct Point { x };\nPoint{x: 1};\n"); len(g.UnboundUses()) != 0 {
		t.Fatalf("%v reported for a literal of a declared struct", unboundNames(g))
	}

	miss := onlyUnbound(t, graphOf(t, "let Point = 1;\nPoint{x: 1};\n"), "Point")
	if miss.Kind != UnboundType {
		t.Fatalf("kind = %s, want type -- a value of that name is the wrong table", miss.Kind)
	}
}

// One mistake, not two. The field names of a literal whose type is unknown are
// not uses of anything, and reporting them would be reporting the half the
// author got right.
func TestAFieldOfAnUnknownStructIsNotAMissOfItsOwn(t *testing.T) {
	onlyUnbound(t, graphOf(t, "Nope{x: 1, y: 2};\n"), "Nope")
}

func TestACallRecordsThatItWasACall(t *testing.T) {
	if miss := onlyUnbound(t, graphOf(t, "quote(1);\n"), "quote"); !miss.InCall {
		t.Fatal("a call of an unbound name did not record that it was a call; " +
			"`quote(x)` is a macro special form and a bare `quote` is not")
	}
	if miss := onlyUnbound(t, graphOf(t, "quote;\n"), "quote"); miss.InCall {
		t.Fatal("a bare name recorded that it was a call")
	}
}

func TestTheMissesComeBackInSourceOrder(t *testing.T) {
	g := graphOf(t, "let h = {\"k\": aaa, \"j\": bbb};\nccc;\n")

	misses := g.UnboundUses()
	for i := 1; i < len(misses); i++ {
		if startsBefore(misses[i].UseRange, misses[i-1].UseRange) {
			t.Fatalf("misses out of order: %v -- a hash literal is a Go map, so "+
				"the walk reaches its entries in a different order every run, and "+
				"the diagnostics would be reported shuffled", unboundNames(g))
		}
	}
}

// Grouped, which used to be pinned in the language server's tests against a
// scope chain that no longer exists.
func TestALetThatBindsMoreThanOneNameSaysSo(t *testing.T) {
	g := graphOf(t, "let first, err = gets();\nlet single = 1;\n")

	for _, name := range []string{"first", "err"} {
		if !find(t, g, name).Grouped {
			t.Fatalf("%s came from a let binding two names and is not marked", name)
		}
	}
	if find(t, g, "single").Grouped {
		t.Fatal("a single-name let is marked as grouped")
	}
}
