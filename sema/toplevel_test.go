package sema

import "testing"

// A bare name is the case the language server used to answer by matching
// strings across every open file. These pin the far narrower answer that is
// actually true, each row checked against the compiler before it was written
// down -- see parity/bare_name_parity_test.go, which runs the same programs
// through the real thing.

// typeFixture: main imports lib, which declares the types; sibling is reachable
// from main but not from lib, and stray is reachable from nothing.
var typeFixture = map[string]string{
	"main.mut": `
import lib "lib/types.mut";
import sibling "lib/sibling.mut";
let p = fn() { return Point{x: 1, y: 2}; };
`,
	"lib/types.mut": `
struct Point { x, y };
enum Colour { Red, Green };
struct _Secret { a };
let helper = fn() { return 1; };
let _hidden = 2;
`,
	"lib/sibling.mut": `
let mk = fn() { return 1; };
`,
	"stray.mut": `
struct Unreachable { z };
`,
}

func TestAStructNameCrossesAModuleBoundaryWrittenBare(t *testing.T) {
	w, key := workspaceOf(t, typeFixture)

	declared, owner, ok := w.ResolveTopLevel(key("main.mut"), "Point")
	if !ok {
		t.Fatal("Point does not resolve from main.mut, but the compiler accepts it")
	}
	if owner != key("lib/types.mut") {
		t.Fatalf("Point resolved to %q, want lib/types.mut", owner)
	}
	if declared.Kind != SymStruct {
		t.Fatalf("Point resolved as kind %v, want SymStruct", declared.Kind)
	}
	if got := declared.Members; len(got) != 2 || got[0] != "x" || got[1] != "y" {
		t.Fatalf("Point fields = %v, want [x y]", got)
	}
}

func TestAnEnumNameCrossesTheSameWay(t *testing.T) {
	w, key := workspaceOf(t, typeFixture)

	declared, _, ok := w.ResolveTopLevel(key("main.mut"), "Colour")
	if !ok {
		t.Fatal("Colour does not resolve from main.mut")
	}
	if declared.Kind != SymEnum {
		t.Fatalf("Colour resolved as kind %v, want SymEnum", declared.Kind)
	}
}

// The whole reason the old index was wrong. An import binds one namespace; it
// does not put the imported file's values into this file's scope.
func TestAValueDoesNotCrossAModuleBoundaryWrittenBare(t *testing.T) {
	w, key := workspaceOf(t, typeFixture)

	for _, name := range []string{"helper", "_hidden"} {
		if _, owner, ok := w.ResolveTopLevel(key("main.mut"), name); ok {
			t.Fatalf("bare %s resolved to %s, but the compiler says "+
				"undefined variable: %s", name, owner, name)
		}
	}
}

// Surprising, and checked rather than assumed: the underscore rule is a
// symbol-table rule, and a type name never reaches the symbol table. `struct
// _Secret` in another module compiles when written bare here, so the editor
// must resolve it. Refusing would be refusing a program that builds.
func TestAnUnderscoredTypeStillCrossesBecauseTypesAreNotSymbols(t *testing.T) {
	w, key := workspaceOf(t, typeFixture)

	if _, _, ok := w.ResolveTopLevel(key("main.mut"), "_Secret"); !ok {
		t.Fatal("_Secret was refused, but the compiler accepts it: " +
			"IsModulePrivate governs the symbol table, and types are not symbols")
	}
}

// A file outside the closure is not a jump target however well its names match.
// This is the bug the old UniqueTopLevelDefinition shipped.
func TestATypeOutsideTheClosureDoesNotResolve(t *testing.T) {
	w, key := workspaceOf(t, typeFixture)

	if _, owner, ok := w.ResolveTopLevel(key("main.mut"), "Unreachable"); ok {
		t.Fatalf("Unreachable resolved to %s, which main.mut never imports", owner)
	}
}

// Closure, not "the whole workspace": main reaches both lib and sibling, but
// lib reaches neither sibling nor main. Asking from lib must not find Point's
// siblings.
func TestTheClosureIsDirectionalAndNotSymmetric(t *testing.T) {
	w, key := workspaceOf(t, typeFixture)

	// Sanity: sibling really is in the workspace and really is reachable from
	// main, so the refusal below is about direction and not about indexing.
	if _, _, ok := w.ResolveTopLevel(key("lib/types.mut"), "Point"); ok {
		t.Fatal("a module resolved its own declaration through ResolveTopLevel; " +
			"that is the file-local walk's answer to give")
	}
	if _, _, ok := w.ResolveTopLevel(key("lib/sibling.mut"), "Point"); ok {
		t.Fatal("sibling.mut resolved Point, which it does not import")
	}
}

// Two modules declaring one type name is a program claimTypeName refuses. There
// is no right answer to give, so none is given.
func TestAnAmbiguousTypeNameIsRefusedRatherThanGuessedAt(t *testing.T) {
	w, key := workspaceOf(t, map[string]string{
		"main.mut": `
import a "a.mut";
import b "b.mut";
let x = 1;
`,
		"a.mut": "struct Dup { p };\n",
		"b.mut": "struct Dup { q };\n",
	})

	if _, owner, ok := w.ResolveTopLevel(key("main.mut"), "Dup"); ok {
		t.Fatalf("Dup resolved to %s, but two modules declare it and the "+
			"compiler refuses the whole program", owner)
	}
}

func TestTheDefinitionOfACrossModuleTypeCarriesAURIAndARange(t *testing.T) {
	w, key := workspaceOf(t, typeFixture)

	uri, declRange, ok := w.TypeDefinition(key("main.mut"), "Point")
	if !ok {
		t.Fatal("Point has no definition")
	}
	if want, _ := w.URIOf(key("lib/types.mut")); uri != want {
		t.Fatalf("definition URI = %q, want %q", uri, want)
	}
	if !declRange.IsValid() {
		t.Fatal("definition range is not valid")
	}
	if declRange.Start.Line != 2 {
		t.Fatalf("definition is at line %d, want 2 -- ranges must be "+
			"file-local to the declaring module", declRange.Start.Line)
	}
}

// Importers is the reverse of Closure, and it is the set a find-references has
// to walk: a use of lib/types.mut's Point can only be written in a file that
// reaches lib/types.mut.
func TestImportersIsEveryModuleThatReachesTheTarget(t *testing.T) {
	w, key := workspaceOf(t, typeFixture)

	got := w.Importers(key("lib/types.mut"))
	want := []string{key("lib/types.mut"), key("main.mut")}
	if len(got) != len(want) {
		t.Fatalf("importers of lib/types.mut = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("importers of lib/types.mut = %v, want %v", got, want)
		}
	}

	// stray.mut is imported by nothing, so it is reached only by itself.
	if got := w.Importers(key("stray.mut")); len(got) != 1 || got[0] != key("stray.mut") {
		t.Fatalf("importers of stray.mut = %v, want just itself", got)
	}
}

// One module imported twice binds two namespaces, and both spellings are real
// uses. A reference walk that knew only the first would silently miss the rest.
func TestAModuleImportedTwiceReportsBothAliases(t *testing.T) {
	w, key := workspaceOf(t, map[string]string{
		"main.mut": `
import first "lib.mut";
import second "lib.mut";
let x = 1;
`,
		"lib.mut": "let mean = fn(xs) { return 0; };\n",
	})

	got := w.AliasesFor(key("main.mut"), key("lib.mut"))
	if len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("aliases = %v, want [first second]", got)
	}

	if got := w.AliasesFor(key("lib.mut"), key("main.mut")); got != nil {
		t.Fatalf("lib.mut binds %v to main.mut, but it imports nothing", got)
	}
}
