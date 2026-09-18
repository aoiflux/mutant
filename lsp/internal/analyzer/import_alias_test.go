package analyzer

import (
	"strings"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// An import alias is an ordinary binding. It was not one.
//
// The five walks this package used to do -- resolveStatement, scopeAtStatement,
// advanceStatement, collectStatement and structTypeNameInStatement -- had no
// case for *ast.ImportStatement between them. So `report` in
// `import report "lib/report.mut";` had no definition to go to, no references,
// and was not offered in completion, while the comment above isBoundAt listed
// "an import namespace" among the things VisibleBindingsAt returns. The one
// place that knew better was a sixth walk, importNamespaces, which scanned the
// top level for this and nothing else.
//
// These are that gap, stated as the four things a user notices.

const aliasSource = "import report \"lib/report.mut\";\n" +
	"let total = 1;\n" +
	"report.label();\n" +
	"report.total();\n"

func TestTheAliasAnImportBindsIsOfferedInCompletion(t *testing.T) {
	s := New().Analyze(aliasSource)

	for _, item := range s.CompletionItemsAt(lsp.Position{Line: 2, Character: 0}) {
		if item.Label != "report" {
			continue
		}
		if item.Kind == nil || *item.Kind != lsp.CompletionItemKindModule {
			t.Fatalf("the alias is offered as kind %v, want Module", item.Kind)
		}
		return
	}
	t.Fatal("the alias an import binds is not offered in completion")
}

func TestGoingToTheDefinitionOfAnAliasLandsOnTheAlias(t *testing.T) {
	s := New().Analyze(aliasSource)

	// The `report` of `report.label()`.
	location, ok := s.DefinitionLocation("file:///t.mut", lsp.Position{Line: 2, Character: 2})
	if !ok || location == nil {
		t.Fatal("the alias has no definition to go to")
	}
	want := lsp.Range{
		Start: lsp.Position{Line: 0, Character: 7},
		End:   lsp.Position{Line: 0, Character: 13},
	}
	if location.Range != want {
		t.Fatalf("definition lands at %+v, want the alias on line 0 at %+v",
			location.Range, want)
	}
}

func TestReferencesToAnAliasFindEveryUseInTheFile(t *testing.T) {
	s := New().Analyze(aliasSource)

	locations, ok := s.ReferenceLocations("file:///t.mut", lsp.Position{Line: 2, Character: 2}, true)
	if !ok {
		t.Fatal("the alias has no references")
	}
	if len(locations) != 3 {
		t.Fatalf("reference count = %d, want 3: the alias and its two uses; got %+v",
			len(locations), locations)
	}
	for i, wantLine := range []uint32{0, 2, 3} {
		if locations[i].Range.Start.Line != wantLine {
			t.Fatalf("reference %d is on line %d, want %d -- declaration first, "+
				"then the uses in source order",
				i, locations[i].Range.Start.Line, wantLine)
		}
	}
}

func TestAnAliasIsVisibleWhereItIsUsed(t *testing.T) {
	s := New().Analyze(aliasSource)

	if !s.isBoundAt("report", lsp.Position{Line: 2, Character: 0}) {
		t.Fatal("the alias is not bound where it is used")
	}

	names := make([]string, 0, 2)
	for _, b := range s.VisibleBindingsAt(lsp.Position{Line: 2, Character: 0}) {
		if b.ident != nil {
			names = append(names, b.ident.Value)
		}
	}
	found := false
	for _, name := range names {
		if name == "report" {
			found = true
		}
	}
	if !found {
		t.Fatalf("VisibleBindingsAt does not list the alias; it returned %v", names)
	}
}

// `report.total()` and `let total = 1;` are different things that happen to
// share a name. Resolving the member as if it were the local was never possible
// here, but the alias becoming a binding makes it worth stating: what the alias
// names lives in another file, and this file's own `total` is not it.
func TestAMemberIsNotTheLocalOfTheSameName(t *testing.T) {
	s := New().Analyze(aliasSource)

	locations, ok := s.ReferenceLocations("file:///t.mut", lsp.Position{Line: 1, Character: 4}, true)
	if !ok {
		t.Fatal("the local `total` has no references")
	}
	if len(locations) != 1 {
		t.Fatalf("the local `total` has %d references, want just its own "+
			"declaration -- `report.total()` is a different file's name; got %+v",
			len(locations), locations)
	}
}

// A derived alias can be pointed at and must not be renamed: the name is not
// written anywhere, so every edit rename could make would be to text that means
// something else.
func TestADerivedAliasHasADefinitionButCannotBeRenamed(t *testing.T) {
	const src = "import \"lib/report.mut\";\nreport.label();\n"
	s := New().Analyze(src)

	location, ok := s.DefinitionLocation("file:///t.mut", lsp.Position{Line: 1, Character: 2})
	if !ok || location == nil {
		t.Fatal("a derived alias has no definition to go to")
	}
	if location.Range.Start.Line != 0 {
		t.Fatalf("definition lands on line %d, want the import on line 0",
			location.Range.Start.Line)
	}

	if s.RenameableAt(lsp.Position{Line: 1, Character: 2}) {
		t.Fatal("a derived alias was offered for rename; renaming it would edit " +
			"the uses and leave `import \"lib/report.mut\";` still binding the old name")
	}
	if _, _, ok := s.PrepareRename(lsp.Position{Line: 1, Character: 2}); ok {
		t.Fatal("prepareRename accepted a name that is not written anywhere")
	}

	locations, ok := s.ReferenceLocations("file:///t.mut", lsp.Position{Line: 1, Character: 2}, true)
	if !ok {
		t.Fatal("a derived alias should still have references")
	}
	for _, location := range locations {
		if location.Range.Start.Line == 0 {
			t.Fatalf("the import statement is offered as an editable occurrence "+
				"at %+v; rename would replace the path with the new name",
				location.Range)
		}
	}
}

// A written alias is renameable, and the edit covers the alias rather than the
// statement around it.
func TestAWrittenAliasIsRenameable(t *testing.T) {
	s := New().Analyze("import rep \"lib/report.mut\";\nrep.label();\n")

	name, rng, ok := s.PrepareRename(lsp.Position{Line: 1, Character: 1})
	if !ok {
		t.Fatal("a written alias should be renameable")
	}
	if name != "rep" {
		t.Fatalf("prepareRename offers %q, want rep", name)
	}
	if rng.Start.Line != 2 || rng.Start.Column != 1 {
		t.Fatalf("the rename range is %+v, want the use on line 2 column 1", rng.Start)
	}

	locations, ok := s.ReferenceLocations("file:///t.mut", lsp.Position{Line: 1, Character: 1}, true)
	if !ok || len(locations) != 2 {
		t.Fatalf("want the alias and its one use; got %+v", locations)
	}
	if locations[0].Range.Start.Character != 7 || locations[0].Range.End.Character != 10 {
		t.Fatalf("the declaration edit covers %+v, want just the `rep` at "+
			"characters 7-10", locations[0].Range)
	}
}

// Everything above, for the form that never writes the name.
//
// A derived alias has no identifier node, and every consumer here used to ask
// for one: completion skipped a binding whose ident was nil, isBoundAt compared
// ident.Value, and the predicate that decides whether a name is already taken
// -- the one guarding the builtin fold -- did the same. So `import
// "lib/hash.mut";` left `hash` looking unbound, and `hash.blake2` would have
// been read as the builtin hash_blake2 rather than as a reach into the module
// the author imported.
func TestADerivedAliasIsBoundEverythingThatAsksAboutNames(t *testing.T) {
	const src = "import \"lib/report.mut\";\nreport.label();\n"
	s := New().Analyze(src)
	pos := lsp.Position{Line: 1, Character: 0}

	if !s.isBoundAt("report", pos) {
		t.Fatal("a derived alias is not reported as bound, so the builtin fold " +
			"would take a name the author's import already claimed")
	}

	offered := false
	for _, item := range s.CompletionItemsAt(pos) {
		if item.Label == "report" {
			offered = true
		}
	}
	if !offered {
		t.Fatal("a derived alias is not offered in completion")
	}

	named := false
	for _, b := range s.VisibleBindingsAt(pos) {
		if b.name == "report" {
			named = true
			if b.ident != nil {
				t.Fatal("a derived alias should carry its name without an identifier")
			}
		}
	}
	if !named {
		t.Fatal("VisibleBindingsAt returns the derived alias without its name")
	}
}

// The name a derived import binds is a real claim on that name, and a builtin
// family of the same spelling does not override it. `hash` is a builtin family
// -- hash_blake2 and friends -- so this is the collision commit a901ce4 was
// about, arriving from the other direction.
func TestADerivedAliasBeatsABuiltinFamilyOfTheSameName(t *testing.T) {
	s := New().Analyze("import \"lib/hash.mut\";\nhash.blake2();\n")

	if !s.isBoundAt("hash", lsp.Position{Line: 1, Character: 0}) {
		t.Fatal("the import binds `hash`, so the builtin family does not")
	}

	// And the gate that actually decides it. boundAt is what tells
	// sema.ResolveField the name is taken, and it reads the binding's name --
	// which a derived alias has, and an identifier it does not.
	if name, _, folded := s.namespacedBuiltinAt(lsp.Position{Line: 1, Character: 6}); folded {
		t.Fatalf("`hash.blake2` folded to the builtin %q even though this file "+
			"imports a module called hash", name)
	}
	if text, _, ok := s.HoverText(lsp.Position{Line: 1, Character: 6}); ok &&
		strings.Contains(text, "hash_blake2") {
		t.Fatalf("hover offers the builtin card for a reach into the author's "+
			"own module: %q", text)
	}
}
