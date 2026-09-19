package sema

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/lexer"
	"mutant/parser"
)

// A macro is the third kind of name that crosses a module boundary, and the
// only one that crosses ONLY bare.
//
// `let twice = macro(x) {...}` reads like a top-level let and was filed as one,
// so the editor offered `a.twice` behind the dot and resolved it to the
// declaration. The compiler refuses that spelling outright: DefineMacros
// deletes the statement from the program before comp.Compile is called, so the
// module's scope never binds the name. The editor resolving a spelling the
// build refuses is the disagreement this package was written to remove.

func factsOfSource(t *testing.T, src string) *ModuleFacts {
	t.Helper()
	program := parser.New(lexer.New(src)).ParseProgram()
	return FactsOf("k", "file:///k", "k", program)
}

func TestAMacroIsNotAnExport(t *testing.T) {
	facts := factsOfSource(t, "let twice = macro(x) { quote(unquote(x) + unquote(x)); };\n"+
		"let plain = fn(x) { return x; };\n")

	if _, exported := facts.Exports["twice"]; exported {
		t.Fatal("a macro was filed among the exports, which offers `ns.twice` -- " +
			"a spelling the compiler refuses, because the declaration is deleted " +
			"before the module's scope is built")
	}
	if _, isMacro := facts.Macros["twice"]; !isMacro {
		t.Fatalf("the macro was not recorded at all; macros = %v", facts.Macros)
	}
	if _, exported := facts.Exports["plain"]; !exported {
		t.Fatal("the ordinary function beside it stopped being an export")
	}
}

func TestAMacroCarriesItsParameterNames(t *testing.T) {
	facts := factsOfSource(t, "let pair = macro(a, b) { quote(unquote(a)); };\n")

	macro, found := facts.Macros["pair"]
	if !found {
		t.Fatal("no macro recorded")
	}
	if len(macro.Params) != 2 || macro.Params[0] != "a" || macro.Params[1] != "b" {
		t.Fatalf("params = %v, want [a b] -- arity is the one thing a caller can "+
			"get wrong before the program has any values in it", macro.Params)
	}
	if !macro.DeclRange.IsValid() {
		t.Fatal("the macro has no declaration range, so nothing can jump to it")
	}
}

// The hash answers "could this edit have changed what another module sees?".
// A macro is visible to other modules, so it has to be in the answer.
func TestAddingAMacroChangesTheHash(t *testing.T) {
	without := factsOfSource(t, "let plain = fn(x) { return x; };\n")
	with := factsOfSource(t, "let plain = fn(x) { return x; };\n"+
		"let twice = macro(x) { quote(unquote(x)); };\n")
	renamed := factsOfSource(t, "let plain = fn(x) { return x; };\n"+
		"let thrice = macro(x) { quote(unquote(x)); };\n")
	reparam := factsOfSource(t, "let plain = fn(x) { return x; };\n"+
		"let twice = macro(a, b) { quote(unquote(a)); };\n")

	if without.Hash == with.Hash {
		t.Fatal("adding a macro did not change the hash, so no importer would be re-asked")
	}
	if with.Hash == renamed.Hash {
		t.Fatal("renaming a macro did not change the hash")
	}
	if with.Hash == reparam.Hash {
		t.Fatal("changing a macro's arity did not change the hash")
	}
}

// writeAndIndex materialises a tree and files every .mut in it, the way the
// editor's workspace scan and `mutant lint`'s project both do.
func writeAndIndex(t *testing.T, files map[string]string) (*Workspace, string) {
	t.Helper()
	root := t.TempDir()
	w := NewWorkspace(nil)
	for rel, src := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		w.PutFile("file:///"+filepath.ToSlash(path), path, parser.New(lexer.New(src)).ParseProgram())
	}
	return w, root
}

const macroSource = "let twice = macro(x) { quote(unquote(x) + unquote(x)); };\n"

func TestResolveMacroFindsOneInTheClosure(t *testing.T) {
	w, root := writeAndIndex(t, map[string]string{
		"alpha.mut": macroSource,
		"main.mut":  "import a \"alpha.mut\";\ntwice(21);\n",
	})
	key := CanonicalKey(filepath.Join(root, "main.mut"))

	macro, owner, found := w.ResolveMacro(key, "twice")
	if !found {
		t.Fatal("a macro in an imported module did not resolve")
	}
	if macro.Name != "twice" || owner != CanonicalKey(filepath.Join(root, "alpha.mut")) {
		t.Fatalf("resolved to %q in %s", macro.Name, owner)
	}
}

// The closure is the whole rule, exactly as it is for a type. A module that
// happens to compile first is not a module this one can see.
func TestResolveMacroDoesNotReachOutsideTheClosure(t *testing.T) {
	w, root := writeAndIndex(t, map[string]string{
		"alpha.mut": macroSource,
		"beta.mut":  "twice(21);\n",
		"main.mut":  "import a \"alpha.mut\";\nimport b \"beta.mut\";\n",
	})
	key := CanonicalKey(filepath.Join(root, "beta.mut"))

	if _, _, found := w.ResolveMacro(key, "twice"); found {
		t.Fatal("beta.mut resolved a macro from a module it never imported. " +
			"The compiler happens to accept that program, because macroEnv is one " +
			"environment filled in link order -- but swapping main's two import " +
			"lines makes the same program fail, so it is not an answer to give")
	}
	if w.ProvidesBareName(key, "twice") {
		t.Fatal("ProvidesBareName reached outside the closure too")
	}
}

// Two modules declaring one macro name is a program that BUILDS -- nothing
// plays claimTypeName's part for macros, and the last one compiled wins. So the
// name is provided, and which declaration it names is not a fact.
func TestAnAmbiguousMacroIsProvidedButNotResolved(t *testing.T) {
	w, root := writeAndIndex(t, map[string]string{
		"alpha.mut": "let pick = macro(x) { quote(unquote(x) + 1); };\n",
		"gamma.mut": "let pick = macro(x) { quote(unquote(x) + 100); };\n",
		"main.mut":  "import a \"alpha.mut\";\nimport g \"gamma.mut\";\npick(10);\n",
	})
	key := CanonicalKey(filepath.Join(root, "main.mut"))

	if _, _, found := w.ResolveMacro(key, "pick"); found {
		t.Fatal("an ambiguous macro was resolved to one of the two. Which one a " +
			"call means depends on the order two import lines were written in, " +
			"so naming either presents an order-dependent answer as a fact")
	}
	if !w.ProvidesBareName(key, "pick") {
		t.Fatal("an ambiguous macro was reported as not provided, which would " +
			"squiggle `pick(10)` -- a call the build accepts")
	}
}

// An import the workspace could not resolve makes the closure incomplete, and
// "I did not find it" is not "it is not there". That answer is Provisional and
// a Provisional answer renders nothing.
func TestAnUnresolvedImportMakesEveryBareNameProvided(t *testing.T) {
	w, root := writeAndIndex(t, map[string]string{
		"main.mut": "import missing \"nowhere/gone.mut\";\nanything(1);\n",
	})
	key := CanonicalKey(filepath.Join(root, "main.mut"))

	if !w.ProvidesBareName(key, "anything") {
		t.Fatal("a name was reported as coming from nowhere while one of the " +
			"file's imports names a module the workspace has never read")
	}
}

// BareNamesFrom is what keeps an import whose alias is never written from being
// called unused. It lists what arrives WITHOUT the namespace, so a value -- the
// one kind that needs it -- must not be in the list.
func TestBareNamesFromListsTypesAndMacrosOnly(t *testing.T) {
	w, root := writeAndIndex(t, map[string]string{
		"alpha.mut": macroSource + "struct Point { x }\nenum Colour { Red }\n" +
			"let helper = fn() { return 1; };\n",
		"main.mut": "import a \"alpha.mut\";\n",
	})
	from := CanonicalKey(filepath.Join(root, "main.mut"))
	target := CanonicalKey(filepath.Join(root, "alpha.mut"))

	got := w.BareNamesFrom(from, target)
	want := map[string]bool{"Point": true, "Colour": true, "twice": true}
	for _, name := range got {
		if !want[name] {
			t.Fatalf("BareNamesFrom offered %q; `helper` and anything like it "+
				"needs the namespace and cannot arrive bare. got %v", name, got)
		}
		delete(want, name)
	}
	if len(want) != 0 {
		t.Fatalf("BareNamesFrom missed %v; got %v", want, got)
	}
}

// ProvidesBareName answers about the OTHER modules, exactly as ResolveTopLevel
// does, and that is a choice rather than an accident.
//
// Nothing observes it today. The one caller is the undefined rule, which only
// ever asks about a name the file declares NOWHERE -- a name the file does
// declare was bound by the file-local walk and never reached the unbound list.
// So this is pinned deliberately: the pair of methods answer "what does the
// rest of the closure give me", and a later caller asking "is this name
// available here at all" has to ask the file-local walk first and this second.
func TestProvidesBareNameIsAboutTheOtherModules(t *testing.T) {
	w, root := writeAndIndex(t, map[string]string{
		"alpha.mut": "struct Elsewhere { x }\n",
		"main.mut":  "import a \"alpha.mut\";\nstruct Here { x }\nHere{x: 1};\n",
	})
	key := CanonicalKey(filepath.Join(root, "main.mut"))

	if w.ProvidesBareName(key, "Here") {
		t.Fatal("ProvidesBareName answered about a type the asking file declares " +
			"itself. The file-local walk owns that answer and knows about scopes; " +
			"this one is about what the closure adds")
	}
	if !w.ProvidesBareName(key, "Elsewhere") {
		t.Fatal("the type in the imported module was not reported as provided")
	}
}
