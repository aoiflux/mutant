package parity

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mutant/lsp/api"
	"mutant/sema"
)

// A macro is the third kind of name that crosses a module boundary, and it
// crosses differently from the other two.
//
// The plan's last open observation was that macroEnv is one environment filled
// in link order, so "a macro a module defines is available to everything that
// imports it and to nothing it imports" -- generator/generate.go's own words --
// might not be what the code does. It is not. Every row below was decided by
// compiling the program and, where it compiles, running it.
//
// Two disagreements came out of asking:
//
//   - `a.twice` resolved in the editor and is refused by the build. The editor
//     resolving a spelling the compiler refuses is the expensive direction: the
//     user finds out when the build breaks.
//   - `Point{x: 1}`, `Colour.Red` and `twice(21)` in a file that imports the
//     module declaring them were all reported as undefined, on a program that
//     compiles and runs. Two of those three predate this package; the third
//     arrived with the rewritten rule.

// lintInProject lints one file with every other file in the tree visible, which
// is what the editor does over a workspace root and what `mutant lint` now does
// over the files it was given.
func lintInProject(t *testing.T, root string) map[string][]string {
	t.Helper()

	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".mut") {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	sort.Strings(files)

	project := api.NewProject(files)
	said := make(map[string][]string, len(files))
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range project.Lint(file, string(src)) {
			if d.Source == "mutant-lint" {
				said[filepath.Base(file)] = append(said[filepath.Base(file)], d.Message)
			}
		}
	}
	return said
}

const macroLibrary = "let twice = macro(x) {\n\tquote(unquote(x) + unquote(x));\n};\n" +
	"struct Point { x }\n" +
	"enum Colour { Red }\n" +
	"let helper = fn() { return 1; };\n"

// TestWhichBareNamesCrossAModuleBoundary drives every position a name from
// another module can be written in, and decides each row by compiling it.
//
// The answer is not "types cross and values do not". It is finer: what crosses
// is a position, not a name. `Point{x: 1}` compiles and bare `Point` does not,
// from the same import of the same module.
func TestWhichBareNamesCrossAModuleBoundary(t *testing.T) {
	for _, c := range []struct {
		name  string
		expr  string
		cross bool
		why   string
	}{
		{name: "a struct literal's name", expr: "Point{x: 1}", cross: true,
			why: "struct names are program-global; they never enter the symbol table"},
		{name: "a struct name as a value", expr: "Point", cross: false,
			why: "a type is not a binding, so there is nothing to read"},
		{name: "an enum variant", expr: "Colour.Red", cross: true},
		{name: "an enum name as a value", expr: "Colour", cross: false},
		{name: "a macro call", expr: "twice(21)", cross: true,
			why: "macroEnv is one environment, and alpha is compiled before its importer"},
		{name: "a macro as a value", expr: "twice", cross: false,
			why: "expansion happens at a call; the name binds nothing"},
		{name: "a plain function", expr: "helper()", cross: false,
			why: "an import binds one namespace and a value needs it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"alpha.mut": macroLibrary,
				"main.mut": "import a \"alpha.mut\";\n" +
					"let main = fn() { " + c.expr + "; };\n" +
					"main();\n",
			})

			compiled, message := compilerAccepts(t, filepath.Join(root, "main.mut"))
			if compiled != c.cross {
				t.Fatalf("the compiler %s %q, but the row says crosses=%v (%s) %s",
					map[bool]string{true: "accepted", false: "rejected"}[compiled],
					c.expr, c.cross, message, c.why)
			}

			// And the editor, over the same two files.
			said := lintInProject(t, root)["main.mut"]
			var undefined []string
			for _, message := range said {
				if strings.Contains(message, "undefined") {
					undefined = append(undefined, message)
				}
			}

			if c.cross && len(undefined) > 0 {
				t.Fatalf("the editor called %q undefined %v, on a program that compiles: %s",
					c.expr, undefined, c.why)
			}
			if !c.cross && len(undefined) == 0 {
				t.Fatalf("the editor passed %q in silence, and the build refuses it: %s",
					c.expr, message)
			}
		})
	}
}

// The other spelling, and the one the editor used to offer. A macro is not a
// module member: its declaration is deleted from the program before the
// module's scope is built, so there is nothing for `a.twice` to name.
func TestAMacroIsNotReachableThroughTheNamespace(t *testing.T) {
	root := writeTree(t, map[string]string{
		"alpha.mut": macroLibrary,
		"main.mut": "import a \"alpha.mut\";\n" +
			"let main = fn() { a.twice(21); };\n" +
			"main();\n",
	})
	entry := filepath.Join(root, "main.mut")

	compiled, message := compilerAccepts(t, entry)
	if compiled {
		t.Fatal("the compiler accepted `a.twice`; this test is about the case where it does not")
	}

	w := workspaceOverTree(t, root)
	resolved := w.ResolveField(sema.CanonicalKey(entry), sema.LocalScope{}, "a", "twice")
	if resolved.Kind == sema.FieldModuleMember {
		t.Fatal("the editor resolved `a.twice` to a declaration, which the build " +
			"refuses. A macro reads like a top-level let and is not one: " +
			"DefineMacros deletes the statement before the module's scope exists")
	}
	if resolved.Refusal == nil {
		t.Fatal("the editor declined `a.twice` without saying why")
	}
	// One sentence, not two phrasings of one rule.
	if resolved.Refusal.Error() != message {
		t.Fatalf("the two engines refuse `a.twice` in different words:\n compiler: %s\n editor:   %s",
			message, resolved.Refusal.Error())
	}

	// And it is not offered behind the dot either, which is where a user would
	// have met it first.
	facts, known := w.Facts(sema.CanonicalKey(filepath.Join(root, "alpha.mut")))
	if !known {
		t.Fatal("alpha.mut was not indexed")
	}
	for _, name := range facts.ExportedNames() {
		if name == "twice" {
			t.Fatalf("`a.` still offers twice; exports = %v", facts.ExportedNames())
		}
	}
}

// An import whose alias is never written is not an unused import when it is
// what brings a bare name into the file. Deleting the line takes Point,
// Colour and twice with it.
func TestAnImportThatSuppliesOnlyBareNamesIsUsed(t *testing.T) {
	root := writeTree(t, map[string]string{
		"alpha.mut": macroLibrary,
		"main.mut": "import a \"alpha.mut\";\n" +
			"let p = Point{x: 1};\n" +
			"let c = Colour.Red;\n" +
			"let n = twice(21);\n" +
			"[p, c, n];\n",
	})

	compiled, message := compilerAccepts(t, filepath.Join(root, "main.mut"))
	if !compiled {
		t.Fatalf("the fixture does not compile, so nothing below means anything: %s", message)
	}
	if said := lintInProject(t, root)["main.mut"]; len(said) != 0 {
		t.Fatalf("the editor drew %v on a file that compiles and runs", said)
	}
}

// The other direction, so the fix above is a whitelist and not a mute button.
// A name nothing declares is still reported, in a file full of imports.
func TestAFileWithImportsStillReportsNamesNothingDeclares(t *testing.T) {
	root := writeTree(t, map[string]string{
		"alpha.mut": macroLibrary,
		"main.mut": "import a \"alpha.mut\";\n" +
			"let bad = nope.f();\n" +
			"let worse = notAThing;\n" +
			"let missing = Absent{x: 1};\n" +
			"[bad, worse, missing];\n",
	})

	said := lintInProject(t, root)["main.mut"]
	for _, want := range []string{"nope", "notAThing", "Absent"} {
		found := false
		for _, message := range said {
			if strings.Contains(message, want) && strings.Contains(message, "undefined") {
				found = true
			}
		}
		if !found {
			t.Fatalf("`%s` was not reported; the rule went quiet because the file "+
				"contains an import, rather than because the import supplies the "+
				"name. said = %v", want, said)
		}
	}
}
