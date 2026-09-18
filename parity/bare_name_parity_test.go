package parity

import (
	"path/filepath"
	"testing"

	"mutant/sema"
)

// A name written bare. `ns.member` is the other half, and module_member_parity_test.go
// covers it.
//
// The rule here was not reasoned about -- it was read off the compiler by
// running programs through it, and this test is those programs. The rule is
// narrow and counter-intuitive in both directions:
//
//   - a value declared in an imported module is NOT visible bare, however
//     plainly it is declared there;
//   - a type IS, and the underscore rule does not apply to it, because
//     structDefinitions and enumDefinitions are flat program-wide maps on the
//     Compiler and a type name never enters the symbol table at all.
//
// The old workspace index answered a bare name by matching it against every
// indexed document, which got both of these wrong and jumped into modules
// nothing had imported.

// bareNameRow is one program and what the two engines must agree about.
type bareNameRow struct {
	name string

	// files is the program. Its entry point is always main.mut and the bare
	// name under test is always used there.
	files map[string]string

	// use is the name main.mut writes bare, and resolvesTo the relative path of
	// the file that must declare it -- "" when nothing may resolve it.
	use        string
	resolvesTo string

	// compiles says whether the real compiler accepts the program. It is stated
	// rather than derived so that a row asserting a refusal fails loudly if the
	// program stops being refused for some unrelated reason.
	compiles bool
}

func TestTheEditorAndTheCompilerAgreeOnBareNames(t *testing.T) {
	rows := []bareNameRow{
		{
			name: "a struct from an imported module resolves",
			files: map[string]string{
				"main.mut": "import lib \"lib.mut\";\nlet p = Point{x: 1, y: 2};\nputf(\"%d\\n\", p.x);\n",
				"lib.mut":  "struct Point { x, y };\nlet unused = 1;\n",
			},
			use: "Point", resolvesTo: "lib.mut", compiles: true,
		},
		{
			name: "an enum from an imported module resolves",
			files: map[string]string{
				"main.mut": "import lib \"lib.mut\";\nputf(\"%s\\n\", Colour.Red);\n",
				"lib.mut":  "enum Colour { Red, Green };\n",
			},
			use: "Colour", resolvesTo: "lib.mut", compiles: true,
		},
		{
			// The underscore rule is a symbol-table rule and a type is not a
			// symbol. Refusing this would refuse a program that builds.
			name: "an underscored type still resolves",
			files: map[string]string{
				"main.mut": "import lib \"lib.mut\";\nlet s = _Secret{a: 1};\nputf(\"%d\\n\", s.a);\n",
				"lib.mut":  "struct _Secret { a };\n",
			},
			use: "_Secret", resolvesTo: "lib.mut", compiles: true,
		},
		{
			// An import binds one namespace. It does not put the imported
			// file's values into this file's scope.
			name: "a function from an imported module does not resolve",
			files: map[string]string{
				"main.mut": "import lib \"lib.mut\";\nputf(\"%d\\n\", helper());\n",
				"lib.mut":  "let helper = fn() { return 1; };\n",
			},
			use: "helper", resolvesTo: "", compiles: false,
		},
		{
			name: "a type in a module nothing imports does not resolve",
			files: map[string]string{
				"main.mut":  "let x = 1;\nputf(\"%d\\n\", x);\n",
				"stray.mut": "struct Orphan { z };\n",
			},
			use: "Orphan", resolvesTo: "", compiles: true,
		},
		{
			// claimTypeName refuses the program outright, so there is no right
			// file to point at.
			name: "a type two reachable modules declare does not resolve",
			files: map[string]string{
				"main.mut": "import a \"a.mut\";\nimport b \"b.mut\";\nlet d = Dup{p: 1};\nputf(\"%d\\n\", d.p);\n",
				"a.mut":    "struct Dup { p };\n",
				"b.mut":    "struct Dup { p };\n",
			},
			use: "Dup", resolvesTo: "", compiles: false,
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			root := writeTree(t, row.files)
			entry := filepath.Join(root, "main.mut")

			accepted, message := compilerAccepts(t, entry)
			if accepted != row.compiles {
				t.Fatalf("the compiler %s this program, and the row says it %s: %s",
					acceptedWord(accepted), acceptedWord(row.compiles), message)
			}

			w := workspaceOverTree(t, root)
			from := sema.CanonicalKey(entry)
			_, owner, resolved := w.ResolveTopLevel(from, row.use)

			if row.resolvesTo == "" {
				if resolved {
					t.Fatalf("the editor resolves bare %s to %s; the compiler does not: %s",
						row.use, owner, message)
				}
				return
			}
			if !resolved {
				t.Fatalf("the editor does not resolve bare %s, but the compiler compiles it",
					row.use)
			}
			if want := sema.CanonicalKey(filepath.Join(root, row.resolvesTo)); owner != want {
				t.Fatalf("the editor resolves bare %s to %s, want %s", row.use, owner, want)
			}
		})
	}
}

func acceptedWord(accepted bool) string {
	if accepted {
		return "accepts"
	}
	return "refuses"
}

// Where the editor is deliberately stricter than the compiler, and why.
//
// Modules compile in post-order, so a type declared in a sibling that happens
// to be compiled first is visible to a module that never imported it -- which
// makes the program's meaning depend on the order two import lines were
// written in. This test is that fact, pinned: the same two files, the same two
// imports, swapped, and one program builds while the other does not.
//
// sema answers about the closure, so it resolves Q in neither. That is a
// refusal to follow the compiler somewhere it would take a user, and it is the
// one direction that is safe: the editor declines to jump, rather than jumping
// somewhere the build will not go.
func TestSiblingTypeVisibilityDependsOnImportOrderAndTheEditorDoesNotFollow(t *testing.T) {
	shared := map[string]string{
		"a.mut": "struct Q { n };\n",
		"b.mut": "let mk = fn() { return Q{n: 5}; };\n",
	}

	// entryImporting builds the same program with the two import lines in the
	// given order, and reports whether the compiler accepts it.
	entryImporting := func(t *testing.T, main string) (string, bool, string) {
		t.Helper()
		files := map[string]string{"main.mut": main}
		for rel, src := range shared {
			files[rel] = src
		}
		root := writeTree(t, files)
		accepted, message := compilerAccepts(t, filepath.Join(root, "main.mut"))
		return root, accepted, message
	}

	const (
		aThenB = "import a \"a.mut\";\nimport b \"b.mut\";\nputf(\"%d\\n\", b.mk().n);\n"
		bThenA = "import b \"b.mut\";\nimport a \"a.mut\";\nputf(\"%d\\n\", b.mk().n);\n"
	)

	rootAB, acceptedAB, _ := entryImporting(t, aThenB)
	rootBA, acceptedBA, messageBA := entryImporting(t, bThenA)

	if !acceptedAB || acceptedBA {
		t.Fatalf("the order-dependence this test exists to describe is gone: "+
			"a-then-b accepted=%v, b-then-a accepted=%v (%s). If the compiler now "+
			"treats both alike, revisit whether sema should still restrict to the "+
			"closure.", acceptedAB, acceptedBA, messageBA)
	}

	// b.mut imports nothing, so a.mut is outside its closure in both trees, and
	// the editor gives the same answer either way.
	for _, root := range []string{rootAB, rootBA} {
		w := workspaceOverTree(t, root)
		from := sema.CanonicalKey(filepath.Join(root, "b.mut"))
		if _, owner, ok := w.ResolveTopLevel(from, "Q"); ok {
			t.Fatalf("the editor resolved Q from b.mut to %s. b.mut imports nothing, "+
				"so whether that compiles depends on which import line is written "+
				"first in a file b.mut has never heard of", owner)
		}
	}
}
