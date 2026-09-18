package parity

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mutant/generator"
	"mutant/lexer"
	"mutant/module"
	"mutant/parser"
	"mutant/sema"
)

// What `ns.member` means was decided in two places that could not see each
// other. The compiler knew what an import was; the language server did not
// import mutant/module at all, and resolved cross-file names by matching them
// against every indexed document.
//
// So the editor and the build disagreed in both directions:
//
//   - `stats.mean` had no code path in the editor. No definition, no hover, no
//     completion, while the compiler resolved it exactly.
//   - go-to-definition jumped into modules nothing had imported, because a name
//     declared anywhere was a candidate.
//   - `_private` resolved across files in the editor and was refused by the
//     compiler.
//   - two modules declaring `label` -- which docs/MODULES.md blesses and
//     examples/modules demonstrates -- made both unresolvable, because the
//     index bailed on the ambiguity.
//
// This test compiles each fixture for real and asks sema.Workspace the same
// question, and fails on disagreement in either direction. The direction that
// matters most is the editor resolving what the compiler refuses: that is the
// one a user cannot see until the build breaks.

// writeTree materialises a map of relative path to source under a temp dir and
// returns the root. The files have to be real: the compiler reads them.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

// workspaceOverTree seeds a sema.Workspace with every .mut file under root, the
// way the language server's workspace scan does.
func workspaceOverTree(t *testing.T, root string) *sema.Workspace {
	t.Helper()
	w := sema.NewWorkspace(nil)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, module.Extension) {
			return err
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		p := parser.New(lexer.New(string(source)))
		program := p.ParseProgram()
		if errs := p.Errors(); len(errs) > 0 {
			t.Fatalf("fixture %s did not parse: %v", path, errs)
		}
		w.PutFile("file:///"+filepath.ToSlash(path), path, program)
		return nil
	})
	if err != nil {
		t.Fatalf("scanning %s: %v", root, err)
	}
	return w
}

// compilerAccepts reports whether the real compilation path accepts entry, and
// the message when it does not.
func compilerAccepts(t *testing.T, entry string) (bool, string) {
	t.Helper()
	_, err, _, _ := generator.CompileForTest(entry, nil)
	if err != nil {
		return false, err.Error()
	}
	return true, ""
}

// The cases below each put one expression in main.mut's body and ask both
// engines about it. `want` is whether the program is legal.
func TestTheEditorAndTheCompilerAgreeOnModuleMembers(t *testing.T) {
	// A library with a public function, a private one, and a name that also
	// exists in main.mut.
	library := map[string]string{
		"lib/stats.mut": "let _total = fn(xs) { return 1; };\n" +
			"let mean = fn(xs) { return _total(xs); };\n" +
			"let label = \"stats\";\n",
		"other/spare.mut": "let orphan = fn() { return 1; };\n" +
			"let mean = fn(xs) { return 99; };\n",
	}

	for _, c := range []struct {
		name string
		expr string
		want bool
		why  string
	}{
		{
			name: "a public member resolves",
			expr: "stats.mean([1, 2])",
			want: true,
		},
		{
			name: "a private member is refused",
			expr: "stats._total([1, 2])",
			want: false,
			why:  "a leading underscore is the whole export rule",
		},
		{
			name: "a member the module does not declare is refused",
			expr: "stats.median([1, 2])",
			want: false,
		},
		{
			name: "a member of a module nothing imported is refused",
			expr: "spare.orphan()",
			want: false,
			why:  "spare.mut is on disk and indexed, but main.mut never imported it",
		},
		{
			name: "one name in two modules resolves to the imported one",
			expr: "stats.label",
			want: true,
			why:  "`label` is declared in main.mut too; the namespace decides",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{
				"main.mut": "import stats \"lib/stats.mut\";\n" +
					"let label = \"main\";\n" +
					"let main = fn() { " + c.expr + "; };\n" +
					"main();\n",
			}
			for path, src := range library {
				files[path] = src
			}

			root := writeTree(t, files)
			entry := filepath.Join(root, "main.mut")

			compiled, message := compilerAccepts(t, entry)
			if compiled != c.want {
				t.Fatalf("the compiler %s %q, but the case says want=%v (%s)",
					map[bool]string{true: "accepted", false: "rejected"}[compiled], c.expr, c.want, message)
			}

			// Now the same question, of the editor.
			w := workspaceOverTree(t, root)
			key := sema.CanonicalKey(entry)

			left, field, ok := strings.Cut(strings.SplitN(c.expr, "(", 2)[0], ".")
			if !ok {
				t.Fatalf("test expression %q is not a field expression", c.expr)
			}
			resolved := w.ResolveField(key, sema.LocalScope{}, left, field)

			editorAccepts := resolved.Kind == sema.FieldModuleMember
			if editorAccepts != c.want {
				t.Fatalf("disagreement on %q:\n compiler accepts = %v\n editor resolves = %v (%v)\n %s",
					c.expr, compiled, editorAccepts, resolved.Kind, c.why)
			}

			// The editor resolving what the compiler refuses is the failure
			// that costs a user the most, so it is called out by name.
			if editorAccepts && !compiled {
				t.Fatalf("the editor resolved %q, which the compiler refuses: %s", c.expr, message)
			}
			if !editorAccepts && compiled {
				t.Fatalf("the editor declined %q, which the compiler accepts", c.expr)
			}
		})
	}
}

// A refusal must be one sentence, not two phrasings of one rule. The compiler
// prints sema's text verbatim, so the editor's squiggle and the build error are
// the same words.
func TestARefusalReadsTheSameFromBothEngines(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import util \"lib/util.mut\";\n" +
			"let main = fn() { util._secret(); };\n" +
			"main();\n",
		"lib/util.mut": "let _secret = fn() { return 1; };\n",
	})
	entry := filepath.Join(root, "main.mut")

	compiled, message := compilerAccepts(t, entry)
	if compiled {
		t.Fatal("the compiler accepted a reach into a private name")
	}

	w := workspaceOverTree(t, root)
	resolved := w.ResolveField(sema.CanonicalKey(entry), sema.LocalScope{}, "util", "_secret")
	if resolved.Refusal == nil {
		t.Fatal("the editor produced no refusal for a private member")
	}

	// The compiler decorates with a location prefix; the sentence itself must
	// appear in it unchanged.
	if !strings.Contains(message, resolved.Refusal.Error()) {
		t.Fatalf("two phrasings of one rule:\n compiler: %s\n editor:   %s", message, resolved.Refusal.Error())
	}
}

// Two independently-written walkers of the same import graph. module.Load
// resolves by asking the filesystem; sema.Workspace resolves by asking what is
// indexed. They must reach the same set, or the editor is reasoning about a
// different program than the one that gets built.
func TestTheClosureMatchesWhatTheLoaderLoads(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
	}{
		{
			name: "a chain",
			files: map[string]string{
				"main.mut":       "import report \"lib/report.mut\";\nlet main = fn() { return report.render(); };\nmain();\n",
				"lib/report.mut": "import stats \"stats.mut\";\nlet render = fn() { return stats.mean(); };\n",
				"lib/stats.mut":  "let mean = fn() { return 1; };\n",
			},
		},
		{
			name: "a diamond -- the shared module is reached twice and loaded once",
			files: map[string]string{
				"main.mut": "import a \"a.mut\";\nimport b \"b.mut\";\nlet main = fn() { return a.f() + b.g(); };\nmain();\n",
				"a.mut":    "import base \"base.mut\";\nlet f = fn() { return base.v(); };\n",
				"b.mut":    "import base \"base.mut\";\nlet g = fn() { return base.v(); };\n",
				"base.mut": "let v = fn() { return 1; };\n",
			},
		},
		{
			name: "an unimported file on disk is in neither",
			files: map[string]string{
				"main.mut":  "import a \"a.mut\";\nlet main = fn() { return a.f(); };\nmain();\n",
				"a.mut":     "let f = fn() { return 1; };\n",
				"spare.mut": "let unused = fn() { return 1; };\n",
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := writeTree(t, c.files)
			entry := filepath.Join(root, "main.mut")

			graph, err := module.Load(entry, nil)
			if err != nil {
				t.Fatalf("module.Load: %v", err)
			}
			loaded := make([]string, 0, len(graph.Modules))
			for _, mod := range graph.Modules {
				loaded = append(loaded, mod.Key())
			}
			sort.Strings(loaded)

			closure, diags := workspaceOverTree(t, root).Closure(sema.CanonicalKey(entry))
			if len(diags) != 0 {
				t.Fatalf("a loadable program produced diagnostics: %v", diags)
			}

			if strings.Join(closure, "\n") != strings.Join(loaded, "\n") {
				t.Fatalf("the two walkers disagree:\n loader:    %v\n workspace: %v", loaded, closure)
			}
		})
	}
}

// A cycle is one fact in two postures: the loader refuses it, the editor
// reports it and keeps answering. Both must notice it.
func TestACycleIsRefusedByTheLoaderAndReportedByTheWorkspace(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.mut": "import a \"a.mut\";\nlet main = fn() { return a.f(); };\nmain();\n",
		"a.mut":    "import b \"b.mut\";\nlet f = fn() { return b.g(); };\n",
		"b.mut":    "import a \"a.mut\";\nlet g = fn() { return a.f(); };\n",
	})
	entry := filepath.Join(root, "main.mut")

	if _, err := module.Load(entry, nil); err == nil {
		t.Fatal("the loader accepted an import cycle")
	}

	closure, diags := workspaceOverTree(t, root).Closure(sema.CanonicalKey(entry))
	if len(diags) == 0 {
		t.Fatal("the workspace walked a cycle without noticing it")
	}
	if diags[0].Code != sema.DiagImportCycle {
		t.Fatalf("diagnostic = %v, want DiagImportCycle", diags[0].Code)
	}
	// And it must still have answered, rather than refusing.
	if len(closure) != 3 {
		t.Fatalf("closure = %v, want all three modules despite the cycle", closure)
	}
}
