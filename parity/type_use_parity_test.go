package parity

import (
	"path/filepath"
	"testing"

	"mutant/sema"
)

// A type used in one module and declared in another is resolved by the program
// graph exactly when the compiler resolves it, and counted as unresolved
// exactly when the compiler refuses it (M26-SEM-001).
//
// The rule is the compiler's, and it is not "the importing module can see the
// imported one's types". structDefinitions and enumDefinitions are one table
// for the whole program, filled as each module compiles in the loader's
// post-order, so a module sees the types of every module compiled before it --
// imported or not -- and none compiled after it. Two sibling imports are the
// case that tells the rules apart: the second can build the first's struct
// without importing it, and the first cannot build the second's.
//
// Each case is compiled for real, so the test states what the compiler does
// rather than what this file believes it does.
func TestTheProgramGraphResolvesATypeWhereTheCompilerDoes(t *testing.T) {
	geo := "struct Loc { a; b; };\nenum Dir { N, S };\n"

	cases := []struct {
		name  string
		files map[string]string
		// resolved is the type uses the program graph must record as
		// references into another module, as "module: Type role"; unresolved
		// is how many it must count as misses.
		resolved   []string
		unresolved int
	}{
		{
			name: "an imported module's struct and enum",
			files: map[string]string{
				"lib/geo.mut": geo,
				"main.mut": "import \"lib/geo.mut\";\n" +
					"let l = Loc{a: 1, b: 2};\n" +
					"let d = Dir.S;\n" +
					"let pick = fn(x) { return match (x) { Dir.N => 1, _ => 2, }; };\n" +
					"putln(pick(d), l.a);\n",
			},
			resolved: []string{
				"main.mut: Loc construct", "main.mut: Dir use", "main.mut: Dir pattern",
			},
		},
		{
			name: "a sibling compiled first, not imported",
			files: map[string]string{
				"lib/a.mut": "struct Loc { a; };\nlet one = 1;\n",
				"lib/b.mut": "let make = fn() { return Loc{a: 1}; };\n",
				"main.mut":  "import \"lib/a.mut\";\nimport \"lib/b.mut\";\nputln(b.make().a);\n",
			},
			resolved: []string{"lib/b.mut: Loc construct"},
		},
		{
			name: "a sibling compiled after",
			files: map[string]string{
				"lib/a.mut": "struct Loc { a; };\nlet one = 1;\n",
				"lib/b.mut": "let make = fn() { return Loc{a: 1}; };\n",
				"main.mut":  "import \"lib/b.mut\";\nimport \"lib/a.mut\";\nputln(b.make().a);\n",
			},
			unresolved: 1,
		},
		{
			name: "the importing module's own struct, used by what it imports",
			files: map[string]string{
				"lib/make.mut": "let make = fn() { return Loc{a: 1}; };\n",
				"main.mut":     "import \"lib/make.mut\";\nstruct Loc { a; };\nputln(make.make().a);\n",
			},
			unresolved: 1,
		},
		{
			// A module's own types are visible to it only from their
			// statement on, so the program table must not hold them while
			// the module is being built.
			name: "a struct literal above its own module's struct statement",
			files: map[string]string{
				"main.mut": "let p = Loc{a: 1};\nstruct Loc { a; };\nputln(p.a);\n",
			},
			unresolved: 1,
		},
		{
			name: "an enum variant reached before the enum's module compiles",
			files: map[string]string{
				"lib/first.mut": "let d = fn() { return Dir.S; };\n",
				"main.mut":      "import \"lib/first.mut\";\nenum Dir { N, S };\nputln(first.d());\n",
			},
			unresolved: 1,
		},
		{
			// The enum wins over a value of the same name, in the compiler
			// because it asks about enums first. The graph used to answer
			// with the local value, because it could not see the enum.
			name: "an enum from an earlier module beside a value of its name",
			files: map[string]string{
				"lib/geo.mut": geo,
				"main.mut":    "import \"lib/geo.mut\";\nlet Dir = 7;\nputln(Dir.S, Dir);\n",
			},
			resolved: []string{"main.mut: Dir use"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeTree(t, tc.files)
			entry := filepath.Join(root, "main.mut")
			accepted, message := compilerAccepts(t, entry)
			if accepted != (tc.unresolved == 0) {
				t.Fatalf("the compiler accepted=%v (%s), and this case expects %d unresolved "+
					"type use(s): the case is wrong about the compiler", accepted, message, tc.unresolved)
			}

			loaded, loadedRoot := loadFixture(t, tc.files, "main.mut")
			program := programOf(loaded)
			rel := func(key string) string {
				mod, _ := program.ModuleFor(key)
				path, err := filepath.Rel(loadedRoot, mod.Path)
				if err != nil {
					t.Fatal(err)
				}
				return filepath.ToSlash(path)
			}

			var got []string
			unresolved := 0
			for _, mod := range program.Modules {
				unresolved += len(mod.UnresolvedTypeUses)
				for _, ref := range mod.Graph.References() {
					if ref.Target.Module == mod.Key {
						continue
					}
					owner, found := program.ModuleFor(ref.Target.Module)
					if !found {
						continue
					}
					target, found := owner.Graph.NodeFor(ref.Target)
					if !found || (target.Kind != sema.KindStruct && target.Kind != sema.KindEnum) {
						continue
					}
					got = append(got, rel(mod.Key)+": "+target.Name+" "+ref.Role.String())
				}
			}

			if unresolved != tc.unresolved {
				t.Errorf("the program graph counts %d unresolved type use(s), want %d; the compiler said: %s",
					unresolved, tc.unresolved, message)
			}
			for _, want := range tc.resolved {
				found := false
				for _, have := range got {
					found = found || have == want
				}
				if !found {
					t.Errorf("no cross-module type use %q; the graph recorded %v", want, got)
				}
			}
			if len(tc.resolved) == 0 && len(got) > 0 {
				t.Errorf("the graph resolved %v, which the compiler refuses", got)
			}
		})
	}
}
