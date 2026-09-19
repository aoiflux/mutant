package parity

import (
	"path/filepath"
	"testing"

	"mutant/generator"
	"mutant/lexer"
	"mutant/module"
	"mutant/parser"
	"mutant/sema"
)

// The symbol graph is built before the program is linked, and every range in it
// is file-local. That ordering is the plan's one hard sequencing constraint, and
// this is it as a test rather than as a comment above the call.
//
// # Why it cannot be the other way round
//
// module.Graph.Link concatenates every module into one blob and rebases each
// one's positions onto it, so that the compiler sees a single source and
// nothing downstream has to learn what a module is. What it records to undo
// that is compiler.ModuleSpan, which carries a path and a start line -- and no
// offset. But ast.Range is two token.Positions and each carries an Offset,
// which the language server picks the innermost node by. A graph built after
// linking could un-rebase the lines and could not un-rebase the offsets.
//
// And the modules are in post-order, so the ENTRY file gets the largest shift
// of all. The file the author has open is the one whose positions would be
// furthest from the truth.
//
// # What it would look like if it were wrong
//
// Nothing, for a while. Every position would be internally consistent and every
// jump would land somewhere. The symptom is go-to-definition opening the right
// file at a line that exists in no file, which is the kind of wrongness that is
// noticed a week later and blamed on the editor.

// linkFixture is a program in three files, so that the entry is last in compile
// order and its shift is the largest.
var linkFixture = map[string]string{
	"main.mut": `import "lib/report.mut";
let label = "main";
let show = fn() { return report.line(label); };
`,
	"lib/report.mut": `import "stats.mut";
let line = fn(name) { return stats.mean([1]); };
`,
	"lib/stats.mut": `let mean = fn(values) { return 1; };
`,
}

func loadFixture(t *testing.T, files map[string]string, entry string) (*module.Graph, string) {
	t.Helper()
	root := writeTree(t, files)
	loaded, err := module.Load(filepath.Join(root, filepath.FromSlash(entry)), nil)
	if err != nil {
		t.Fatalf("loading the fixture: %v", err)
	}
	return loaded, root
}

func programOf(loaded *module.Graph) *sema.Program {
	files := make([]sema.ProgramFile, 0, len(loaded.Modules))
	for _, mod := range loaded.Modules {
		files = append(files, sema.ProgramFile{
			Path:    mod.Path,
			Display: mod.Display,
			Program: mod.Program,
		})
	}
	return sema.BuildProgram(files, nil)
}

// declarationAt finds a declaration by name in one module's graph.
func declarationAt(t *testing.T, program *sema.Program, key, name string) *sema.Node {
	t.Helper()
	mod, found := program.ModuleFor(key)
	if !found {
		t.Fatalf("the program holds no module %s", key)
	}
	for _, node := range mod.Graph.Declarations() {
		if node.Name == name {
			return node
		}
	}
	t.Fatalf("module %s declares no %q", key, name)
	return nil
}

// A program graph's ranges are the ranges a single-file graph would give. Two
// independent parses, so what is compared is positions and not shared pointers.
func TestAProgramGraphAgreesWithAPerFileGraphOnEveryPosition(t *testing.T) {
	loaded, _ := loadFixture(t, linkFixture, "main.mut")
	program := programOf(loaded)

	for _, mod := range loaded.Modules {
		key := sema.CanonicalKey(mod.Path)
		inProgram, found := program.ModuleFor(key)
		if !found {
			t.Fatalf("the program holds no graph for %s", mod.Display)
		}

		p := parser.New(lexer.New(mod.Source))
		reparsed := p.ParseProgram()
		if errs := p.Errors(); len(errs) > 0 {
			t.Fatalf("%s did not re-parse: %v", mod.Display, errs)
		}
		alone := sema.BuildFile(key, reparsed, nil, nil)

		inModule := inProgram.Graph.Declarations()
		onItsOwn := alone.Declarations()
		if len(inModule) != len(onItsOwn) {
			t.Fatalf("%s declares %d names in the program and %d on its own",
				mod.Display, len(inModule), len(onItsOwn))
		}
		for i := range inModule {
			if inModule[i].DeclRange != onItsOwn[i].DeclRange {
				t.Fatalf("%s: %q is at %+v in the program graph and %+v in a "+
					"single-file graph. A program graph is built before anything "+
					"links it, so there is nothing that could have moved it",
					mod.Display, inModule[i].Name,
					inModule[i].DeclRange.Start, onItsOwn[i].DeclRange.Start)
			}
		}
	}
}

// The ordering itself: build, then link, and confirm that the AST moved and the
// graph did not.
//
// The graph holds ast.Range values rather than pointers into the tree, so a
// later Link cannot reach them. That is what makes "build before Link" a
// property of this code rather than a convention -- and it is exactly what
// would stop being true if the build were moved after the link, because then
// the values captured would be the shifted ones.
func TestLinkShiftsTheTreeAndNotTheGraphBuiltBeforeIt(t *testing.T) {
	loaded, _ := loadFixture(t, linkFixture, "main.mut")
	entryKey := sema.CanonicalKey(loaded.Entry.Path)

	program := programOf(loaded)
	before := declarationAt(t, program, entryKey, "show")
	if before.DeclRange.Start.Line != 3 {
		t.Fatalf("`show` is at line %d before linking; it is written on line 3 "+
			"of main.mut", before.DeclRange.Start.Line)
	}

	linked := loaded.Link()
	if len(linked.Spans) != 3 {
		t.Fatalf("the link produced %d spans, want one per module", len(linked.Spans))
	}

	// The entry is last in link order, so its span starts well down the blob.
	// This is the shift a graph built afterwards would have baked in.
	entrySpan := linked.Spans[len(linked.Spans)-1]
	if entrySpan.StartLine <= 1 {
		t.Fatalf("the entry module starts at line %d of the blob; the fixture has "+
			"two modules ahead of it and the shift is the whole point of this test",
			entrySpan.StartLine)
	}

	// The tree moved.
	moved := false
	for _, stmt := range loaded.Entry.Program.Statements {
		if rng, ok := loaded.Entry.Program.RangeOf(stmt); ok && rng.Start.Line >= entrySpan.StartLine {
			moved = true
			break
		}
	}
	if !moved {
		t.Fatal("Link did not rebase the entry module's positions, so this test " +
			"is not checking what it claims to")
	}

	// The graph did not.
	after := declarationAt(t, program, entryKey, "show")
	if after.DeclRange.Start.Line != 3 {
		t.Fatalf("`show` is at line %d after linking, and at line 3 in the file. "+
			"A graph built before the link holds ranges by value, so nothing the "+
			"link does can reach them -- unless the graph was built afterwards, "+
			"in which case every position in it names a line of the blob and not "+
			"of any file", after.DeclRange.Start.Line)
	}
	if after.DeclRange.Start.Offset != before.DeclRange.Start.Offset {
		t.Fatalf("the offset moved from %d to %d. ModuleSpan carries a start line "+
			"and no offset, so this is the half of a rebase that cannot be undone",
			before.DeclRange.Start.Offset, after.DeclRange.Start.Offset)
	}
}

// The closure sema walks and the closure the loader walked are the same set.
//
// Two independently written walkers agreeing is worth more than either alone,
// and it is nearly free here: the loader resolved these imports by reading the
// filesystem, and sema resolved them by asking what it had been told about.
func TestTheProgramsModulesAreTheOnesTheLoaderFound(t *testing.T) {
	loaded, _ := loadFixture(t, linkFixture, "main.mut")
	program := programOf(loaded)

	if len(program.Modules) != len(loaded.Modules) {
		t.Fatalf("the program holds %d modules and the loader found %d",
			len(program.Modules), len(loaded.Modules))
	}
	for i, mod := range loaded.Modules {
		if program.Modules[i].Key != sema.CanonicalKey(mod.Path) {
			t.Fatalf("module %d is %s in the program and %s in the loader -- the "+
				"order is compile order and is what decides which of two modules "+
				"claiming one type name is named first",
				i, program.Modules[i].Key, mod.Path)
		}
	}

	closure, diags := program.Workspace().Closure(sema.CanonicalKey(loaded.Entry.Path))
	if len(diags) != 0 {
		t.Fatalf("the closure of a well-formed program reported %v", diags)
	}
	if len(closure) != len(loaded.Modules) {
		t.Fatalf("sema's closure has %d modules, the loader's graph %d",
			len(closure), len(loaded.Modules))
	}
}

// The program-wide type table and claimTypeName refuse the same program, and in
// the same words. Two modules declaring one struct name is legal in every
// module-scoped reading of Mutant and is refused program-wide, because
// ByteCode.StructDefs is one flat map.
func TestTheCompilerAndTheGraphRefuseADuplicateTypeNameIdentically(t *testing.T) {
	files := map[string]string{
		"main.mut":      "import \"lib/other.mut\";\nstruct Point { x; };\nlet p = 1;\n",
		"lib/other.mut": "struct Point { lat; };\n",
	}
	root := writeTree(t, files)
	entry := filepath.Join(root, "main.mut")

	loaded, err := module.Load(entry, nil)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	program := programOf(loaded)
	if len(program.Refusals) != 1 {
		t.Fatalf("the graph raised %d refusals, want one: %v",
			len(program.Refusals), program.Refusals)
	}

	_, compileErr, _, _ := generator.CompileForTest(entry, nil)
	if compileErr == nil {
		t.Fatal("the compiler accepted two modules declaring one struct name, " +
			"which the graph refused")
	}
	if compileErr.Error() != program.Refusals[0].Error() {
		t.Fatalf("two phrasings of one rule:\n compiler: %s\n graph:    %s",
			compileErr, program.Refusals[0])
	}
}
