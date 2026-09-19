package sema

import (
	"path/filepath"
	"strings"
	"testing"
)

// programOf builds a Program from a map of relative path to source, rooted at a
// directory that does not exist. Nothing here reads a file: BuildProgram is
// handed parsed programs, which is the whole of why it can sit underneath the
// loader that would have read them.
//
// The order is given rather than taken from the map, because compile order is
// load-bearing -- it is what decides which of two modules claiming one struct
// name is named first in the refusal -- and a Go map has none.
func programOf(t *testing.T, order []string, files map[string]string) (*Program, func(string) string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "proj")

	parsed := make([]ProgramFile, 0, len(order))
	for _, rel := range order {
		path := filepath.Join(root, rel)
		parsed = append(parsed, ProgramFile{
			Path:    path,
			Display: rel,
			Program: parse(t, files[rel]),
		})
	}
	key := func(rel string) string { return CanonicalKey(filepath.Join(root, rel)) }
	return BuildProgram(parsed, nil), key
}

// The reason BuildProgram exists rather than a loop over BuildFile.
//
// An import alias reads the workspace for the module it names, so every file's
// facts have to be recorded before the first graph is built. A loop that built
// each graph as it reached it would hand the first module an alias pointing at
// nothing -- and an alias with no target is indistinguishable, to everything
// downstream, from an import of a file that does not exist.
func TestAnAliasInTheFirstModuleAlreadyKnowsWhatItNames(t *testing.T) {
	program, key := programOf(t,
		[]string{"main.mut", "lib/report.mut", "lib/stats.mut"},
		map[string]string{
			"main.mut":       "import report \"lib/report.mut\";\nreport.render();\n",
			"lib/report.mut": "import stats \"stats.mut\";\nlet render = fn() { return stats.mean(); };\n",
			"lib/stats.mut":  "let mean = fn() { return 1; };\n",
		})

	main, found := program.ModuleFor(key("main.mut"))
	if !found {
		t.Fatal("the entry module is not in the program")
	}

	alias := find(t, main.Graph, "report")
	if alias.Kind != KindNamespace {
		t.Fatalf("the alias is a %s, want a namespace", alias.Kind)
	}
	if alias.Target != key("lib/report.mut") {
		t.Fatalf("the alias in the first module targets %q, want lib/report.mut -- "+
			"the module it names was passed after it, and every file's facts have "+
			"to be recorded before any graph is built", alias.Target)
	}

	edges := main.Graph.Imports()
	if len(edges) != 1 || edges[0].To != key("lib/report.mut") {
		t.Fatalf("import edges are %+v, want one resolved edge to lib/report.mut", edges)
	}
}

// A struct name is the one thing in Mutant that is not module-scoped.
// claimTypeName refuses two modules declaring one, program-wide, because
// ByteCode.StructDefs is a flat map and the second would quietly win. A
// per-module graph cannot see that, so the program holds the table.
func TestTwoModulesCannotDeclareOneStructName(t *testing.T) {
	program, _ := programOf(t,
		[]string{"lib/a.mut", "lib/b.mut"},
		map[string]string{
			"lib/a.mut": "struct Point { x; y; };\n",
			"lib/b.mut": "struct Point { lat; lon; };\n",
		})

	if len(program.Refusals) != 1 {
		t.Fatalf("refusals are %v, want exactly one for the duplicate struct name",
			program.Refusals)
	}
	message := program.Refusals[0].Error()
	for _, want := range []string{"struct Point", "lib/a.mut", "lib/b.mut", "renamed"} {
		if !strings.Contains(message, want) {
			t.Fatalf("the refusal does not mention %q: %s", want, message)
		}
	}
	if program.Refusals[0].Code != RefuseDuplicateTypeName {
		t.Fatalf("the refusal is coded %v, want RefuseDuplicateTypeName",
			program.Refusals[0].Code)
	}
}

// The same name declared twice in ONE module is not this rule. It is a
// duplicate declaration, which is a different diagnostic in a different place,
// and raising the program-wide refusal for it would tell an author to rename a
// struct so that it stops colliding with itself.
func TestOneModuleDeclaringAStructTwiceIsNotAProgramWideCollision(t *testing.T) {
	program, _ := programOf(t,
		[]string{"lib/a.mut"},
		map[string]string{"lib/a.mut": "struct Point { x; };\nstruct Point { y; };\n"})

	if len(program.Refusals) != 0 {
		t.Fatalf("refusals are %v; two declarations in one file are that file's "+
			"problem, not the program's", program.Refusals)
	}
}

// Which module owns a type name has one answer across the whole program, so
// asking any single graph would be right only by luck.
func TestAStructNameIsOwnedByOneModuleForTheWholeProgram(t *testing.T) {
	program, key := programOf(t,
		[]string{"lib/shapes.mut", "main.mut"},
		map[string]string{
			"lib/shapes.mut": "struct Point { x; y; };\n",
			"main.mut":       "import shapes \"lib/shapes.mut\";\nlet p = Point{x: 1, y: 2};\n",
		})

	owner, claimed := program.TypeOwner("Point")
	if !claimed {
		t.Fatal("no module claims Point")
	}
	if owner.Key != key("lib/shapes.mut") {
		t.Fatalf("Point is owned by %s, want lib/shapes.mut", owner.Display)
	}
	if _, claimed := program.TypeOwner("Segment"); claimed {
		t.Fatal("a name no module declares is claimed by one")
	}
}

// Every range in a Program is file-local, and this is the property the whole
// pre-Link ordering exists to preserve: a graph built after module.Graph.Link
// could not recover one, because ModuleSpan carries a start line and no offset,
// and ast.Range carries offsets the language server picks nodes by.
//
// parity/program_positions_test.go checks the same thing against a real
// module.Graph and against Link's own shift. This is the half that can be
// checked without leaving the package.
func TestAProgramsRangesAreTheSameOnesBuildFileWouldGive(t *testing.T) {
	const source = "import lib \"lib/shared.mut\";\nlet value = 1;\nlet use = fn() { return value; };\n"
	root := filepath.Join(t.TempDir(), "proj")
	path := filepath.Join(root, "main.mut")

	// Two parses of one text, so the comparison is of positions rather than of
	// pointers that happen to be shared.
	program := BuildProgram([]ProgramFile{{Path: path, Display: "main.mut", Program: parse(t, source)}}, nil)
	alone := BuildFile(CanonicalKey(path), parse(t, source), nil, nil)

	inProgram := program.Modules[0].Graph
	if len(inProgram.Declarations()) != len(alone.Declarations()) {
		t.Fatalf("the program's graph declares %d names, the file's %d",
			len(inProgram.Declarations()), len(alone.Declarations()))
	}
	for i, node := range inProgram.Declarations() {
		other := alone.Declarations()[i]
		if node.Name != other.Name {
			t.Fatalf("declaration %d is %q in the program and %q alone", i, node.Name, other.Name)
		}
		if node.DeclRange != other.DeclRange || node.FullRange != other.FullRange {
			t.Fatalf("%q sits at %+v in the program and %+v alone: a program graph "+
				"holds file-local positions, and the only thing that could have "+
				"moved them is a rebase that has not happened yet",
				node.Name, node.DeclRange, other.DeclRange)
		}
	}
}

// A program of nothing is still a program, and a file that did not parse is
// still a file. Neither returns an error, because neither is a fact about the
// call.
func TestAProgramOfNothingIsStillAProgram(t *testing.T) {
	program := BuildProgram(nil, nil)
	if program == nil {
		t.Fatal("BuildProgram returned nil")
	}
	if len(program.Modules) != 0 || len(program.Refusals) != 0 {
		t.Fatalf("an empty program has %d modules and %d refusals",
			len(program.Modules), len(program.Refusals))
	}
	if program.Workspace() == nil {
		t.Fatal("an empty program has no workspace to ask")
	}
	if _, found := program.ModuleFor("anything"); found {
		t.Fatal("an empty program claims to hold a module")
	}
}

// The loader dedupes two spellings of one file into one Module. A caller that
// did not would otherwise get two graphs for one file and a duplicate-type
// refusal naming that file on both sides of the sentence.
func TestOneFileGivenTwiceIsOneModule(t *testing.T) {
	root := filepath.Join(t.TempDir(), "proj")
	path := filepath.Join(root, "a.mut")
	const source = "struct Point { x; };\n"

	program := BuildProgram([]ProgramFile{
		{Path: path, Display: "a.mut", Program: parse(t, source)},
		{Path: path, Display: "a.mut", Program: parse(t, source)},
	}, nil)

	if len(program.Modules) != 1 {
		t.Fatalf("one file given twice produced %d modules", len(program.Modules))
	}
	if len(program.Refusals) != 0 {
		t.Fatalf("one file was refused for colliding with itself: %v", program.Refusals)
	}
}
