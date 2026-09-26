package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/graphene/store"
)

// The type and dependency questions, asked of stores the export really wrote.

// typesFixture is a program whose types are used across modules in every way
// the export records: built in one module from another's struct, matched in a
// function against another's enum, and named without either.
var typesFixture = map[string]string{
	"lib/geo.mut": `struct Loc { a; b; };
enum Dir { N, S };
let origin = fn() { return Loc{a: 0, b: 0}; };
`,
	"main.mut": `import "lib/geo.mut";
let make = fn(x) { return Loc{a: x, b: x}; };
let pick = fn(d) { return match (d) { Dir.N => 1, Dir.S => 2, }; };
let heading = Dir.S;
putln(pick(heading), make(1).a);
`,
}

// M26-SEM-001. A struct built in one module from another's declaration, and an
// enum matched against the same way, are edges in the store -- REFERENCES, as
// every use is, and USES_TYPE plus CONSTRUCTS or MATCHES. Before 2.6.0 the
// export recorded none of them: a type's uses stopped at its own file.
func TestATypeUsedAcrossModulesIsAnEdgeIntoTheModuleThatDeclaresIt(t *testing.T) {
	summary, dir, _ := exportFixtureTo(t, typesFixture, "main.mut")
	if summary.TypeUses != 4 {
		t.Errorf("the export counts %d type use(s) across modules; main.mut builds Loc once "+
			"and names Dir three times", summary.TypeUses)
	}
	if summary.UnresolvedTypeUses != 0 {
		t.Errorf("the export counts %d unresolved type use(s), and every one resolved", summary.UnresolvedTypeUses)
	}

	g := openExported(t, dir)
	loc, _ := nodeByName(t, g, "Loc")
	make_, _ := nodeByName(t, g, "make")
	pick, _ := nodeByName(t, g, "pick")

	edges, err := g.QueryRelations(store.RelationQuery{
		Anchors: []store.NodeID{loc.ID}, Direction: store.DirectionInbound,
		EdgeTypes: []store.EdgeType{edgeReferences},
	})
	if err != nil {
		t.Fatal(err)
	}
	built := false
	for _, edge := range edges {
		if edge.Src == make_.ID {
			built = edge.HasLabel(edgeUsesType) && edge.HasLabel(edgeConstructs) && !edge.HasLabel(edgeMatches)
		}
	}
	if !built {
		t.Fatal("make builds a Loc in another module and no REFERENCES edge from make carries USES_TYPE and CONSTRUCTS")
	}

	dir_, _ := nodeByName(t, g, "Dir")
	edges, err = g.QueryRelations(store.RelationQuery{
		Anchors: []store.NodeID{dir_.ID}, Direction: store.DirectionInbound,
		EdgeTypes: []store.EdgeType{edgeMatches},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 2 {
		t.Fatalf("%d MATCHES edges into Dir, want the two arms of pick", len(edges))
	}
	for _, edge := range edges {
		if edge.Src != pick.ID || !edge.HasLabel(edgeReferences) || !edge.HasLabel(edgeUsesType) {
			t.Fatalf("a MATCHES edge into Dir is not a use of it by pick: %+v", edge)
		}
	}
}

func TestTypesSaysHowOftenEachTypeIsBuiltMatchedAndUsed(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, typesFixture, "main.mut")
	answer := ask(t, dir, "types", "")

	if answer.Headline != "1 struct(s) and 1 enum(s)" {
		t.Fatalf("headline %q", answer.Headline)
	}
	structs := strings.Join(rows(answer, "Structs"), "\n")
	if !strings.Contains(structs, "Loc") || !strings.Contains(structs, "2 field(s), built 2 time(s), 2 use(s)") {
		t.Fatalf("the struct row does not count both constructions -- one in each module:\n%s", structs)
	}
	enums := strings.Join(rows(answer, "Enums"), "\n")
	if !strings.Contains(enums, "2 variant(s), matched 2 time(s), 3 use(s)") {
		t.Fatalf("the enum row does not count two arms and one other use:\n%s", enums)
	}
}

func TestTypeSortsTheUsesIntoBuiltMatchedAndTheRest(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, typesFixture, "main.mut")

	loc := ask(t, dir, "type", "Loc")
	if !strings.HasPrefix(loc.Headline, "struct Loc, declared at lib/geo.mut:1:8: 2 use(s), 2 of them building it") {
		t.Fatalf("headline %q", loc.Headline)
	}
	fields := strings.Join(rows(loc, "Fields of Loc"), "\n")
	if !strings.Contains(fields, "a") || !strings.Contains(fields, "b") {
		t.Fatalf("the fields are not listed:\n%s", allRows(loc))
	}
	built := strings.Join(rows(loc, "Built by"), "\n")
	if !strings.Contains(built, "main.mut:2:") || !strings.Contains(built, "make (function)") ||
		!strings.Contains(built, "lib/geo.mut:3:") || !strings.Contains(built, "origin (function)") {
		t.Fatalf("the constructions are not the two functions that build a Loc:\n%s", built)
	}
	for _, section := range loc.Sections {
		if strings.HasPrefix(section.Title, "Matched by") {
			t.Fatalf("a struct cannot be matched against, and its answer has a heading for it:\n%s", allRows(loc))
		}
	}

	dirAnswer := ask(t, dir, "type", "Dir")
	matched := rows(dirAnswer, "Matched by")
	if len(matched) != 2 {
		t.Fatalf("%d match arms, want 2:\n%s", len(matched), allRows(dirAnswer))
	}
	other := strings.Join(rows(dirAnswer, "Otherwise used by"), "\n")
	if !strings.Contains(other, "main.mut:4:") || !strings.Contains(other, "top level of main.mut") {
		t.Fatalf("the use of Dir at the top level is not the other use:\n%s", allRows(dirAnswer))
	}
}

// A use of a type the compiler cannot see -- declared by a module compiled
// later, or by none -- has no edge, and is listed rather than silently absent.
// Without it a type nobody manages to use reads as a type nobody uses.
func TestATypeUseTheCompilerCannotSeeIsListedAndNotCounted(t *testing.T) {
	summary, dir, _ := exportFixtureTo(t, map[string]string{
		"lib/early.mut": "let make = fn() { return Later{x: 1}; };\nlet lost = fn() { return Nowhere{y: 2}; };\n",
		"main.mut":      "import \"lib/early.mut\";\nstruct Later { x; };\nlet mine = Later{x: 3};\n",
	}, "main.mut")
	if summary.UnresolvedTypeUses != 2 {
		t.Fatalf("the export counts %d unresolved type use(s), want Later and Nowhere in lib/early.mut",
			summary.UnresolvedTypeUses)
	}

	later := ask(t, dir, "type", "Later")
	if !strings.Contains(later.Headline, "1 use(s), 1 of them building it") {
		t.Fatalf("the construction in main.mut, after the declaration, is the one use: %q", later.Headline)
	}
	missed := strings.Join(rows(later, "Uses that left no edge"), "\n")
	if !strings.Contains(missed, "early.mut:1:") || !strings.Contains(missed, "builds Later") {
		t.Fatalf("the construction the compiler refuses is not listed:\n%s", allRows(later))
	}

	nowhere := ask(t, dir, "type", "Nowhere")
	if !strings.Contains(nowhere.Headline, "nothing in this store declares") ||
		!strings.Contains(strings.Join(rows(nowhere, "Uses that left no edge"), "\n"), "builds Nowhere") {
		t.Fatalf("a type declared nowhere is not answered with its one use:\n%s", allRows(nowhere))
	}

	types := ask(t, dir, "types", "")
	if !strings.Contains(types.Headline, "2 use(s) of a type the compiler cannot see") {
		t.Fatalf("the types headline does not count what left no edge: %q", types.Headline)
	}
}

// A store exported before CONSTRUCTS and MATCHES existed still opens, and a
// question about types says what it cannot tell rather than answering zero.
// One carrying only one of the two is not something any export writes.
func TestAStoreExportedBeforeRolesOpensAndSaysWhatItCannotTell(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, typesFixture, "main.mut")
	path := filepath.Join(dir, "graphene.labels")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	constructs := fmt.Sprintf("edge\t%d\tCONSTRUCTS\n", edgeConstructs)
	matches := fmt.Sprintf("edge\t%d\tMATCHES\n", edgeMatches)
	if !strings.Contains(string(raw), constructs) || !strings.Contains(string(raw), matches) {
		t.Fatalf("the label table is not shaped the way this test assumes:\n%s", raw)
	}

	oneOnly := strings.Replace(string(raw), matches, "", 1)
	if err := os.WriteFile(path, []byte(oneOnly), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := QueryGraph(QueryOptions{Store: dir, Question: "types"}); err == nil ||
		!strings.Contains(err.Error(), "both or neither") {
		t.Fatalf("a table naming CONSTRUCTS without MATCHES was read: %v", err)
	}

	before := strings.Replace(oneOnly, constructs, "", 1)
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, question := range []struct{ name, argument string }{
		{"summary", ""}, {"types", ""}, {"type", "Loc"}, {"where", "Loc"},
	} {
		answer, err := QueryGraph(QueryOptions{Store: dir, Question: question.name, Argument: question.argument})
		if err != nil {
			t.Fatalf("%s refused a store from before 2.6.0: %v", question.name, err)
		}
		if len(answer.Warnings) != 0 {
			t.Fatalf("%s warned about a store from before 2.6.0: %v", question.name, answer.Warnings)
		}
		if question.name == "types" || question.name == "type" {
			text := allRows(answer)
			if !strings.Contains(text, "Re-export") || strings.Contains(text, "built") ||
				strings.Contains(text, "Built by") {
				t.Fatalf("%s on a store from before 2.6.0 does not say what it cannot tell, "+
					"or counts constructions anyway:\n%s", question.name, text)
			}
		}
	}
}

// depsFixture imports one module two ways -- directly under an alias and
// through another module -- and a second one twice from one file.
var depsFixture = map[string]string{
	"main.mut": `import "lib/report.mut";
import numbers "lib/stats.mut";
import again "lib/stats.mut";
putln(report.line(), numbers.mean(), again.mean());
`,
	"lib/report.mut": `import "stats.mut";
let line = fn() { return stats.mean(); };
`,
	"lib/stats.mut": `let mean = fn() { return 1; };
`,
}

func TestDepsAndRdepsFollowEachImportInItsOwnDirectionAndKeepEveryOne(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, depsFixture, "main.mut")

	deps := ask(t, dir, "deps", "main.mut")
	if deps.Headline != "main.mut imports 2 module(s), 2 of them directly" {
		t.Fatalf("headline %q", deps.Headline)
	}
	listed := strings.Join(rows(deps, "Imported"), "\n")
	for _, want := range []string{
		"imported by main.mut as report",
		"imported by main.mut as numbers",
		"imported by main.mut as again",
		"imported by lib/report.mut as stats",
	} {
		if !strings.Contains(listed, want) {
			t.Fatalf("deps does not list %q -- every import is kept, the two of one module "+
				"from one file included:\n%s", want, listed)
		}
	}

	// Directed: what stats imports is nothing, whatever imports it.
	if leaf := ask(t, dir, "deps", "lib/stats.mut"); leaf.Headline != "lib/stats.mut imports 0 module(s), 0 of them directly" {
		t.Fatalf("a module that imports nothing is said to import something: %s", allRows(leaf))
	}

	rdeps := ask(t, dir, "rdeps", "lib/stats.mut")
	if rdeps.Headline != "2 module(s) import lib/stats.mut, 2 of them directly" {
		t.Fatalf("headline %q", rdeps.Headline)
	}
	importers := strings.Join(rows(rdeps, "Imported by"), "\n")
	for _, want := range []string{
		"imports lib/stats.mut as numbers",
		"imports lib/stats.mut as again",
		"imports lib/report.mut as report",
		"imports lib/stats.mut as stats",
	} {
		if !strings.Contains(importers, want) {
			t.Fatalf("rdeps does not list %q:\n%s", want, importers)
		}
	}
	if entry := ask(t, dir, "rdeps", "main.mut"); !strings.HasPrefix(entry.Headline, "0 module(s) import main.mut") {
		t.Fatalf("the entry is said to be imported: %s", allRows(entry))
	}
}

// The loader refuses a cycle, so no export writes one; the store is a file, and
// a walk over a damaged one must still stop.
func TestAnImportWalkStopsAtACycleAndSaysSo(t *testing.T) {
	edges := []importEdge{
		{src: 1, dst: 2, alias: "b"},
		{src: 2, dst: 3, alias: "c"},
		{src: 3, dst: 1, alias: "a"},
		{src: 3, dst: 2, alias: "b2"},
	}
	done := make(chan importWalk, 1)
	go func() { done <- walkImports(1, edges, true) }()
	select {
	case walk := <-done:
		if !walk.cycle {
			t.Fatal("an import back into the origin was not reported")
		}
		if len(walk.reached) != 2 || walk.level[2] != 1 || walk.level[3] != 2 {
			t.Fatalf("the walk reached %v at levels %v", walk.reached, walk.level)
		}
		if len(walk.arriving[2]) != 2 {
			t.Fatalf("module 2 is reached by two imports inside the closure, and %d are kept", len(walk.arriving[2]))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the import walk did not stop at a cycle")
	}

	back := walkImports(2, edges, false)
	if !back.cycle || len(back.reached) != 2 {
		t.Fatalf("walked backwards from 2, the walk found %v, cycle %v", back.reached, back.cycle)
	}
}

// M26-TOOL-015. A nesting in which every level encloses both declarations of
// the next rendered each shared declaration once per path to it: 2^(L+1)-2
// rows. The exporter writes a tree, so this is a damaged store; the answer to
// one is still an answer, and it is linear.
func TestOutlineRendersADeclarationWithTwoEnclosersOnce(t *testing.T) {
	const levels = 16
	byID := map[store.NodeID]declProps{}
	children := map[store.NodeID][]store.NodeID{}
	enclosed := map[store.NodeID]bool{}
	ids := make([]store.NodeID, 0, 2*levels)
	for level := 0; level < levels; level++ {
		for side := 0; side < 2; side++ {
			id := store.NodeID(2*level + side + 1)
			ids = append(ids, id)
			byID[id] = declProps{Name: fmt.Sprintf("d%d_%d", level, side), Kind: "value", Line: level + 1, Column: side + 1}
			if level+1 < levels {
				children[id] = []store.NodeID{store.NodeID(2*level + 3), store.NodeID(2*level + 4)}
			}
			if level > 0 {
				enclosed[id] = true
			}
		}
	}

	outline := newOutliner(byID, children)
	done := make(chan []string, 1)
	go func() { done <- outline.module(ids, enclosed) }()
	var out []string
	select {
	case out = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the outline of 32 declarations did not finish")
	}
	if len(out) > 2*len(ids) {
		t.Fatalf("%d rows for %d declarations; each is rendered in full once and named once "+
			"for each further encloser", len(out), len(ids))
	}
	full := 0
	for _, row := range out {
		if !strings.Contains(row, "also enclosed by") {
			full++
		}
	}
	if full != len(ids) || outline.repeats != len(out)-len(ids) {
		t.Fatalf("%d declarations rendered in full and %d repeats counted, of %d rows", full, outline.repeats, len(out))
	}
}

// A declaration enclosed only from inside a cycle is reached from no root. The
// outline lists it anyway: the headline counted it.
func TestOutlineListsADeclarationOnlyACycleEncloses(t *testing.T) {
	byID := map[store.NodeID]declProps{
		1: {Name: "free", Kind: "value", Line: 1, Column: 1},
		2: {Name: "looped", Kind: "function", Line: 2, Column: 1},
	}
	children := map[store.NodeID][]store.NodeID{2: {2}}
	out := newOutliner(byID, children).module([]store.NodeID{1, 2}, map[store.NodeID]bool{2: true})
	text := strings.Join(out, "\n")
	if !strings.Contains(text, "free") || !strings.Contains(text, "looped") || !strings.Contains(text, "cycle") {
		t.Fatalf("the outline left out a declaration a cycle encloses:\n%s", text)
	}
}
