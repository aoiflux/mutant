package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/lexer"
	"mutant/parser"
	"mutant/sema"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"
)

// What the export writes has to be readable by something that is not this
// program, and the only way to check that is to read it back.
//
// These tests therefore do the whole round trip: a real source tree on disk, a
// real module load, a real store written and reopened. Nothing here is a mock,
// because the parts most likely to be wrong -- the label registry, the property
// index, the endpoints a bulk load does not check -- are exactly the parts a
// mock would stand in for.

// writeTree materialises relative path to source under a temp dir. The files
// have to be real: module.Load reads them.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// The shape of examples/modules: a transitive import, a written alias and a
// derived one, a name declared in two modules, and a private name used inside
// its own file.
var exportFixture = map[string]string{
	"main.mut": `import "lib/report.mut";
import numbers "lib/stats.mut";
let label = "main";
let show = fn() { return report.line(label); };
show();
`,
	"lib/report.mut": `import "stats.mut";
let label = "report";
let line = fn(name) { return stats.mean([1, 2]); };
`,
	"lib/stats.mut": `let _total = fn(values) { return 3; };
let mean = fn(values) { return _total(values); };
`,
}

func exportFixtureTo(t *testing.T, files map[string]string, entry string) (ExportSummary, string, func(string) string) {
	t.Helper()
	root := writeTree(t, files)
	out := filepath.Join(t.TempDir(), "store")

	summary, err := ExportGraph(ExportOptions{
		Entry: filepath.Join(root, filepath.FromSlash(entry)),
		Out:   out,
	})
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}
	// A module is identified by its key, never by its display name: Display is
	// relative to the working directory when it can be and absolute when it
	// cannot, so it is for reading and not for looking up.
	key := func(rel string) string {
		return sema.CanonicalKey(filepath.Join(root, filepath.FromSlash(rel)))
	}
	return summary, out, key
}

func openExported(t *testing.T, dir string) *graphene.Graph {
	t.Helper()
	g, err := graphene.Open(dir)
	if err != nil {
		t.Fatalf("reopening the exported store: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

// nodeByName finds the one declaration with a name, by the property index. If
// this needs a scan the index was not written, which is the failure that would
// otherwise show up only as a slow store.
func nodeByName(t *testing.T, g *graphene.Graph, name string) (*store.Node, declProps) {
	t.Helper()
	found, err := g.NodesWithProperties(map[string][]byte{"name": []byte(name)})
	if err != nil {
		t.Fatalf("looking up %q: %v", name, err)
	}
	if len(found) != 1 {
		t.Fatalf("%d nodes are indexed under the name %q, want 1", len(found), name)
	}
	var props declProps
	if err := json.Unmarshal(found[0].Properties, &props); err != nil {
		t.Fatalf("the blob on %q is not readable: %v", name, err)
	}
	return found[0], props
}

func TestTheExportedStoreAnswersWhatTheGraphKnew(t *testing.T) {
	summary, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")

	if summary.Modules != 3 {
		t.Fatalf("exported %d modules, want 3: the entry and the two it reaches",
			summary.Modules)
	}
	if len(summary.Refusals) != 0 {
		t.Fatalf("a program that compiles was refused: %v", summary.Refusals)
	}

	g := openExported(t, dir)

	counts, err := g.CountNodesByType()
	if err != nil {
		t.Fatalf("counting nodes: %v", err)
	}
	if counts[nodeModule] != 3 {
		t.Fatalf("%d Module nodes, want 3", counts[nodeModule])
	}
	// Counting the functions in a program is the question a store with no
	// query language can only answer if the kind is a label.
	if counts[nodeFunction] != 4 {
		t.Fatalf("%d Function nodes, want 4 (show, line, _total, mean)",
			counts[nodeFunction])
	}
	if counts[nodeNamespace] != 3 {
		t.Fatalf("%d Namespace nodes, want 3: two derived aliases and one written",
			counts[nodeNamespace])
	}

	// `label` is declared in two modules, which docs/MODULES.md blesses. Both
	// are in the store and they are different nodes.
	labels, err := g.NodesWithProperties(map[string][]byte{"name": []byte("label")})
	if err != nil {
		t.Fatalf("looking up label: %v", err)
	}
	if len(labels) != 2 {
		t.Fatalf("%d nodes named label, want 2 -- one per module, which is a legal "+
			"program and must not be collapsed", len(labels))
	}

	_, mean := nodeByName(t, g, "mean")
	if mean.Kind != "function" || !mean.Exported {
		t.Fatalf("mean is %+v, want an exported function", mean)
	}
	_, private := nodeByName(t, g, "_total")
	if private.Exported {
		t.Fatal("_total is marked exported; the leading underscore is the whole " +
			"of Mutant's export rule")
	}
}

// An import is an edge between modules, and a traversal over those edges has to
// reach what the loader reached. This is the property that makes the store an
// analysis target rather than a heap of records.
func TestImportEdgesTraverseTheSameClosureTheLoaderWalked(t *testing.T) {
	_, dir, key := exportFixtureTo(t, exportFixture, "main.mut")
	g := openExported(t, dir)

	modules, err := g.NodesWithProperties(map[string][]byte{"key": []byte(key("main.mut"))})
	if err != nil || len(modules) != 1 {
		t.Fatalf("the entry module is not indexed by key: %d found, %v", len(modules), err)
	}

	reached, err := g.BFSIDs(modules[0].ID, 8, store.DirectionOutbound,
		[]store.EdgeType{edgeImports})
	if err != nil {
		t.Fatalf("walking imports: %v", err)
	}
	// main, report, stats -- the entry included, and stats reached only through
	// report. A closure that stopped at the direct imports would find two.
	if len(reached) != 3 {
		t.Fatalf("following imports from the entry reaches %d modules, want 3: "+
			"stats is imported by report, not by main", len(reached))
	}
}

// A call is a reference with a flag, not an edge of its own, and a use of a
// type is the same edge under a second label. Both are the plan's refusal of
// parallel edge sets: a separate set can drift out of step with the one it is a
// subset of.
func TestACallIsAReferenceAndAUseOfATypeIsTheSameEdgeTwiceLabelled(t *testing.T) {
	_, dir, key := exportFixtureTo(t, map[string]string{
		"main.mut": `struct Point { x; y; };
let helper = fn(p) { return p; };
let run = fn() { return helper(Point{x: 1, y: 2}); };
`,
	}, "main.mut")
	g := openExported(t, dir)

	helper, _ := nodeByName(t, g, "helper")
	run, _ := nodeByName(t, g, "run")
	module := moduleNode(t, g, key("main.mut"))

	// Who names helper: run, and nothing else. A count is not enough here --
	// attributing every use to the file it is written in gives the same count,
	// with the module node standing where the caller should be, and that is a
	// call graph with no calls in it.
	callers := reachedBy(t, g, helper.ID, store.DirectionInbound, edgeReferences)
	if !callers[run.ID] {
		t.Fatal("run calls helper and no REFERENCES edge says so")
	}
	if callers[module.ID] {
		t.Fatal("the use of helper inside run is attributed to the file. A use " +
			"belongs to the declaration it sits in; only a use outside every " +
			"declaration belongs to the module")
	}

	point, _ := nodeByName(t, g, "Point")
	users := reachedBy(t, g, point.ID, store.DirectionInbound, edgeUsesType)
	if !users[run.ID] {
		t.Fatal("run builds a Point and no USES_TYPE edge says so")
	}

	// And USES_TYPE is a second label on the reference, not an edge beside it
	// and not an edge instead of it. Naming a type is naming something, so the
	// walk that finds every use has to find this one too: a label that replaces
	// rather than adds is how a subset quietly becomes a set of its own that
	// can disagree with what it is a subset of.
	asReference := reachedBy(t, g, point.ID, store.DirectionInbound, edgeReferences)
	if !asReference[run.ID] {
		t.Fatal("the use of Point is a USES_TYPE and not a REFERENCES; it is both")
	}

	edges, err := g.CountEdgesByType()
	if err != nil {
		t.Fatalf("counting edges: %v", err)
	}
	if edges[edgeUsesType] > edges[edgeReferences] {
		t.Fatalf("%d USES_TYPE edges against %d REFERENCES: a use of a type is a "+
			"reference, so it cannot be the rarer of the two",
			edges[edgeUsesType], edges[edgeReferences])
	}
}

// reachedBy is the set of nodes one hop from origin along one edge type. The
// origin itself is in it, which is what BFS returns and what every caller here
// allows for.
func reachedBy(t *testing.T, g *graphene.Graph, origin store.NodeID,
	dir store.Direction, edge store.EdgeType) map[store.NodeID]bool {

	t.Helper()
	ids, err := g.BFSIDs(origin, 1, dir, []store.EdgeType{edge})
	if err != nil {
		t.Fatalf("walking from node %d: %v", origin, err)
	}
	out := make(map[store.NodeID]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// moduleNode is the Module node for one module key.
func moduleNode(t *testing.T, g *graphene.Graph, key string) *store.Node {
	t.Helper()
	found, err := g.NodesWithProperties(map[string][]byte{"key": []byte(key)})
	if err != nil {
		t.Fatalf("looking up the module %s: %v", key, err)
	}
	if len(found) != 1 {
		t.Fatalf("%d module nodes are indexed under %s, want 1", len(found), key)
	}
	return found[0]
}

// A declaration that sits inside another is reachable from it, and one at the
// top level of a file is not reachable from anything but its module.
func TestAParameterIsEnclosedByItsFunctionAndATopLevelNameByNothing(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, map[string]string{
		"main.mut": "let outer = fn(inner) { return inner; };\n",
	}, "main.mut")
	g := openExported(t, dir)

	outer, _ := nodeByName(t, g, "outer")
	inner, _ := nodeByName(t, g, "inner")

	inside, err := g.BFSIDs(outer.ID, 1, store.DirectionOutbound,
		[]store.EdgeType{edgeEncloses})
	if err != nil {
		t.Fatalf("walking enclosure: %v", err)
	}
	if len(inside) != 2 || (inside[0] != inner.ID && inside[1] != inner.ID) {
		t.Fatalf("the parameter is not enclosed by the function it belongs to; "+
			"the walk reached %v", inside)
	}

	above, err := g.BFSIDs(outer.ID, 1, store.DirectionInbound,
		[]store.EdgeType{edgeEncloses})
	if err != nil {
		t.Fatalf("walking enclosure upwards: %v", err)
	}
	if len(above) != 1 {
		t.Fatalf("a top-level declaration is enclosed by %d things, want none -- "+
			"the module declares it, which is a different edge", len(above)-1)
	}
}

// Positions in the store are the positions in the file, and the entry module is
// the one that proves it: module.Graph is post-order, so the entry is compiled
// last and a linked graph would give it the largest shift of all. A store built
// after linking would report every declaration in the entry file at a line
// number that exists in no file.
func TestPositionsAreTheOnesInTheFile(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")
	g := openExported(t, dir)

	_, show := nodeByName(t, g, "show")
	if show.Line != 4 {
		t.Fatalf("`show` is recorded at line %d; it is written on line 4 of "+
			"main.mut, and the two imported modules ahead of it in compile order "+
			"are what a linked position would have added", show.Line)
	}
	if show.Column != 5 {
		t.Fatalf("`show` is recorded at column %d, want 5", show.Column)
	}
}

// A derived alias is bound without being written. Anything that offers to
// rename has to know that, and the store has to carry it or a reader would have
// to guess from the fact that the name does not appear on the line.
func TestADerivedAliasIsMarkedAsNotWritten(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")
	g := openExported(t, dir)

	_, derived := nodeByName(t, g, "report")
	if derived.Written {
		t.Fatal("the alias of `import \"lib/report.mut\";` is marked as written; " +
			"the word `report` appears nowhere in that line")
	}
	if derived.Target == "" {
		t.Fatal("the derived alias names no module")
	}

	_, written := nodeByName(t, g, "numbers")
	if !written.Written {
		t.Fatal("the alias of `import numbers \"lib/stats.mut\";` is marked as " +
			"not written; it is right there")
	}
}

// The store says what its own labels mean. A graphene directory records that a
// node is type 32769; what that means lives in the program that wrote it, and a
// store outliving this program -- or read by anything else -- would otherwise be
// a graph of numbers.
func TestTheStoreSaysWhatItsLabelsMean(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")

	table, err := os.ReadFile(filepath.Join(dir, "graphene.labels"))
	if err != nil {
		t.Fatalf("the store carries no label table: %v", err)
	}
	for _, want := range []string{"Module", "Declaration", "Function", "DECLARES", "REFERENCES", "IMPORTS"} {
		if !strings.Contains(string(table), want) {
			t.Fatalf("the label table does not name %q:\n%s", want, table)
		}
	}
}

// A store is written in one pass into an empty directory, so that what is there
// describes one program at one moment. Merging would give a store holding two
// versions of one program with no way to tell them apart.
func TestTheExportRefusesADirectoryThatAlreadyHoldsSomething(t *testing.T) {
	root := writeTree(t, exportFixture)
	out := filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "something"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ExportGraph(ExportOptions{Entry: filepath.Join(root, "main.mut"), Out: out})
	if err == nil {
		t.Fatal("the export wrote into a directory that already held something")
	}
	if !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("the refusal does not say what is wrong with the argument: %v", err)
	}
}

// A program that will not compile is exactly the program someone exports a
// graph of in order to find out why. The refusal is recorded and the export
// still happens.
func TestAProgramThatBreaksAProgramWideRuleStillExports(t *testing.T) {
	summary, dir, _ := exportFixtureTo(t, map[string]string{
		"main.mut":      "import \"lib/other.mut\";\nstruct Point { x; };\n",
		"lib/other.mut": "struct Point { lat; };\n",
	}, "main.mut")

	if len(summary.Refusals) != 1 {
		t.Fatalf("refusals are %v, want one for the struct name declared twice",
			summary.Refusals)
	}
	if !strings.Contains(summary.Refusals[0], "struct Point") {
		t.Fatalf("the refusal does not name the collision: %s", summary.Refusals[0])
	}
	if summary.Modules != 2 {
		t.Fatalf("the export stopped at %d modules", summary.Modules)
	}

	g := openExported(t, dir)
	points, err := g.NodesWithProperties(map[string][]byte{"name": []byte("Point")})
	if err != nil {
		t.Fatalf("looking up Point: %v", err)
	}
	if len(points) != 2 {
		t.Fatalf("%d nodes named Point, want both of them -- the graph describes "+
			"the program as written, refusal and all", len(points))
	}
}

// The identity in the store resolves: given one, you can open a file and look.
//
// That is the whole of why sema.DeclID is not written down. A DeclID is a
// handle into one Graph -- its scope path carries NUL bytes so that reserved
// roots stay unspellable, and its sequence number counts declarations of one
// name within one scope -- so a reader holding one has no way to get from it to
// anything. Both halves of that are checked here, because an identity that is
// merely unique is easy to reach for and tells nobody anything.
func TestTheMintedIdentityNamesAPlaceInASourceFile(t *testing.T) {
	root := writeTree(t, exportFixture)
	out := filepath.Join(t.TempDir(), "store")
	if _, err := ExportGraph(ExportOptions{
		Entry: filepath.Join(root, "main.mut"),
		Out:   out,
	}); err != nil {
		t.Fatalf("export failed: %v", err)
	}
	g := openExported(t, out)

	_, mean := nodeByName(t, g, "mean")
	if strings.ContainsRune(mean.ID, 0) {
		t.Fatalf("the identity %q carries a NUL. It is written to a store that "+
			"outlives this program, and NUL is in it only because the graph "+
			"needed a byte no identifier could contain", mean.ID)
	}

	// Split it back into the two things it claims to name, and go and look.
	cut := strings.LastIndex(mean.ID, "#")
	if cut < 0 {
		t.Fatalf("the identity %q does not name a position, so nothing can be "+
			"found from it", mean.ID)
	}
	module, where := mean.ID[:cut], mean.ID[cut+1:]

	var line, column int
	if _, err := fmt.Sscanf(where, "%d:%d", &line, &column); err != nil {
		t.Fatalf("the position half of %q is not a position: %v", mean.ID, err)
	}

	source, err := os.ReadFile(filepath.Join(root, "lib", "stats.mut"))
	if err != nil {
		t.Fatal(err)
	}
	if module != sema.CanonicalKey(filepath.Join(root, "lib", "stats.mut")) {
		t.Fatalf("the identity names the module %q; mean is declared in stats.mut", module)
	}

	lines := strings.Split(strings.ReplaceAll(string(source), "\r\n", "\n"), "\n")
	if line < 1 || line > len(lines) {
		t.Fatalf("the identity names line %d of a file with %d lines", line, len(lines))
	}
	at := lines[line-1]
	if column < 1 || column+len("mean")-1 > len(at) ||
		at[column-1:column-1+len("mean")] != "mean" {
		t.Fatalf("the identity %q points at %q column %d, where the word is not "+
			"`mean`", mean.ID, at, column)
	}
}

// An import naming a module the program does not hold gets no edge.
//
// This cannot happen through ExportGraph -- module.Load refuses an import it
// cannot resolve, so every alias that reaches the writer has a target. It can
// happen to a Program built from a partial set of files, which is what a
// workspace mid-scan is, and the writer has to survive it: graphene does not
// check an edge's endpoints, so the alternative is an edge into node zero that
// reads as an import of whatever was written first.
func TestAnImportOfAModuleTheProgramDoesNotHoldGetsNoEdge(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "main.mut")
	source := "import \"lib/absent.mut\";\nlet x = 1;\n"

	p := parser.New(lexer.New(source))
	parsed := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("fixture did not parse: %v", errs)
	}

	// One file, importing a second that was never handed over.
	program := sema.BuildProgram([]sema.ProgramFile{
		{Path: path, Display: "main.mut", Program: parsed},
	}, nil)

	out := filepath.Join(t.TempDir(), "store")
	summary, err := ExportProgram(program, out)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if summary.Imports != 0 {
		t.Fatalf("%d import edges were written for an import that resolved to "+
			"nothing", summary.Imports)
	}
	if summary.UnresolvedImports != 1 {
		t.Fatalf("%d unresolved imports reported, want 1 -- an import graph with "+
			"fewer edges than the source has imports has to say so",
			summary.UnresolvedImports)
	}

	g := openExported(t, out)
	edges, err := g.CountEdgesByType()
	if err != nil {
		t.Fatalf("counting edges: %v", err)
	}
	if edges[edgeImports] != 0 {
		t.Fatalf("%d IMPORTS edges in the store; the one import names a module "+
			"that is not in it, and graphene does not check endpoints",
			edges[edgeImports])
	}

	// The alias is still a declaration. What is unknown is the module's
	// contents, not that a name was bound.
	_, alias := nodeByName(t, g, "absent")
	if alias.Kind != "namespace" {
		t.Fatalf("the alias is a %s; an import binds a name whether or not the "+
			"file is there", alias.Kind)
	}
}

// Two exports of one unchanged tree agree.
func TestTwoExportsOfOneTreeAgree(t *testing.T) {
	root := writeTree(t, exportFixture)
	entry := filepath.Join(root, "main.mut")

	ids := func() []string {
		out := filepath.Join(t.TempDir(), "store")
		if _, err := ExportGraph(ExportOptions{Entry: entry, Out: out}); err != nil {
			t.Fatalf("export failed: %v", err)
		}
		g := openExported(t, out)
		nodes, err := g.NodesWithProperties(map[string][]byte{"kind": []byte("function")})
		if err != nil {
			t.Fatalf("listing functions: %v", err)
		}
		found := make([]string, 0, len(nodes))
		for _, node := range nodes {
			var props declProps
			if err := json.Unmarshal(node.Properties, &props); err != nil {
				t.Fatal(err)
			}
			found = append(found, props.ID)
		}
		return found
	}

	first, second := ids(), ids()
	if len(first) == 0 {
		t.Fatal("the fixture declares functions and the export found none")
	}
	if strings.Join(first, "|") != strings.Join(second, "|") {
		t.Fatalf("two exports of one tree minted different identities:\n %v\n %v",
			first, second)
	}
}
