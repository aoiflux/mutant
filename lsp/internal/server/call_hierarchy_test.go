package server

import (
	"sort"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// The call hierarchy, driven through the real handlers.
//
// The file-local half is the graph read as a call graph. The cross-file half is
// the part no single file can answer, and it is the reason the feature is worth
// having: the caller you are looking for is usually in a file nobody has open.

func prepareAt(t *testing.T, s *Server, uri lsp.DocumentUri, line, character int) lsp.CallHierarchyItem {
	t.Helper()
	items, err := s.prepareCallHierarchy(nil, &lsp.CallHierarchyPrepareParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Position:     lsp.Position{Line: lsp.UInteger(line), Character: lsp.UInteger(character)},
		},
	})
	if err != nil {
		t.Fatalf("prepareCallHierarchy: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("prepareCallHierarchy returned %d items, want 1: %+v", len(items), items)
	}
	return items[0]
}

func incomingNames(t *testing.T, s *Server, item lsp.CallHierarchyItem) []string {
	t.Helper()
	calls, err := s.callHierarchyIncomingCalls(nil, &lsp.CallHierarchyIncomingCallsParams{Item: item})
	if err != nil {
		t.Fatalf("incomingCalls: %v", err)
	}
	names := make([]string, 0, len(calls))
	for _, call := range calls {
		if len(call.FromRanges) == 0 {
			t.Fatalf("caller %q came back with no call sites, so the editor has "+
				"nothing to highlight", call.From.Name)
		}
		names = append(names, call.From.Name)
	}
	sort.Strings(names)
	return names
}

func outgoingNames(t *testing.T, s *Server, item lsp.CallHierarchyItem) []string {
	t.Helper()
	calls, err := s.callHierarchyOutgoingCalls(nil, &lsp.CallHierarchyOutgoingCallsParams{Item: item})
	if err != nil {
		t.Fatalf("outgoingCalls: %v", err)
	}
	names := make([]string, 0, len(calls))
	for _, call := range calls {
		names = append(names, call.To.Name)
	}
	sort.Strings(names)
	return names
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTheCallersOfAFunctionInOneFile(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": "let target = fn() { return 1; };\n" +
			"let first = fn() { return target(); };\n" +
			"let second = fn() { return target() + target(); };\n" +
			"let mentions = fn() { return target; };\n" +
			"first();\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	item := prepareAt(t, s, uri, 0, 4)
	if item.Name != "target" {
		t.Fatalf("prepare resolved to %q, want target", item.Name)
	}

	got := incomingNames(t, s, item)
	want := []string{"first", "second"}
	if !equalStrings(got, want) {
		t.Fatalf("callers = %v, want %v -- `mentions` names target without "+
			"calling it, which is a reference and not an edge", got, want)
	}
}

// Two calls from one function are one caller with two sites, not two callers.
func TestTwoCallsFromOneFunctionAreOneCaller(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": "let target = fn() { return 1; };\n" +
			"let twice = fn() { return target() + target(); };\n" +
			"twice();\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	calls, err := s.callHierarchyIncomingCalls(nil, &lsp.CallHierarchyIncomingCallsParams{
		Item: prepareAt(t, s, uri, 0, 4),
	})
	if err != nil {
		t.Fatalf("incomingCalls: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("callers = %d, want 1", len(calls))
	}
	if len(calls[0].FromRanges) != 2 {
		t.Fatalf("call sites = %d, want 2", len(calls[0].FromRanges))
	}
}

func TestWhatAFunctionCalls(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": "let a = fn() { return 1; };\n" +
			"let b = fn() { return 2; };\n" +
			"let caller = fn() { return a() + b() + a(); };\n" +
			"caller();\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	got := outgoingNames(t, s, prepareAt(t, s, uri, 2, 4))
	want := []string{"a", "b"}
	if !equalStrings(got, want) {
		t.Fatalf("callees = %v, want %v", got, want)
	}
}

// A recursive call is an edge and belongs in the hierarchy. Hiding it would
// hide the thing a reader opened the view to find.
func TestARecursiveCallIsAnEdge(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": "let down = fn(n) { return down(n); };\ndown(1);\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	item := prepareAt(t, s, uri, 0, 4)
	if got := outgoingNames(t, s, item); !equalStrings(got, []string{"down"}) {
		t.Fatalf("callees = %v, want [down]", got)
	}
	if got := incomingNames(t, s, item); !equalStrings(got, []string{"down"}) {
		t.Fatalf("callers = %v, want [down]", got)
	}
}

// The half a single file cannot answer. other.mut is scanned and never opened,
// which is the ordinary case: the caller you are hunting is in a file you have
// not got on screen.
func TestTheCallersOfAModuleMemberReachUnopenedFiles(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut": "let mean = fn(xs) { return 0; };\n",
		"main.mut": "import stats \"lib.mut\";\n" +
			"let report = fn() { return stats.mean([1]); };\n" +
			"report();\n",
		"other.mut": "import s2 \"lib.mut\";\n" +
			"let summary = fn() { return s2.mean([2]); };\n" +
			"summary();\n",
		"unrelated.mut": "let mean = fn(xs) { return 99; };\nmean([3]);\n",
	})
	s, _ := serverOver(t, root, "main.mut")

	libURI := pathToURI(root + "/lib.mut")
	item := prepareAt(t, s, libURI, 0, 4)
	if item.Name != "mean" {
		t.Fatalf("prepare resolved to %q, want mean", item.Name)
	}

	got := incomingNames(t, s, item)
	want := []string{"report", "summary"}
	if !equalStrings(got, want) {
		t.Fatalf("callers = %v, want %v -- `summary` is in a file that was "+
			"scanned and never opened, and `mean` in unrelated.mut is a "+
			"different function that nothing imports", got, want)
	}
}

// A mention that is not a call must not become an edge across files either.
func TestAModuleMemberNamedButNotCalledIsNotACaller(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut": "let mean = fn(xs) { return 0; };\n",
		"main.mut": "import stats \"lib.mut\";\n" +
			"let held = fn() { return stats.mean; };\n" +
			"held();\n",
	})
	s, _ := serverOver(t, root, "main.mut")

	item := prepareAt(t, s, pathToURI(root+"/lib.mut"), 0, 4)
	if got := incomingNames(t, s, item); len(got) != 0 {
		t.Fatalf("callers = %v, want none: stats.mean is named, never called", got)
	}
}

// A call at a file's top level has no enclosing declaration. The graph says so
// rather than inventing one, and the file is what makes the call.
func TestACallAtTheTopLevelOfAnotherFileIsAttributedToTheFile(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut": "let mean = fn(xs) { return 0; };\n",
		"main.mut": "import stats \"lib.mut\";\n" +
			"stats.mean([1]);\n",
	})
	s, _ := serverOver(t, root, "main.mut")

	calls, err := s.callHierarchyIncomingCalls(nil, &lsp.CallHierarchyIncomingCallsParams{
		Item: prepareAt(t, s, pathToURI(root+"/lib.mut"), 0, 4),
	})
	if err != nil {
		t.Fatalf("incomingCalls: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("callers = %d, want 1: %+v", len(calls), calls)
	}
	if calls[0].From.Kind != lsp.SymbolKindFile {
		t.Fatalf("the caller is a %v, want a file -- nothing in main.mut "+
			"declares the call", calls[0].From.Kind)
	}
	if calls[0].From.Name != "main.mut" {
		t.Fatalf("the caller is named %q, want main.mut", calls[0].From.Name)
	}
}

// A type is not callable, so a hierarchy rooted on one would be an empty view
// offered for no reason.
func TestATypeHasNoCallHierarchy(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": "struct Point { x };\nlet p = Point{x: 1};\np;\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	items, err := s.prepareCallHierarchy(nil, &lsp.CallHierarchyPrepareParams{
		TextDocumentPositionParams: lsp.TextDocumentPositionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Position:     lsp.Position{Line: 0, Character: 7},
		},
	})
	if err != nil {
		t.Fatalf("prepareCallHierarchy: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("a struct offered a call hierarchy: %+v", items)
	}
}

// Prepare works from a call site as well as from the declaration: "who else
// calls this" is asked with the cursor on a call at least as often.
func TestPrepareWorksFromACallSite(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": "let target = fn() { return 1; };\n" +
			"let caller = fn() { return target(); };\n" +
			"caller();\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	item := prepareAt(t, s, uri, 1, 28)
	if item.Name != "target" {
		t.Fatalf("prepare from a call site resolved to %q, want target", item.Name)
	}
	if got := incomingNames(t, s, item); !equalStrings(got, []string{"caller"}) {
		t.Fatalf("callers = %v, want [caller]", got)
	}
}

// Rooting the hierarchy on a name this file does not declare. The cursor is on
// `stats.mean` in the importing file; the item has to be the declaration in the
// other file, because that is what "who calls this" is about -- rooting it on
// the alias would ask who calls a namespace.
func TestPrepareFollowsAModuleMemberToItsDeclaration(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut": "let mean = fn(xs) { return 0; };\n",
		"main.mut": "import stats \"lib.mut\";\n" +
			"let report = fn() { return stats.mean([1]); };\n" +
			"report();\n",
	})
	s, uri := serverOver(t, root, "main.mut")

	item := prepareAt(t, s, uri, 1, 34)
	if item.Name != "mean" {
		t.Fatalf("prepare on stats.mean resolved to %q, want mean", item.Name)
	}
	if item.URI != pathToURI(root+"/lib.mut") {
		t.Fatalf("the item points at %s, want lib.mut", item.URI)
	}
	if got := incomingNames(t, s, item); !equalStrings(got, []string{"report"}) {
		t.Fatalf("callers = %v, want [report]", got)
	}
}

// Two modules, each declaring `mean`, each imported under the same alias. The
// alias is what scopes a member use, so this is the shape that would cross the
// wires if it did not: the spelling `stats.mean(` is identical in both files
// and refers to different functions.
func TestCallersDoNotCrossBetweenModulesWithTheSameMemberName(t *testing.T) {
	root := writeModules(t, map[string]string{
		"a.mut": "let mean = fn(xs) { return 1; };\n",
		"b.mut": "let mean = fn(xs) { return 2; };\n",
		"callsA.mut": "import stats \"a.mut\";\n" +
			"let fromA = fn() { return stats.mean([1]); };\n" +
			"fromA();\n",
		"callsB.mut": "import stats \"b.mut\";\n" +
			"let fromB = fn() { return stats.mean([2]); };\n" +
			"fromB();\n",
	})
	s, _ := serverOver(t, root, "callsA.mut")

	if got := incomingNames(t, s, prepareAt(t, s, pathToURI(root+"/a.mut"), 0, 4)); !equalStrings(got, []string{"fromA"}) {
		t.Fatalf("callers of a.mut's mean = %v, want [fromA]", got)
	}
	if got := incomingNames(t, s, prepareAt(t, s, pathToURI(root+"/b.mut"), 0, 4)); !equalStrings(got, []string{"fromB"}) {
		t.Fatalf("callers of b.mut's mean = %v, want [fromB]", got)
	}
}

// A call written inside an anonymous function belongs to the declaration around
// it. The literal declares nothing, so naming it as the caller would hand the
// editor an item with nowhere to go -- and the user is looking for the function
// they can open, not for the closure they passed to map.
func TestACallInsideAnAnonymousFunctionIsAttributedToTheDeclarationAroundIt(t *testing.T) {
	root := writeModules(t, map[string]string{
		"lib.mut": "let mean = fn(xs) { return 0; };\n",
		"main.mut": "import stats \"lib.mut\";\n" +
			"let report = fn(rows) { return map(rows, fn(row) { return stats.mean(row); }); };\n" +
			"report([[1]]);\n",
	})
	s, _ := serverOver(t, root, "main.mut")

	calls, err := s.callHierarchyIncomingCalls(nil, &lsp.CallHierarchyIncomingCallsParams{
		Item: prepareAt(t, s, pathToURI(root+"/lib.mut"), 0, 4),
	})
	if err != nil {
		t.Fatalf("incomingCalls: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("callers = %d, want 1: %+v", len(calls), calls)
	}
	if calls[0].From.Name != "report" {
		t.Fatalf("the caller is %q (a %v), want report -- the anonymous function "+
			"declares nothing to navigate to", calls[0].From.Name, calls[0].From.Kind)
	}
}
