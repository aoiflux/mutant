package sema

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"mutant/ast"
	"mutant/lexer"
	"mutant/parser"
)

// What a keystroke costs.
//
// PutFile is on the didChange path: the server calls it for every change to
// every open document, between the user pressing a key and the screen
// catching up. Its contract is three negatives -- no file read, no closure
// walk, and no work proportional to how many modules the workspace holds --
// and they are not equally provable.
//
// The first is structural and is guarded in policy/sema_guard_test.go: sema
// imports nothing that can open a file, so no path through it can read one.
// That is a stronger statement than any benchmark here could make.
//
// The other two are about this function's behaviour rather than the package's
// capability, so they are measured. The measurement is in allocations rather
// than in nanoseconds, deliberately: a closure walk over 200 modules would
// allocate 200 modules' worth of intermediate state, and that is a number that
// does not change when the machine is busy, which is exactly when a latency
// regression is otherwise easiest to miss.

// chainOf builds a workspace whose entry sits on top of an import chain of the
// given depth. The entry's own source never varies, so two workspaces built
// this way differ only in what lies behind it -- which is the whole point:
// anything the cost of editing the entry has to do with the modules below it
// shows up as a difference between the two.
func chainOf(tb testing.TB, depth int) (w *Workspace, uri, path string, program *ast.Program) {
	tb.Helper()
	root := filepath.Join(tb.TempDir(), "proj")
	w = NewWorkspace(nil)

	put := func(rel, source string) (string, string, *ast.Program) {
		at := filepath.Join(root, rel)
		parsed := parser.New(lexer.New(source)).ParseProgram()
		fileURI := "file:///" + filepath.ToSlash(at)
		w.PutFile(fileURI, at, parsed)
		return fileURI, at, parsed
	}

	for i := 0; i < depth; i++ {
		n := strconv.Itoa(i)
		source := "let helper" + n + " = fn(v) { return v + " + n + "; };\n"
		if i+1 < depth {
			source = "import next \"m" + strconv.Itoa(i+1) + ".mut\";\n" +
				"let helper" + n + " = fn(v) { return next.helper" +
				strconv.Itoa(i+1) + "(v); };\n"
		}
		put("m"+n+".mut", source)
	}

	uri, path, program = put("main.mut", entrySource(0))
	return w, uri, path, program
}

// entrySource is the file the benchmarks edit. The edit is inside a function
// body -- a digit changing in a literal -- which is what almost all typing is,
// and which changes no fact another file could see.
func entrySource(edit int) string {
	var sb strings.Builder
	sb.WriteString("import next \"m0.mut\";\n")
	sb.WriteString("struct Point { x; y; };\n")
	sb.WriteString("enum Colour { Red, Green, Blue };\n")
	for i := 0; i < 20; i++ {
		n := strconv.Itoa(i)
		sb.WriteString("let value" + n + " = fn(a, b) {\n")
		sb.WriteString("  let scaled = a + b + " + strconv.Itoa(edit) + ";\n")
		sb.WriteString("  return next.helper0(scaled) + Colour.Red;\n")
		sb.WriteString("};\n")
	}
	return sb.String()
}

// TestAKeystrokeCostsTheSameHoweverDeepTheWorkspaceIs is the closure-walk half
// of the contract.
//
// Both workspaces are handed the identical file, so the facts computed are
// identical and so is every allocation PutFile makes on its own account. What
// differs is what stands behind the file: one import, or a chain of two
// hundred. A PutFile that resolved imports, or checked whether a dependent
// needed re-analysis, or touched the closure in any way at all, would cost more
// in the second -- and would do so on every keystroke in every deep project,
// while every small fixture in the test suite went on passing.
func TestAKeystrokeCostsTheSameHoweverDeepTheWorkspaceIs(t *testing.T) {
	shallow, shallowURI, shallowPath, _ := chainOf(t, 1)
	deep, deepURI, deepPath, _ := chainOf(t, 200)

	// A fresh parse each round, as a real edit produces. The parse itself is
	// the server's cost, not PutFile's, so it is excluded from the count by
	// being done up front.
	edits := make([]*ast.Program, 64)
	for i := range edits {
		edits[i] = parser.New(lexer.New(entrySource(i))).ParseProgram()
	}

	measure := func(w *Workspace, uri, path string) float64 {
		i := 0
		return testing.AllocsPerRun(len(edits), func() {
			w.PutFile(uri, path, edits[i%len(edits)])
			i++
		})
	}

	// Warm both, so that neither pays for a map growing on the first call.
	measure(shallow, shallowURI, shallowPath)
	measure(deep, deepURI, deepPath)

	small := measure(shallow, shallowURI, shallowPath)
	large := measure(deep, deepURI, deepPath)

	if small != large {
		t.Fatalf("a keystroke allocates %.0f times behind one module and %.0f behind "+
			"two hundred. PutFile is on the didChange path and must recompute one "+
			"file's facts and nothing else: the modules below it have not changed, "+
			"and looking at them is work the user waits through on every key",
			small, large)
	}

	// And the edits really were the indistinguishable kind: a body changing is
	// not a fact changing, so nothing keyed on the generation was invalidated.
	before := deep.Generation()
	deep.PutFile(deepURI, deepPath, edits[0])
	if after := deep.Generation(); after != before {
		t.Fatalf("editing a function body moved the generation from %d to %d, so every "+
			"cache in the server was thrown away for a change no other file can see",
			before, after)
	}
}

// TestAKeystrokeThatChangesNothingVisibleSaysSo is the return value the server
// branches on, checked against the two kinds of edit it has to tell apart.
func TestAKeystrokeThatChangesNothingVisibleSaysSo(t *testing.T) {
	w, uri, path, _ := chainOf(t, 4)

	body := parser.New(lexer.New(entrySource(1))).ParseProgram()
	if changed := w.PutFile(uri, path, body); changed {
		t.Fatal("a digit changing inside a function body was reported as a change " +
			"another file could see")
	}

	declaration := parser.New(lexer.New(entrySource(1) + "let addedLater = 1;\n")).ParseProgram()
	if changed := w.PutFile(uri, path, declaration); !changed {
		t.Fatal("a new top-level declaration was reported as invisible, so every " +
			"importer's completion list is now stale with nothing to say it")
	}
}

// BenchmarkKeystrokeInsideAFunctionBody is the common case: the great majority
// of typing happens inside a body and changes no fact at all.
func BenchmarkKeystrokeInsideAFunctionBody(b *testing.B) {
	for _, depth := range []int{1, 200} {
		b.Run(strconv.Itoa(depth)+"-modules-behind", func(b *testing.B) {
			w, uri, path, _ := chainOf(b, depth)
			edits := make([]*ast.Program, 64)
			for i := range edits {
				edits[i] = parser.New(lexer.New(entrySource(i))).ParseProgram()
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w.PutFile(uri, path, edits[i%len(edits)])
			}
		})
	}
}

// BenchmarkKeystrokeThatAddsADeclaration is the rarer one, and the only one
// that bumps the generation. It is here to be compared with the benchmark
// above: the difference between them is what a fact-changing edit costs over a
// fact-preserving one, and it should be small, because both recompute the same
// facts and only one of them increments a counter.
func BenchmarkKeystrokeThatAddsADeclaration(b *testing.B) {
	w, uri, path, _ := chainOf(b, 200)
	edits := make([]*ast.Program, 64)
	for i := range edits {
		edits[i] = parser.New(lexer.New(
			entrySource(0) + "let added" + strconv.Itoa(i) + " = 1;\n")).ParseProgram()
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.PutFile(uri, path, edits[i%len(edits)])
	}
}

// BenchmarkClosureWalk is the work a keystroke must not do, measured so that
// "must not" has a number attached to it.
func BenchmarkClosureWalk(b *testing.B) {
	for _, depth := range []int{1, 200} {
		b.Run(strconv.Itoa(depth)+"-modules-behind", func(b *testing.B) {
			w, _, path, _ := chainOf(b, depth)
			key := CanonicalKey(path)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w.Closure(key)
			}
		})
	}
}
