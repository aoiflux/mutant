package workspace

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"mutant/lexer"
	"mutant/lsp/internal/analyzer"
	"mutant/parser"
	"mutant/sema"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func BenchmarkSymbolIndexUpdateLargeDocument(b *testing.B) {
	idx := NewSymbolIndex()
	uri := lsp.DocumentUri("file:///bench-update.mut")
	src := buildUsageSource("shared", 4000)

	b.ResetTimer()
	for b.Loop() {
		idx.Update(uri, analyzer.New().Analyze(src))
	}
}

func BenchmarkSymbolIndexUpdateLargeDocumentIndexOnly(b *testing.B) {
	idx := NewSymbolIndex()
	uri := lsp.DocumentUri("file:///bench-update-index-only.mut")
	src := buildUsageSource("shared", 4000)
	snapshot := analyzer.New().Analyze(src)

	b.ResetTimer()
	for b.Loop() {
		idx.Update(uri, snapshot)
	}
}

// Find-references over a workspace where every document really does import the
// declaring one. The closure walk is inside the measurement on purpose: it is
// recomputed per query rather than stored, and this is the cost of that choice.
func BenchmarkSymbolIndexReferencesToLargeWorkspace(b *testing.B) {
	const importers = 20

	root := filepath.Join(b.TempDir(), "proj")
	idx := NewSymbolIndex()
	w := sema.NewWorkspace(nil)

	put := func(rel, src string) {
		path := filepath.Join(root, rel)
		uri := "file:///" + filepath.ToSlash(path)
		p := parser.New(lexer.New(src))
		program := p.ParseProgram()
		if errs := p.Errors(); len(errs) > 0 {
			b.Fatalf("fixture %s did not parse: %v", rel, errs)
		}
		w.PutFile(uri, path, program)
		idx.Update(lsp.DocumentUri(uri), analyzer.New().Analyze(src))
	}

	put("lib.mut", "let shared = fn() { return 1; };\n")

	var usage strings.Builder
	usage.WriteString("import lib \"lib.mut\";\n")
	for i := 0; i < 200; i++ {
		usage.WriteString("lib.shared();\n")
	}
	for i := 0; i < importers; i++ {
		put("usage-"+strconv.Itoa(i)+".mut", usage.String())
	}

	declKey := sema.CanonicalKey(filepath.Join(root, "lib.mut"))

	b.ResetTimer()
	for b.Loop() {
		locations := idx.ReferencesTo(w, declKey, "shared", false, nil, false)
		if len(locations) != importers*200 {
			b.Fatalf("reference count = %d, want %d", len(locations), importers*200)
		}
	}
}

func buildUsageSource(name string, occurrences int) string {
	if occurrences <= 0 {
		return ""
	}

	var sb strings.Builder
	for i := 0; i < occurrences; i++ {
		sb.WriteString(name)
		sb.WriteString(";\n")
	}
	return sb.String()
}

// The keystroke path, on a document whose names are actually declared.
//
// The two benchmarks above feed it 4000 bare `shared;` lines, where no name is
// ever declared -- which is the one shape that skips the expensive part of any
// index that resolves as it collects. This one does not skip it: every call is
// to a function the document declares.
//
// Update runs inside setSnapshot, so this is paid on every keystroke and the
// number is worth watching. Collection now resolves nothing at all: it records
// where names are written and hands every question of meaning to sema at query
// time.
func BenchmarkSymbolIndexUpdateResolvableDocument(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 400; i++ {
		n := strconv.Itoa(i)
		sb.WriteString("let v" + n + " = fn(a, b) { return a + b + v0(a, b); };\n")
	}
	snapshot := analyzer.New().Analyze(sb.String())

	idx := NewSymbolIndex()
	uri := lsp.DocumentUri("file:///keystroke.mut")

	b.ResetTimer()
	for b.Loop() {
		idx.Update(uri, snapshot)
	}
}
