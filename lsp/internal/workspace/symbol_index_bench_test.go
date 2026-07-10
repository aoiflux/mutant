package workspace

import (
	"strconv"
	"strings"
	"testing"

	"mutant/lsp/internal/analyzer"
)

func BenchmarkSymbolIndexUpdateLargeDocument(b *testing.B) {
	idx := NewSymbolIndex()
	uri := "file:///bench-update.mut"
	src := buildUsageSource("shared", 4000)

	b.ResetTimer()
	for b.Loop() {
		idx.Update(uri, analyzer.New().Analyze(src))
	}
}

func BenchmarkSymbolIndexUpdateLargeDocumentIndexOnly(b *testing.B) {
	idx := NewSymbolIndex()
	uri := "file:///bench-update-index-only.mut"
	src := buildUsageSource("shared", 4000)
	snapshot := analyzer.New().Analyze(src)

	b.ResetTimer()
	for b.Loop() {
		idx.Update(uri, snapshot)
	}
}

func BenchmarkSymbolIndexReferenceLocationsLargeWorkspace(b *testing.B) {
	idx := NewSymbolIndex()
	idx.Update("file:///defs.mut", analyzer.New().Analyze("let shared = 1;\n"))

	for i := 0; i < 20; i++ {
		uri := "file:///usage-" + strconv.Itoa(i) + ".mut"
		idx.Update(uri, analyzer.New().Analyze(buildUsageSource("shared", 200)))
	}

	decl, ok := idx.UniqueTopLevelDefinition("shared", "file:///usage-0.mut")
	if !ok || decl == nil {
		b.Fatal("missing declaration for shared")
	}

	b.ResetTimer()
	for b.Loop() {
		locations := idx.ReferenceLocations("shared", decl, true)
		if len(locations) == 0 {
			b.Fatal("expected at least one location")
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
