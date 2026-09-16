package compiler

import "testing"

func spannedByteCode() *ByteCode {
	return &ByteCode{
		SourceFile: "main.mut",
		SourceText: "let a = 1;\nlet a2 = 2;\nlet b = 1;\nimport \"a.mut\";\nlet main = 1;\n",
		ModuleSpans: []ModuleSpan{
			{Path: "a.mut", StartLine: 1},
			{Path: "b.mut", StartLine: 3},
			{Path: "main.mut", StartLine: 4},
		},
	}
}

func TestModuleAtResolvesEveryLineToItsFile(t *testing.T) {
	bc := spannedByteCode()

	tests := []struct {
		absLine   int
		wantPath  string
		wantLocal int
	}{
		{1, "a.mut", 1},
		{2, "a.mut", 2},
		{3, "b.mut", 1},
		{4, "main.mut", 1},
		{5, "main.mut", 2},
	}

	for _, tt := range tests {
		path, local, ok := bc.ModuleAt(tt.absLine)
		if !ok {
			t.Fatalf("line %d resolved to nothing", tt.absLine)
		}
		if path != tt.wantPath || local != tt.wantLocal {
			t.Fatalf("line %d -> %s:%d, want %s:%d", tt.absLine, path, local, tt.wantPath, tt.wantLocal)
		}
	}
}

// TestModuleAtReportsUnknownRatherThanGuessing pins the contract that matters:
// with no spans the blob line is a file line only by coincidence, so the
// caller must be told to fall back rather than handed a number.
func TestModuleAtReportsUnknownRatherThanGuessing(t *testing.T) {
	cases := map[string]*ByteCode{
		"no spans": {SourceFile: "main.mut", SourceText: "let x = 1;\n"},
		"nil":      nil,
	}

	for name, bc := range cases {
		if _, _, ok := bc.ModuleAt(1); ok {
			t.Fatalf("%s: expected ModuleAt to report unknown", name)
		}
	}

	bc := spannedByteCode()
	for _, line := range []int{0, -1} {
		if _, _, ok := bc.ModuleAt(line); ok {
			t.Fatalf("line %d must not resolve", line)
		}
	}
}

// TestStripDebugInfoDropsModuleSpans guards the disclosure. ModuleSpans names
// every file a program was built from; shipping it while stripping the line
// tables would defeat the point of stripping.
func TestStripDebugInfoDropsModuleSpans(t *testing.T) {
	bc := spannedByteCode()
	bc.StripDebugInfo()

	if bc.ModuleSpans != nil {
		t.Fatalf("ModuleSpans survived stripping: %+v", bc.ModuleSpans)
	}
	if _, _, ok := bc.ModuleAt(1); ok {
		t.Fatal("a stripped artifact must not resolve module lines")
	}
}

func TestSetModuleSpansCopies(t *testing.T) {
	spans := []ModuleSpan{{Path: "a.mut", StartLine: 1}}

	c := New()
	c.SetModuleSpans(spans)
	spans[0].Path = "mutated.mut"

	if got := c.ByteCode().ModuleSpans; len(got) != 1 || got[0].Path != "a.mut" {
		t.Fatalf("the compiler kept a reference to the caller's slice: %+v", got)
	}
}
