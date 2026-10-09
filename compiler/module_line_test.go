package compiler

import "testing"

// TestModuleLineResolvesAnEmptyPathToTheEntryModule is the half of the defect
// an editor reaches by sending a breakpoint with no file at all. Spans are in
// link order and the linker emits dependencies first, so "no file named" used
// to resolve to span 0 -- the program's deepest import -- and the breakpoint
// was bound into a file the reader had never opened.
func TestModuleLineResolvesAnEmptyPathToTheEntryModule(t *testing.T) {
	bc := spannedByteCode()

	// main.mut is the entry and holds blob lines 4-5, which are its own 1-2.
	for local := 1; local <= 2; local++ {
		abs, ok := bc.ModuleLine("", local)
		if !ok {
			t.Fatalf("ModuleLine(%q, %d) was refused", "", local)
		}
		path, got, resolved := bc.ModuleAt(abs)
		if !resolved {
			t.Fatalf("blob line %d resolved to nothing", abs)
		}
		if path != bc.SourceFile || got != local {
			t.Fatalf("ModuleLine(%q, %d) -> blob %d -> %s:%d, want %s:%d",
				"", local, abs, path, got, bc.SourceFile, local)
		}
	}
}

// TestModuleLineRefusesALinePastTheEndOfItsFile is the other half. Without a
// bound the arithmetic walks out of the module's span and into the next one, so
// a stale marker at line 3 of a two-line file came back verified at line 1 of
// whatever the linker happened to put after it.
func TestModuleLineRefusesALinePastTheEndOfItsFile(t *testing.T) {
	bc := spannedByteCode()

	// a.mut holds blob lines 1-2, b.mut only line 3, main.mut 4-5. One past
	// each is the first line of the next file, or past the blob entirely.
	tests := []struct {
		path string
		line int
	}{
		{"a.mut", 3},
		{"b.mut", 2},
		{"main.mut", 3},
		{"", 3},
	}

	for _, tt := range tests {
		abs, ok := bc.ModuleLine(tt.path, tt.line)
		if !ok {
			continue
		}
		path, local, _ := bc.ModuleAt(abs)
		t.Errorf("ModuleLine(%q, %d) resolved to blob %d, which is %s:%d",
			tt.path, tt.line, abs, path, local)
	}
}

// TestModuleLineAndModuleAtAreInverses pins the property the pair's doc claims:
// for every line of every file the program was built from, mapping into the
// blob and back out returns the same file and the same line. It fails on either
// half of the defect -- the wrong span chosen for an empty path, or a line let
// past its span's end -- and it is the reason the bound is worth having rather
// than being left to the debugger to notice.
func TestModuleLineAndModuleAtAreInverses(t *testing.T) {
	bc := spannedByteCode()

	var checked int
	for i, span := range bc.ModuleSpans {
		last, bounded := bc.spanLastLine(i)
		if !bounded {
			t.Fatalf("span %d (%s) is unbounded, so the property cannot be checked", i, span.Path)
		}

		for local := 1; local <= last-span.StartLine+1; local++ {
			abs, ok := bc.ModuleLine(span.Path, local)
			if !ok {
				t.Fatalf("%s:%d is a line of this program and was refused", span.Path, local)
			}
			path, got, resolved := bc.ModuleAt(abs)
			if !resolved || path != span.Path || got != local {
				t.Fatalf("%s:%d -> blob %d -> %s:%d (resolved %v)",
					span.Path, local, abs, path, got, resolved)
			}
			checked++
		}
	}

	// Every line of the blob is a line of exactly one file, so the round trip
	// has to have covered all of them and no more.
	if want := blobLineCount(bc.SourceText); checked != want {
		t.Fatalf("the round trip covered %d lines, the blob holds %d", checked, want)
	}
}

// TestModuleLinePassesThroughWithoutSpans pins the unlinked case, which the
// bound must not disturb: with no spans the blob is the file, every positive
// line is its own answer, and an empty path means that same single file.
func TestModuleLinePassesThroughWithoutSpans(t *testing.T) {
	bc := &ByteCode{SourceFile: "main.mut", SourceText: "let x = 1;\n"}

	for _, line := range []int{1, 2, 900} {
		if abs, ok := bc.ModuleLine("", line); !ok || abs != line {
			t.Fatalf("ModuleLine(%q, %d) = %d, %v; want %d, true", "", line, abs, ok, line)
		}
		if abs, ok := bc.ModuleLine("anything.mut", line); !ok || abs != line {
			t.Fatalf("ModuleLine(anything.mut, %d) = %d, %v; want %d, true", line, abs, ok, line)
		}
	}
	for _, line := range []int{0, -1} {
		if _, ok := bc.ModuleLine("", line); ok {
			t.Fatalf("line %d must not resolve", line)
		}
	}
}

// TestModuleLineStillRefusesAFileTheProgramLacks keeps the refusal the matching
// rule exists for: naming a file that is not in the program is not the same
// question as naming no file at all, and must not now fall back to the entry.
func TestModuleLineStillRefusesAFileTheProgramLacks(t *testing.T) {
	bc := spannedByteCode()

	if abs, ok := bc.ModuleLine("nowhere.mut", 1); ok {
		t.Fatalf("nowhere.mut resolved to blob line %d", abs)
	}
}

// TestEntrySpanFallsBackToLinkOrder covers the artifact SourceFile cannot
// identify: assembled by hand, or carrying a spelling no span does. Link order
// is then all there is, and under it the entry is the last span.
func TestEntrySpanFallsBackToLinkOrder(t *testing.T) {
	bc := &ByteCode{
		SourceText: "let a = 1;\nlet main = 1;\n",
		ModuleSpans: []ModuleSpan{
			{Path: "a.mut", StartLine: 1},
			{Path: "main.mut", StartLine: 2},
		},
	}

	if index, ok := bc.entrySpan(); !ok || index != 1 {
		t.Fatalf("entrySpan() with no SourceFile = %d, %v; want 1, true", index, ok)
	}

	bc.SourceFile = "/elsewhere/main.mut"
	if index, ok := bc.entrySpan(); !ok || index != 1 {
		t.Fatalf("entrySpan() with an unmatched SourceFile = %d, %v; want 1, true", index, ok)
	}

	// And it reports rather than returning an index into nothing.
	if _, ok := (&ByteCode{SourceFile: "main.mut"}).entrySpan(); ok {
		t.Fatal("a program with no spans has no entry span")
	}
}

// TestEntrySpanPrefersSourceFileOverPosition proves the two rules are ordered
// and not just coincident: with the entry deliberately not last, SourceFile is
// what decides.
func TestEntrySpanPrefersSourceFileOverPosition(t *testing.T) {
	bc := &ByteCode{
		SourceFile:  "main.mut",
		SourceText:  "let main = 1;\nlet a = 1;\n",
		ModuleSpans: []ModuleSpan{{Path: "main.mut", StartLine: 1}, {Path: "a.mut", StartLine: 2}},
	}

	if index, ok := bc.entrySpan(); !ok || index != 0 {
		t.Fatalf("entrySpan() = %d, %v; want 0, true", index, ok)
	}
	if abs, ok := bc.ModuleLine("", 1); !ok || abs != 1 {
		t.Fatalf("ModuleLine(%q, 1) = %d, %v; want 1, true", "", abs, ok)
	}
}

// TestModuleLineBoundsTheLastSpanByItsSource: the last span has no successor to
// bound it, so the blob's own line count is what stops a breakpoint running off
// the end of the entry module. Where the text was not carried there is nothing
// to bound it with, and the line is the answer rather than a refusal -- there is
// no following module for it to be misfiled into.
func TestModuleLineBoundsTheLastSpanByItsSource(t *testing.T) {
	spans := []ModuleSpan{{Path: "a.mut", StartLine: 1}, {Path: "main.mut", StartLine: 2}}

	withText := &ByteCode{
		SourceFile:  "main.mut",
		SourceText:  "let a = 1;\nlet main = 1;\n",
		ModuleSpans: spans,
	}
	if abs, ok := withText.ModuleLine("main.mut", 1); !ok || abs != 2 {
		t.Fatalf("main.mut:1 = %d, %v; want 2, true", abs, ok)
	}
	if abs, ok := withText.ModuleLine("main.mut", 2); ok {
		t.Fatalf("main.mut holds one line; line 2 resolved to blob %d", abs)
	}

	noText := &ByteCode{SourceFile: "main.mut", ModuleSpans: spans}
	if abs, ok := noText.ModuleLine("main.mut", 2); !ok || abs != 3 {
		t.Fatalf("an unbounded last span: got %d, %v; want 3, true", abs, ok)
	}
	// A dependency is bounded by its successor, text or no text.
	if abs, ok := noText.ModuleLine("a.mut", 2); ok {
		t.Fatalf("a.mut holds only blob line 1; line 2 resolved to blob %d", abs)
	}
}

// TestBlobLineCountCountsTheLastLine guards the one case the newline count gets
// wrong on its own: text that ends mid-line holds a line the newlines do not
// account for, and undercounting it would refuse a real line of a real file.
func TestBlobLineCountCountsTheLastLine(t *testing.T) {
	tests := []struct {
		text string
		want int
	}{
		{"", 0},
		{"\n", 1},
		{"let x = 1;\n", 1},
		{"let x = 1;", 1},
		{"a\nb\n", 2},
		{"a\nb", 2},
		{"a\n\n", 2},
		{"let a = 1;\nlet b = 2;\nlet c = 3;\n", 3},
	}

	for _, tt := range tests {
		if got := blobLineCount(tt.text); got != tt.want {
			t.Errorf("blobLineCount(%q) = %d, want %d", tt.text, got, tt.want)
		}
	}
}
