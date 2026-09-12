package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/vm"
)

func report(files ...vm.FileCoverage) *vm.CoverageReport {
	return &vm.CoverageReport{Files: files}
}

// Two test files that exercise the same module have between them reached the
// union of what they reached. Anything but OR understates every module with
// more than one test file.
func TestCoverageMergesAcrossFiles(t *testing.T) {
	accumulated := newCoverageAccumulator()
	accumulated.add(report(vm.FileCoverage{Path: "lib.mut", Lines: map[int]bool{1: true, 2: false, 3: false}}))
	accumulated.add(report(vm.FileCoverage{Path: "lib.mut", Lines: map[int]bool{1: false, 2: true, 3: false}}))

	lines, hit := accumulated.counts("lib.mut")
	if lines != 3 || hit != 2 {
		t.Fatalf("counts = %d/%d, want 2/3", hit, lines)
	}
	if got := collapseRanges(missedLines(accumulated.files["lib.mut"])); got != "3" {
		t.Errorf("missed = %q, want \"3\"", got)
	}
}

// A test file is not the thing under test. Counting it would answer "did the
// tests run", and would move the number every time a test was added.
func TestCoverageExcludesTestFiles(t *testing.T) {
	accumulated := newCoverageAccumulator()
	accumulated.add(report(
		vm.FileCoverage{Path: filepath.Join("a", "lib.mut"), Lines: map[int]bool{1: true}},
		vm.FileCoverage{Path: filepath.Join("a", "lib_test.mut"), Lines: map[int]bool{1: true, 2: true}},
	))

	if paths := accumulated.paths(); len(paths) != 1 || !strings.HasSuffix(paths[0], "lib.mut") {
		t.Fatalf("paths = %v, want only the non-test file", paths)
	}
	if lines, _ := accumulated.totals(); lines != 1 {
		t.Errorf("counted %d lines, want 1", lines)
	}
}

func TestCollapseRanges(t *testing.T) {
	cases := []struct {
		in   []int
		want string
	}{
		{nil, ""},
		{[]int{7}, "7"},
		{[]int{3, 4, 5}, "3-5"},
		{[]int{3, 4, 5, 9}, "3-5, 9"},
		{[]int{1, 3, 5}, "1, 3, 5"},
		{[]int{1, 2, 4, 5, 6}, "1-2, 4-6"},
	}
	for _, c := range cases {
		if got := collapseRanges(c.in); got != c.want {
			t.Errorf("collapseRanges(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The profile is LCOV, which genhtml, Codecov and the editor coverage plugins
// already read. Every count is 1 or 0: the recording is a bitmap, not a
// counter.
func TestCoverProfileIsLCOV(t *testing.T) {
	accumulated := newCoverageAccumulator()
	accumulated.add(report(vm.FileCoverage{Path: "lib.mut", Lines: map[int]bool{1: true, 2: false, 5: true}}))

	path := filepath.Join(t.TempDir(), "cover.lcov")
	if err := accumulated.writeProfile(path); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	want := "SF:lib.mut\nDA:1,1\nDA:2,0\nDA:5,1\nLF:3\nLH:2\nend_of_record\n"
	if string(written) != want {
		t.Errorf("profile =\n%q\nwant\n%q", written, want)
	}
}

// --cover on a real run, end to end: the branch the test never takes is the one
// reported missing.
func TestCoverageOverARealRun(t *testing.T) {
	dir := writeTestTree(t, map[string]string{
		"lib/stats.mut": "let largest = fn(xs) {\n" +
			"    if (len(xs) == 0) {\n" +
			"        return 0;\n" +
			"    }\n" +
			"    reduce(xs, fn(a, b) { if (b > a) { b } else { a } }, first(xs))\n" +
			"};\n",
		"stats_test.mut": "import numbers \"lib/stats.mut\";\n" +
			"test(\"largest\", fn() { assert_eq(numbers.largest([1, 5, 3]), 5); });\n",
	})

	result := runTestFileAt(filepath.Join(dir, "stats_test.mut"), nil, vm.TestRunOptions{Coverage: true})
	if result.err != "" {
		t.Fatalf("unexpected error: %s", result.err)
	}
	if result.coverage == nil {
		t.Fatal("no coverage came back")
	}

	accumulated := newCoverageAccumulator()
	accumulated.add(result.coverage)

	paths := accumulated.paths()
	if len(paths) != 1 || !strings.HasSuffix(paths[0], "stats.mut") {
		t.Fatalf("covered %v, want only the module under test", paths)
	}
	if got := collapseRanges(missedLines(accumulated.files[paths[0]])); got != "3" {
		t.Errorf("missed = %q, want line 3 (the branch the test never takes)", got)
	}
}
