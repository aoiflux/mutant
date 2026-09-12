package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mutant/global"
	"mutant/vm"
)

// Coverage reporting for `mutant test --cover`.
//
// A run covers a file once, not once per test file: two test files that both
// exercise the same module have between them reached the union of the lines
// they reached, and reporting them separately would understate every module
// with more than one test file. So the accumulator merges by OR.

type coverageAccumulator struct {
	// files maps a source path to its lines, each line mapped to whether any
	// test file in the run reached it.
	files map[string]map[int]bool
}

func newCoverageAccumulator() *coverageAccumulator {
	return &coverageAccumulator{files: make(map[string]map[int]bool)}
}

func (a *coverageAccumulator) add(report *vm.CoverageReport) {
	if a == nil || report == nil {
		return
	}
	for _, file := range report.Files {
		if isMutantTestFile(file.Path) {
			// A test file is not the thing under test. Measuring it would
			// answer "did the tests run", which the report above already
			// answers, and would move the number every time a test was added.
			continue
		}
		lines := a.files[file.Path]
		if lines == nil {
			lines = make(map[int]bool)
			a.files[file.Path] = lines
		}
		for line, ran := range file.Lines {
			lines[line] = lines[line] || ran
		}
	}
}

func isMutantTestFile(path string) bool {
	return strings.HasSuffix(filepath.Base(path), "_test"+global.MutantSourceCodeFileExtention)
}

func (a *coverageAccumulator) paths() []string {
	paths := make([]string, 0, len(a.files))
	for path := range a.files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func (a *coverageAccumulator) counts(path string) (lines, hit int) {
	for _, ran := range a.files[path] {
		lines++
		if ran {
			hit++
		}
	}
	return lines, hit
}

func (a *coverageAccumulator) totals() (lines, hit int) {
	for path := range a.files {
		fileLines, fileHit := a.counts(path)
		lines += fileLines
		hit += fileHit
	}
	return lines, hit
}

// printCoverage writes the per-file percentages and the run's total.
//
// The uncovered lines are listed, collapsed into ranges, because the number on
// its own says a file is 80% covered and the next question is always which 20%.
func (a *coverageAccumulator) print() {
	totalLines, totalHit := a.totals()
	if totalLines == 0 {
		// Every file the run touched was a test file, so there is nothing under
		// test to measure. Saying so beats printing 0.0% of 0 lines.
		fmt.Println("\ncoverage: nothing but test files was reached")
		return
	}

	fmt.Printf("\ncoverage: %s of %d lines\n", percent(totalHit, totalLines), totalLines)
	for _, path := range a.paths() {
		lines, hit := a.counts(path)
		fmt.Printf("      %6s  %7s  %s\n", percent(hit, lines), fmt.Sprintf("%d/%d", hit, lines), path)
		if missed := collapseRanges(missedLines(a.files[path])); missed != "" {
			fmt.Printf("              missing %s\n", missed)
		}
	}
}

func missedLines(lines map[int]bool) []int {
	var missed []int
	for line, ran := range lines {
		if !ran {
			missed = append(missed, line)
		}
	}
	sort.Ints(missed)
	return missed
}

func percent(hit, total int) string {
	if total == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(hit)/float64(total))
}

// collapseRanges renders 3,4,5,9 as "3-5, 9". A list of every uncovered line in
// a file that ran none of them is a wall; the ranges are what a reader can act
// on.
func collapseRanges(values []int) string {
	if len(values) == 0 {
		return ""
	}

	var parts []string
	start, previous := values[0], values[0]
	flush := func() {
		if start == previous {
			parts = append(parts, fmt.Sprint(start))
			return
		}
		parts = append(parts, fmt.Sprintf("%d-%d", start, previous))
	}

	for _, value := range values[1:] {
		if value == previous+1 {
			previous = value
			continue
		}
		flush()
		start, previous = value, value
	}
	flush()

	return strings.Join(parts, ", ")
}

// writeCoverProfile writes the run as LCOV.
//
// LCOV rather than Go's own cover profile: Go's format carries statement counts
// and column spans and is read by `go tool cover`, which resolves paths as Go
// packages and would not find a `.mut` file. LCOV is line-oriented, which is
// exactly what is being measured, and is what genhtml, Codecov and the editor
// coverage plugins already read.
//
// Every hit count is 1 or 0. The recording is a bitmap -- did this instruction
// run -- not a counter, because a counter on the instruction path would cost
// every run something to serve a number nothing here reports.
func (a *coverageAccumulator) writeProfile(path string) error {
	var out strings.Builder
	for _, file := range a.paths() {
		lines := a.files[file]

		numbers := make([]int, 0, len(lines))
		for line := range lines {
			numbers = append(numbers, line)
		}
		sort.Ints(numbers)

		fmt.Fprintf(&out, "SF:%s\n", file)
		hit := 0
		for _, line := range numbers {
			count := 0
			if lines[line] {
				count = 1
				hit++
			}
			fmt.Fprintf(&out, "DA:%d,%d\n", line, count)
		}
		fmt.Fprintf(&out, "LF:%d\nLH:%d\nend_of_record\n", len(numbers), hit)
	}

	return os.WriteFile(path, []byte(out.String()), 0o644)
}
