package vm

import (
	"sort"

	"mutant/code"
	"mutant/object"
)

// Line coverage.
//
// The recording is a bitmap per function, indexed by instruction offset, so the
// hot path is a pointer comparison and one bounds-checked store. It is on only
// under `mutant test --cover`; every other run sees the same single nil check
// the debugger costs.
//
// Instructions are turned into lines afterwards rather than as they run,
// because the line table is a delta-varint stream that can only be decoded
// forward: asking it for one offset means walking it from the start, which is
// the wrong thing to do per instruction and the right thing to do once per
// function at the end.
//
// What is counted is a LINE THAT PRODUCED INSTRUCTIONS. A blank line, a comment
// and a closing brace are not in the denominator, because a report that counted
// them would measure the layout of the file rather than what the tests reached.

type coverage struct {
	marks map[*object.CompiledFunction][]bool

	// lastFn and lastMarks cache the function being executed. A program stays
	// inside one function for long stretches, so this turns the common case
	// from a map lookup per instruction into a pointer compare.
	lastFn    *object.CompiledFunction
	lastMarks []bool
}

func (c *coverage) mark(fn *object.CompiledFunction, ip int) {
	if fn == nil {
		return
	}
	if fn != c.lastFn {
		marks, seen := c.marks[fn]
		if !seen {
			marks = make([]bool, len(fn.Instructions))
			c.marks[fn] = marks
		}
		c.lastFn, c.lastMarks = fn, marks
	}
	if ip >= 0 && ip < len(c.lastMarks) {
		c.lastMarks[ip] = true
	}
}

// EnableCoverage starts recording which lines the program reaches.
//
// It has to be called before Run: the program's own function is read from the
// frame the constructor laid down, and it is not in the constant pool with the
// others.
func (vm *VM) EnableCoverage() {
	vm.cover = &coverage{marks: make(map[*object.CompiledFunction][]bool)}
	if vm.frameIndex > 0 && vm.frames[0] != nil && vm.frames[0].cl != nil {
		vm.coverMain = vm.frames[0].cl.Fn
	}
}

// FileCoverage is one source file's lines.
type FileCoverage struct {
	// Path is the file as the module spans name it, or the program's own source
	// file for a program that was never linked.
	Path string

	// Lines are the lines in this file that produced instructions, ascending,
	// each mapped to whether it ran.
	Lines map[int]bool
}

// Counts returns how many lines carry code and how many of them ran.
func (f FileCoverage) Counts() (lines, hit int) {
	for _, ran := range f.Lines {
		lines++
		if ran {
			hit++
		}
	}
	return lines, hit
}

// Missed returns the lines that carry code and did not run, ascending.
func (f FileCoverage) Missed() []int {
	var missed []int
	for line, ran := range f.Lines {
		if !ran {
			missed = append(missed, line)
		}
	}
	sort.Ints(missed)
	return missed
}

// CoverageReport is what one run reached, grouped by file and sorted by path.
type CoverageReport struct {
	Files []FileCoverage
}

// CoverageReport decodes the recording. It returns nil when coverage was never
// enabled, which is not the same answer as a run that covered nothing.
func (vm *VM) CoverageReport() *CoverageReport {
	if vm.cover == nil {
		return nil
	}

	// Every line the program CONTAINS, from every function in it, whether or
	// not anything ran. This is the denominator, and it has to come from the
	// program rather than from what executed -- otherwise a test that ran one
	// branch would report full coverage of the file.
	lines := make(map[int]bool)
	for _, fn := range vm.allFunctions() {
		for _, line := range code.BuildLineIndex(fn.LineTable).Lines() {
			if _, known := lines[line]; !known {
				lines[line] = false
			}
		}
	}

	// Every line that ran. The function a mark was recorded against need not be
	// the same object as the one in the constant pool -- the VM may hand a
	// closure its own copy -- which is exactly why this is keyed by line and
	// not by function.
	for fn, marks := range vm.cover.marks {
		for ip, ran := range marks {
			if !ran {
				continue
			}
			if line, _, ok := fn.LineTable.At(ip); ok {
				lines[line] = true
			}
		}
	}

	return vm.groupCoverageByFile(lines)
}

// groupCoverageByFile resolves each line of the linked source blob back to the
// file it was written in.
func (vm *VM) groupCoverageByFile(lines map[int]bool) *CoverageReport {
	byPath := make(map[string]map[int]bool)

	for absLine, ran := range lines {
		path, local := vm.coverageLocation(absLine)
		if path == "" {
			// A program with no name has nowhere to attribute a line. Every
			// build the test runner makes sets one, so this is the hand-built
			// ByteCode case and reporting it under an empty path would put an
			// unnamed row in the table.
			continue
		}
		if byPath[path] == nil {
			byPath[path] = make(map[int]bool)
		}
		byPath[path][local] = byPath[path][local] || ran
	}

	report := &CoverageReport{}
	for path, fileLines := range byPath {
		report.Files = append(report.Files, FileCoverage{Path: path, Lines: fileLines})
	}
	sort.Slice(report.Files, func(i, j int) bool { return report.Files[i].Path < report.Files[j].Path })
	return report
}

func (vm *VM) coverageLocation(absLine int) (path string, local int) {
	if vm.bytecode == nil {
		return "", 0
	}
	if path, local, ok := vm.bytecode.ModuleAt(absLine); ok {
		return path, local
	}
	return vm.bytecode.SourceFile, absLine
}

// allFunctions is every compiled function in the program: the one the VM was
// constructed around, plus every function literal, which the compiler leaves in
// the constant pool flat -- a function nested three deep is a constant like any
// other, so this needs no recursion.
func (vm *VM) allFunctions() []*object.CompiledFunction {
	var fns []*object.CompiledFunction
	if vm.coverMain != nil {
		fns = append(fns, vm.coverMain)
	}
	if vm.bytecode == nil {
		return fns
	}
	for _, constant := range vm.bytecode.Constants {
		if fn, ok := constant.(*object.CompiledFunction); ok {
			fns = append(fns, fn)
		}
	}
	return fns
}
