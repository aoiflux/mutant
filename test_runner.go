package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mutant/builtin"
	"mutant/generator"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
	"mutant/vm"
)

// handleTestCommand implements
// `mutant test [--run PATTERN] [-v] [--json] [--fail-fast] [--module-path DIR] [paths...]`.
//
// Each `*_test.mut` file is compiled and run the way any program is, and what it
// reports comes from the testing builtins: `test(name, fn)` names a test, the
// assert family records what it saw. With no paths it tests the current
// directory.
//
// A file that declares no test keeps the original contract -- it passes unless
// running it errored or its last expression was false -- because a program
// shaped that way is still a legitimate test, and the file is then reported as
// a single test named after itself.
func handleTestCommand(args []string) int {
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	pattern := set.String("run", "",
		"Run only the tests whose names match this pattern, split on \"/\" per nesting level.")
	verbose := set.Bool("v", false, "List every test, not only the ones that failed.")
	asJSON := set.Bool("json", false, "Report as line-delimited JSON events, for CI.")
	failFast := set.Bool("fail-fast", false, "Stop calling tests once one has failed.")
	cover := set.Bool("cover", false, "Report which source lines the tests reached.")
	coverProfile := set.String("coverprofile", "",
		"Write the coverage as LCOV to this file. Implies --cover.")

	var modulePaths []string
	registerModulePathFlag(set, &modulePaths)

	if err := set.Parse(args[2:]); err != nil {
		return 2
	}

	filter, err := vm.NewTestFilter(*pattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutant test: --run %v\n", err)
		return 2
	}

	paths := set.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	files, err := collectMutantTestFiles(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutant test: %v\n", err)
		return 1
	}

	reporter := newTestReporter(*asJSON, *verbose)
	if len(files) == 0 {
		reporter.nothingFound()
		return 0
	}

	options := vm.TestRunOptions{Filter: filter, FailFast: *failFast, Coverage: *cover || *coverProfile != ""}
	totals := testTotals{}

	var accumulated *coverageAccumulator
	if options.Coverage {
		accumulated = newCoverageAccumulator()
	}

	for index, file := range files {
		report := runTestFileAt(file, modulePaths, options)
		reporter.file(file, report)
		totals.add(report)
		accumulated.add(report.coverage)

		// --fail-fast stops the whole run, not just the file: the first failure
		// is what the flag is asking to be shown, and everything after it is
		// noise the reader has to scroll past to reach it.
		//
		// What was left is counted and said out loud. A summary reading "1
		// file" after a run that was given five would be a true sentence that
		// leaves the wrong impression.
		if *failFast && !report.passed() {
			totals.filesNotRun = len(files) - index - 1
			break
		}
	}

	reporter.summary(totals)

	// Coverage is printed after the summary, and not at all under --json: a
	// reader wants the verdict first, and a machine reading the event stream
	// should not have a table dropped into it. --coverprofile is the answer
	// there, and it writes the same numbers to a file either way.
	if accumulated != nil {
		if !*asJSON {
			accumulated.print()
		}
		if *coverProfile != "" {
			if err := accumulated.writeProfile(*coverProfile); err != nil {
				fmt.Fprintf(os.Stderr, "mutant test: --coverprofile: %v\n", err)
				return 1
			}
		}
	}

	if totals.filesFailed > 0 {
		return 1
	}
	return 0
}

func printTestHelp() {
	fmt.Print(`mutant test

Usage:
  mutant test [options] [file-or-dir]...

Runs every *_test.mut file. With no paths it tests the current directory.

A test file is an ordinary program, compiled and run the way any program is --
so it can import the module it is testing. What it reports comes from the
testing builtins:

  test("name", fn() { ... })   names a test and runs it where it is written;
                               a test declared inside another is a subtest
  before_each(fn)              fixtures for the tests declared after them
  after_each(fn)
  assert(condition, msg?)      record a failure and carry on
  assert_eq(got, want, msg?)
  assert_ne(got, unwanted, msg?)
  assert_contains(c, v, msg?)  substring, element, or hash key
  assert_err(value, substr?)   the value is an error
  assert_ok(value, msg?)       the value is not an error
  fail(msg)                    for the branch a test should never reach

A file that declares no test keeps the original contract: it passes unless
running it errored or its last expression was false.

Options:
  --run PATTERN         Run only the tests whose names match. The pattern is
                        split on "/" and each part matches one nesting level.
  -v                    List every test, not only the ones that failed.
  --json                Line-delimited JSON events, for CI.
  --fail-fast           Stop calling tests once one has failed.
  --cover               Report which source lines the tests reached.
  --coverprofile FILE   Write the coverage as LCOV. Implies --cover.
  --module-path DIR     Directory to search for imported modules; repeat for
                        more, searched in order.

Exit codes:
  0  every file passed (a run that selected no test passes)
  1  a test failed, or a file would not compile or run
  2  the command line was wrong

Notes:
  A failed assertion is recorded and the test carries on -- the language has
  no exceptions and this does not invent one. A test that needs to stop early
  returns. A test that dies of a runtime error is caught at its own boundary,
  so one broken test costs the file no other test.

  Every assertion also RETURNS its verdict, so a failure is an ordinary value
  the program can look at, and a test file run as a plain program is not
  silently passing.

  Tests run outside secure mode, like --dev: the tamper responses are advisory
  on the machine that is writing the code. Coverage counts the lines that
  produced instructions, and test files are not counted as code under test.

  Nothing is configured through environment variables. See
  docs/CONFIGURATION_POLICY.md, and docs/TESTING.md for the full guide.
`)
}

// testTotals is the run's tally.
type testTotals struct {
	files, filesFailed int
	tests, testsFailed int
	testsSkipped       int

	// filesNotRun is what --fail-fast left on the floor.
	filesNotRun int

	elapsed time.Duration
}

func (t *testTotals) add(report testFileReport) {
	t.files++
	if !report.passed() {
		t.filesFailed++
	}
	t.elapsed += report.elapsed
	t.addResults(report.results)
}

func (t *testTotals) addResults(results []*vm.TestResult) {
	for _, result := range results {
		if result.Skipped {
			t.testsSkipped++
			continue
		}
		t.tests++
		if !result.Passed() {
			t.testsFailed++
		}
	}
}

func (t testTotals) event() *testEventTotals {
	return &testEventTotals{
		Files:        t.files,
		FilesFailed:  t.filesFailed,
		FilesNotRun:  t.filesNotRun,
		Tests:        t.tests,
		TestsFailed:  t.testsFailed,
		TestsSkipped: t.testsSkipped,
	}
}

// testFileReport is everything one `*_test.mut` produced.
type testFileReport struct {
	// err is a failure of the file as a whole: it would not compile, or the run
	// died somewhere outside every test. Results collected before that are kept
	// and still reported -- the tests that did run are how a reader works out
	// what broke.
	err string

	results []*vm.TestResult
	elapsed time.Duration

	// coverage is what this file's run reached, or nil when --cover was not
	// asked for.
	coverage *vm.CoverageReport
}

func (r testFileReport) passed() bool {
	if r.err != "" {
		return false
	}
	for _, result := range r.results {
		if !result.Skipped && !result.Passed() {
			return false
		}
	}
	return true
}

// runTestFileAt compiles and runs one test file and returns what it recorded.
//
// It goes through the same build every other program goes through, which is
// what lets a test file import the module it tests. A VM panic is converted to
// a failure rather than taking the runner down with it.
func runTestFileAt(path string, modulePaths []string, options vm.TestRunOptions) (report testFileReport) {
	defer func() {
		if recovered := recover(); recovered != nil {
			report.err = fmt.Sprintf("panic during execution: %v", recovered)
		}
	}()

	bytecode, err, _, details := generator.CompileForTest(path, modulePaths)
	if err != nil {
		report.err = err.Error()
		if len(details) > 0 {
			report.err += "\n      " + strings.Join(details, "\n      ")
		}
		return report
	}

	// Sealed exactly as an artifact is, with the key derived from the
	// instructions, so the values a test inspects live on the stack encrypted
	// the way they do in a real run.
	password := fmt.Sprint(security.DerivePasswordFromInstructions(bytecode.Instructions))
	sealed := mutil.EncryptByteCode(bytecode, password)

	// Not secure mode. A test run is a development activity on the developer's
	// own machine, so the tamper responses are advisory here the way they are
	// under --dev -- and it is what lets a test that dies be caught at the test
	// boundary instead of ending the file, since in secure mode an error
	// reaching the runner may be the security policy ending the run and nothing
	// gets to swallow that. See VM.mustNotCatch.
	machine := vm.NewWithPasswordAndGlobalStoreMode(sealed, password, make([]object.Object, global.GlobalSize), false)
	machine.ConfigureTestRun(options)
	if options.Coverage {
		machine.EnableCoverage()
	}

	started := time.Now()
	runErr := machine.Run()

	// Wait for anything the tests spawned, so a test that starts work and
	// asserts on its effect sees a finished program rather than a racing one --
	// the same guarantee runner.runvm gives a real run.
	builtin.WaitForTasks()
	report.elapsed = time.Since(started)
	report.results = machine.TestResults()

	// Read before the run error is returned: a file that died halfway still
	// covered everything it reached on the way, and that is the half a reader
	// is trying to see.
	report.coverage = machine.CoverageReport()

	if runErr != nil {
		report.err = runErr.Error()
		return report
	}
	if len(report.results) == 0 {
		report.results = legacyFileResult(machine.LastPoppedStackElement())
	}
	return report
}

// legacyFileResult applies the original contract to a file that declared no
// test: it passed unless its last expression was an error or false.
//
// The result carries no name, which is how the reporter knows to call it after
// the file.
func legacyFileResult(final object.Object) []*vm.TestResult {
	switch value := final.(type) {
	case *object.Error:
		return []*vm.TestResult{{Failures: []vm.TestFailure{{Message: value.Message}}}}
	case *object.Boolean:
		if !value.Value {
			return []*vm.TestResult{{Failures: []vm.TestFailure{{Message: "the file's last expression is false"}}}}
		}
	}
	return []*vm.TestResult{{}}
}

// testReporter writes what a run did, either for a person or for a machine.
type testReporter struct {
	asJSON  bool
	verbose bool
	encoder *json.Encoder
}

func newTestReporter(asJSON, verbose bool) *testReporter {
	reporter := &testReporter{asJSON: asJSON, verbose: verbose}
	if asJSON {
		reporter.encoder = json.NewEncoder(os.Stdout)
	}
	return reporter
}

// testEvent is one line of `--json`. One object per test, one per file, one for
// the run: line-delimited rather than a single document, so a watcher can read
// it as the run produces it and a CI log stays greppable.
type testEvent struct {
	Kind    string `json:"kind"`
	File    string `json:"file,omitempty"`
	Name    string `json:"name,omitempty"`
	Outcome string `json:"outcome,omitempty"`

	// Always written, never omitted: a consumer that has to tell "fast" from
	// "field missing" has been given a puzzle instead of a measurement.
	ElapsedMS int64 `json:"elapsed_ms"`

	Failures []testEventFailure `json:"failures,omitempty"`
	Error    string             `json:"error,omitempty"`

	// Totals is present on the `file` and `summary` events and nowhere else,
	// which is why it is nested rather than flattened: every count inside it is
	// then written even when it is zero, and a CI check reading
	// totals.tests_failed never has to distinguish absent from none.
	Totals *testEventTotals `json:"totals,omitempty"`
}

type testEventTotals struct {
	Files        int `json:"files,omitempty"`
	FilesFailed  int `json:"files_failed,omitempty"`
	FilesNotRun  int `json:"files_not_run,omitempty"`
	Tests        int `json:"tests"`
	TestsFailed  int `json:"tests_failed"`
	TestsSkipped int `json:"tests_skipped"`
}

type testEventFailure struct {
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
}

func (r *testReporter) nothingFound() {
	if r.asJSON {
		r.emit(testEvent{Kind: "summary", Totals: testTotals{}.event()})
		return
	}
	fmt.Println("no *_test.mut files found")
}

func (r *testReporter) file(file string, report testFileReport) {
	if r.asJSON {
		r.fileJSON(file, report)
		return
	}
	r.fileText(file, report)
}

func (r *testReporter) fileJSON(file string, report testFileReport) {
	for _, result := range report.results {
		r.emit(testEvent{
			Kind:      "test",
			File:      file,
			Name:      testDisplayName(result, file),
			Outcome:   testOutcome(result),
			ElapsedMS: result.Elapsed.Milliseconds(),
			Failures:  testEventFailures(result),
			Error:     testResultError(result),
		})
	}

	outcome := "pass"
	if !report.passed() {
		outcome = "fail"
	}
	counts := testTotals{}
	counts.addResults(report.results)
	r.emit(testEvent{
		Kind:      "file",
		File:      file,
		Outcome:   outcome,
		ElapsedMS: report.elapsed.Milliseconds(),
		Error:     report.err,
		Totals:    counts.event(),
	})
}

// fileText writes one file's outcome for a person.
//
// A passing file is one line: a suite is read by scrolling to the first thing
// that is not `ok`. A failing file lists the tests that failed and why, and
// says nothing about the ones that passed unless -v asked.
func (r *testReporter) fileText(file string, report testFileReport) {
	status := "ok  "
	if !report.passed() {
		status = "FAIL"
	}

	// The header counts the tests that RAN. Counting the skipped ones in it
	// would say a filtered run did more than it did, which is the one number a
	// reader takes on trust.
	counts := testTotals{}
	counts.addResults(report.results)
	tally := testCount(counts.tests)
	if counts.testsSkipped > 0 {
		tally += fmt.Sprintf(", %d skipped", counts.testsSkipped)
	}
	fmt.Printf("%s  %s  (%s, %s)\n", status, file, tally, roundMillis(report.elapsed))

	if report.err != "" {
		fmt.Printf("      %s\n", report.err)
	}

	for _, result := range report.results {
		if result.Passed() && !result.Skipped && !r.verbose {
			continue
		}
		if result.Skipped && !r.verbose {
			continue
		}

		fmt.Printf("      --- %-4s  %s  (%s)\n",
			strings.ToUpper(testOutcome(result)), testDisplayName(result, file), roundMillis(result.Elapsed))
		for _, failure := range result.Failures {
			fmt.Printf("          %s\n", failure.String())
		}
		if result.Err != nil {
			fmt.Printf("          %s\n", result.Err.String())
		}
	}
}

func (r *testReporter) summary(totals testTotals) {
	if r.asJSON {
		r.emit(testEvent{Kind: "summary", ElapsedMS: totals.elapsed.Milliseconds(), Totals: totals.event()})
		return
	}

	line := fmt.Sprintf("\n%s | %s",
		countPhrase(totals.files, totals.filesFailed, "file"),
		countPhrase(totals.tests, totals.testsFailed, "test"))
	if totals.testsSkipped > 0 {
		line += fmt.Sprintf(", %d skipped", totals.testsSkipped)
	}
	fmt.Printf("%s  (%s)\n", line, roundMillis(totals.elapsed))
	if totals.filesNotRun > 0 {
		fmt.Printf("stopped after the first failing file; %s not run\n",
			countPhrase(totals.filesNotRun, 0, "file"))
	}
}

func (r *testReporter) emit(event testEvent) {
	if err := r.encoder.Encode(event); err != nil {
		fmt.Fprintf(os.Stderr, "mutant test: %v\n", err)
	}
}

func testOutcome(result *vm.TestResult) string {
	switch {
	case result.Skipped:
		return "skip"
	case result.Passed():
		return "pass"
	default:
		return "fail"
	}
}

func testEventFailures(result *vm.TestResult) []testEventFailure {
	if len(result.Failures) == 0 {
		return nil
	}
	out := make([]testEventFailure, 0, len(result.Failures))
	for _, failure := range result.Failures {
		out = append(out, testEventFailure{File: failure.File, Line: failure.Line, Message: failure.Message})
	}
	return out
}

func testResultError(result *vm.TestResult) string {
	if result.Err == nil {
		return ""
	}
	return result.Err.String()
}

// testDisplayName names a result. The top-level result has no name of its own,
// because what it collected was written outside every test -- so it answers to
// the file.
func testDisplayName(result *vm.TestResult, file string) string {
	if result.Name != "" {
		return result.Name
	}
	return filepath.Base(file)
}

func testCount(n int) string {
	if n == 1 {
		return "1 test"
	}
	return fmt.Sprintf("%d tests", n)
}

// countPhrase renders "5 files, 1 failed", dropping the second half when
// nothing failed rather than printing a zero the reader has to check.
func countPhrase(total, failed int, noun string) string {
	unit := noun
	if total != 1 {
		unit += "s"
	}
	if failed == 0 {
		return fmt.Sprintf("%d %s", total, unit)
	}
	return fmt.Sprintf("%d %s, %d failed", total, unit, failed)
}

func roundMillis(d time.Duration) string {
	return d.Round(time.Millisecond).String()
}

// collectMutantTestFiles expands paths into `*_test.mut` files: explicit file
// arguments are taken as-is; directories are walked for the `_test.mut` suffix
// (skipping .git/node_modules/vendor and dot-directories).
func collectMutantTestFiles(paths []string) ([]string, error) {
	testSuffix := "_test" + global.MutantSourceCodeFileExtention
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		walkErr := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == "node_modules" || name == "vendor" || (strings.HasPrefix(name, ".") && name != "." && name != "..") {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, testSuffix) {
				files = append(files, path)
			}
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}
	return files, nil
}
