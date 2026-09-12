package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/vm"
)

// writeTestTree writes the named files into a fresh directory and returns it.
func writeTestTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runOneTestFile(t *testing.T, files map[string]string, name string) testFileReport {
	t.Helper()
	return runOneTestFileWith(t, files, name, vm.TestRunOptions{})
}

func runOneTestFileWith(t *testing.T, files map[string]string, name string, options vm.TestRunOptions) testFileReport {
	t.Helper()
	dir := writeTestTree(t, files)
	return runTestFileAt(filepath.Join(dir, name), nil, options)
}

// outcomes renders a report as "name:outcome" pairs, which answers most of
// these tests in one line.
func outcomes(report testFileReport, file string) []string {
	var out []string
	for _, result := range report.results {
		out = append(out, testDisplayName(result, file)+":"+testOutcome(result))
	}
	return out
}

// The reason this phase exists. `mutant test` used to compile through its own
// private pipeline -- lexer, parser, compiler.New() -- which left `import`
// resolving to nothing, so the namespace it bound was an undefined variable and
// no module could be tested at all.
func TestATestFileCanImportTheModuleItTests(t *testing.T) {
	report := runOneTestFile(t, map[string]string{
		"lib/stats.mut": "let largest = fn(xs) { reduce(xs, fn(a, b) { if (b > a) { b } else { a } }, first(xs)) };\n",
		"stats_test.mut": `import numbers "lib/stats.mut";

test("largest picks the biggest", fn() {
    assert_eq(numbers.largest([1, 5, 3]), 5);
});
`,
	}, "stats_test.mut")

	if report.err != "" {
		t.Fatalf("unexpected file error: %s", report.err)
	}
	if !report.passed() {
		t.Fatalf("expected the file to pass, got %+v", report.results)
	}
	if len(report.results) != 1 || report.results[0].Name != "largest picks the biggest" {
		t.Fatalf("expected one named test, got %+v", report.results)
	}
}

func TestAFailingTestIsReportedWithItsPosition(t *testing.T) {
	report := runOneTestFile(t, map[string]string{
		"a_test.mut": "test(\"arithmetic\", fn() {\n    assert_eq(1 + 1, 3);\n});\n",
	}, "a_test.mut")

	if report.passed() {
		t.Fatal("expected the file to fail")
	}
	if len(report.results) != 1 {
		t.Fatalf("expected one test, got %d", len(report.results))
	}
	failures := report.results[0].Failures
	if len(failures) != 1 {
		t.Fatalf("expected one failure, got %d", len(failures))
	}
	if failures[0].Line != 2 {
		t.Errorf("failure line = %d, want 2", failures[0].Line)
	}
	if !strings.HasSuffix(failures[0].File, "a_test.mut") {
		t.Errorf("failure file = %q, want it to name a_test.mut", failures[0].File)
	}
}

// A file that declares no test keeps the original contract. Programs shaped
// that way are still tests, and the file is reported as one test named after
// itself.
func TestAFileWithNoTestKeepsTheOriginalContract(t *testing.T) {
	cases := []struct {
		name       string
		source     string
		wantPassed bool
	}{
		{"true", "1 + 1 == 2;\n", true},
		{"false", "1 + 1 == 3;\n", false},
		{"non-boolean", "let x = 5;\nx;\n", true},
		{"ends-in-let", "let x = 5;\n", true},
		{"runtime-error", "1 / 0;\n", false},
		{"parse-error", "let = ;\n", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			report := runOneTestFile(t, map[string]string{"x_test.mut": c.source}, "x_test.mut")
			if report.passed() != c.wantPassed {
				t.Fatalf("passed = %v, want %v (err %q, results %+v)",
					report.passed(), c.wantPassed, report.err, report.results)
			}
		})
	}
}

// One test that dies costs the file nothing but itself.
func TestATestThatDiesDoesNotStopTheOthers(t *testing.T) {
	report := runOneTestFile(t, map[string]string{
		"d_test.mut": `
test("dies", fn() { let x = 1 / 0; });
test("runs", fn() { assert(true); });
`,
	}, "d_test.mut")

	if len(report.results) != 2 {
		t.Fatalf("expected 2 tests, got %d: %+v", len(report.results), report.results)
	}
	if report.results[0].Passed() || !report.results[1].Passed() {
		t.Fatalf("expected the first to fail and the second to pass, got %+v", report.results)
	}
	if report.err != "" {
		t.Errorf("the file itself reported %q; a caught test error is not a file error", report.err)
	}
}

// A file that will not compile is a failure of the file, not of a test.
func TestAFileThatWillNotCompileFailsAsTheFile(t *testing.T) {
	report := runOneTestFile(t, map[string]string{
		"bad_test.mut": "import missing \"nowhere/at/all.mut\";\n",
	}, "bad_test.mut")

	if report.passed() {
		t.Fatal("expected the file to fail")
	}
	if report.err == "" {
		t.Fatal("expected a file-level error")
	}
	if len(report.results) != 0 {
		t.Errorf("a file that never ran reported %d tests", len(report.results))
	}
}

func TestHandleTestCommandExitCodes(t *testing.T) {
	dir := writeTestTree(t, map[string]string{
		"pass_test.mut": "test(\"ok\", fn() { assert(true); });\n",
		"helper.mut":    "let a = 1;\n", // not a *_test.mut -> ignored
	})

	if code := handleTestCommand([]string{"mutant", "test", dir}); code != 0 {
		t.Fatalf("all-passing test dir exit = %d, want 0", code)
	}

	if err := os.WriteFile(filepath.Join(dir, "fail_test.mut"),
		[]byte("test(\"no\", fn() { fail(\"deliberate\"); });\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := handleTestCommand([]string{"mutant", "test", dir}); code != 1 {
		t.Fatalf("dir with a failing test exit = %d, want 1", code)
	}
}

func TestCollectMutantTestFilesFiltersSuffix(t *testing.T) {
	dir := writeTestTree(t, map[string]string{
		"a_test.mut": "let a = 1;\n",
		"b_test.mut": "let a = 1;\n",
		"helper.mut": "let a = 1;\n",
		"notes.txt":  "let a = 1;\n",
	})

	files, err := collectMutantTestFiles([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 *_test.mut files, got %d: %v", len(files), files)
	}
}

// --run selects per nesting level, the way `go test -run` reads: the pattern is
// split on "/" and each part matches the test at that depth.
func TestRunPatternSelectsPerNestingLevel(t *testing.T) {
	const source = `
test("alpha", fn() { assert(true); });
test("beta", fn() {
    test("inner one", fn() { assert(true); });
    test("inner two", fn() { assert(true); });
});
`

	cases := []struct {
		pattern string
		want    string
	}{
		{"", "alpha:pass beta:pass beta/inner one:pass beta/inner two:pass"},
		{"beta", "alpha:skip beta:pass beta/inner one:pass beta/inner two:pass"},
		{"beta/inner one", "alpha:skip beta:pass beta/inner one:pass beta/inner two:skip"},
		{"^z", "alpha:skip beta:skip"},
	}

	for _, c := range cases {
		t.Run(c.pattern, func(t *testing.T) {
			filter, err := vm.NewTestFilter(c.pattern)
			if err != nil {
				t.Fatal(err)
			}
			report := runOneTestFileWith(t,
				map[string]string{"f_test.mut": source}, "f_test.mut",
				vm.TestRunOptions{Filter: filter})

			if got := strings.Join(outcomes(report, "f_test.mut"), " "); got != c.want {
				t.Errorf("--run %q selected %q, want %q", c.pattern, got, c.want)
			}
		})
	}
}

// A skipped test is neither a pass nor a failure, so a run that selected
// nothing still succeeds.
func TestAFilterThatSelectsNothingStillPasses(t *testing.T) {
	filter, err := vm.NewTestFilter("^nothing$")
	if err != nil {
		t.Fatal(err)
	}
	report := runOneTestFileWith(t,
		map[string]string{"f_test.mut": `test("a", fn() { fail("would fail"); });`},
		"f_test.mut", vm.TestRunOptions{Filter: filter})

	if !report.passed() {
		t.Fatalf("a run that called no test reported a failure: %+v", report.results)
	}
}

func TestAnInvalidRunPatternIsRefused(t *testing.T) {
	if _, err := vm.NewTestFilter("("); err == nil {
		t.Fatal("expected an unbalanced parenthesis to be refused")
	}
	if code := handleTestCommand([]string{"mutant", "test", "--run", "(", t.TempDir()}); code != 2 {
		t.Errorf("an invalid --run exited %d, want 2", code)
	}
}

// --fail-fast stops calling tests once one has failed. The ones already run
// keep their results; what is left is skipped rather than silently dropped.
func TestFailFastSkipsWhatIsLeft(t *testing.T) {
	report := runOneTestFileWith(t, map[string]string{"f_test.mut": `
test("first", fn() { assert(true); });
test("second", fn() { fail("stop here"); });
test("third", fn() { assert(true); });
`}, "f_test.mut", vm.TestRunOptions{FailFast: true})

	want := "first:pass second:fail third:skip"
	if got := strings.Join(outcomes(report, "f_test.mut"), " "); got != want {
		t.Errorf("--fail-fast produced %q, want %q", got, want)
	}
}
