package policy

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"mutant/policy/limitscan"
)

// limitPolicyDoc is named in every limit-guard failure.
const limitPolicyDoc = "docs/CONFIGURATION_POLICY.md (\"Limits\") and docs/LIMITS_REFERENCE.md"

// scanHeader opens every source the self-tests scan, importing what their
// snippets use.
const scanHeader = "package p\n\nimport (\n\t\"bufio\"\n\t\"flag\"\n\t\"time\"\n)\n\nvar _ = bufio.NewScanner\nvar _ = flag.Int\nvar _ = time.Now\n\n"

var (
	limitScanOnce   sync.Once
	limitScanResult *limitscan.Result
	limitScanErr    error
)

// scanLimits walks the repository once per test binary; five tests read it.
func scanLimits(t *testing.T) *limitscan.Result {
	t.Helper()
	limitScanOnce.Do(func() {
		limitScanResult, limitScanErr = limitscan.Scan(repositoryRoot)
	})
	if limitScanErr != nil {
		t.Fatalf("limit scan: %v", limitScanErr)
	}
	return limitScanResult
}

const limitHowTo = `Name the value as a package-level const in the package that enforces it, and
say why it has that value in the const's doc comment, followed by a directive:

	// maxWidgets bounds how many widgets one call returns, so a crafted
	// input cannot make the result unbounded.
	//
	//mutant:limit count
	const maxWidgets = 4096

Units: ` + "bytes, bits, count, depth, duration, iterations, percent, ratio, score" + `.
Add flag=--name when a command-line flag overrides it. A value fixed by a file
format or protocol is not a limit: mark it //mutant:format <spec reference>.
Then run ` + "`go run ./cmd/gendocs`" + ` to refresh the limits reference.`

// TestUnnamedLimitsStayWithinBudget is the guard. A file may hold the unnamed
// limits policy.LimitBudget lists for it and no others: one it does not list
// fails because a new literal limit appeared, and an entry nothing answers to
// fails because the entry must come out with the fix, so the list only ever
// shrinks.
func TestUnnamedLimitsStayWithinBudget(t *testing.T) {
	over, under := budgetCheck(scanLimits(t).Findings, LimitBudget)
	if len(over) > 0 {
		t.Errorf("unnamed limits that policy.LimitBudget does not list:\n\n    %s\n\n%s\n\nSee %s.",
			strings.Join(over, "\n    "), limitHowTo, limitPolicyDoc)
	}
	if len(under) > 0 {
		t.Errorf("limits were named -- thank you. Their entries have to come out of policy.LimitBudget in the\n"+
			"same change, or an entry would let the same limit back in unnoticed:\n  %s", strings.Join(under, "\n  "))
	}
}

// budgetCheck holds a scan's findings against a budget, file by file and
// finding by finding. over lists each finding the budget does not hold; under
// lists each entry that no finding answers to any more. An entry answers to
// one finding, so a key listed twice allows two.
func budgetCheck(findings []limitscan.Finding, budget map[string][]string) (over, under []string) {
	found := map[string][]limitscan.Finding{}
	files := map[string]bool{}
	for _, f := range findings {
		found[f.File] = append(found[f.File], f)
		files[f.File] = true
	}
	for file := range budget {
		files[file] = true
	}
	sorted := make([]string, 0, len(files))
	for file := range files {
		sorted = append(sorted, file)
	}
	sort.Strings(sorted)

	for _, file := range sorted {
		allowed := map[string]int{}
		for _, key := range budget[file] {
			allowed[key]++
		}
		for _, f := range found[file] {
			if allowed[f.Key()] > 0 {
				allowed[f.Key()]--
				continue
			}
			over = append(over, f.String())
		}
		for _, key := range budget[file] {
			if allowed[key] > 0 {
				allowed[key]--
				under = append(under, fmt.Sprintf("%s: %q", file, key))
			}
		}
	}
	return over, under
}

// A budget entry for a file that no longer exists is a hole in the guard.
func TestLimitBudgetHasNoStaleEntries(t *testing.T) {
	result := scanLimits(t)
	for file := range LimitBudget {
		if !result.Scanned[file] {
			t.Errorf("policy.LimitBudget names %s, which the scan did not read (moved, deleted, or now a test file). Remove the entry.", file)
		}
	}
}

func TestLimitBudgetEntriesAreWellFormed(t *testing.T) {
	for _, problem := range budgetProblems(LimitBudget) {
		t.Error(problem)
	}

	// The check itself, on a budget that breaks each rule once.
	bad := budgetProblems(map[string][]string{
		"p/p.go":   {"N1 package level: maxThings = 500", "maxThings = 500", "Q9 f: 1"},
		"./p/q.go": {"L1 f: 4096"},
		"p/r.go":   {},
	})
	if len(bad) != 4 {
		t.Errorf("a key with no rule, an unknown rule, a ./ path and an empty list should be four problems, got %v", bad)
	}
}

// budgetProblems lists what is wrong with a budget's own shape.
func budgetProblems(budget map[string][]string) []string {
	var problems []string
	for file, keys := range budget {
		if len(keys) == 0 {
			problems = append(problems, fmt.Sprintf("policy.LimitBudget[%q] lists nothing; an entry that allows nothing should be deleted", file))
		}
		if filepath.ToSlash(file) != file || strings.HasPrefix(file, "/") || strings.HasPrefix(file, "./") {
			problems = append(problems, fmt.Sprintf("policy.LimitBudget[%q]: use a repository-relative path with forward slashes", file))
		}
		for _, key := range keys {
			rule, rest, ok := strings.Cut(key, " ")
			if !ok || limitscan.RuleDescriptions[rule] == "" || !strings.Contains(rest, ": ") {
				problems = append(problems, fmt.Sprintf("policy.LimitBudget[%q]: %q is not a finding's key (rule, function, expression)", file, key))
			}
		}
	}
	sort.Strings(problems)
	return problems
}

// TestTheBudgetListsFindingsNotCounts is the swap a count per file let through
// (M26-LIM-005): one limit in a file is named while a new one is written into
// the same file, and the file's count does not move. A budget of findings sees
// both. A limit that only moves down its file keeps its entry.
func TestTheBudgetListsFindingsNotCounts(t *testing.T) {
	scan := func(src string) []limitscan.Finding {
		t.Helper()
		result, err := limitscan.ScanSource("p/p.go", []byte(scanHeader+src))
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		return result.Findings
	}
	before := scan("func f() time.Duration { return 5 * time.Second }\n")
	if len(before) != 1 {
		t.Fatalf("the fixture should hold one finding, got %v", before)
	}
	budget := map[string][]string{"p/p.go": {before[0].Key()}}

	moved := scan("\n\n\nfunc f() time.Duration { return 5 * time.Second }\n")
	if over, under := budgetCheck(moved, budget); len(over)+len(under) != 0 {
		t.Errorf("a limit that moved down its file lost its entry: over %v, under %v", over, under)
	}

	swapped := scan("// lookupTimeout bounds one lookup.\n//\n//mutant:limit duration\nconst lookupTimeout = 5 * time.Second\n\n" +
		"func f() time.Duration { return lookupTimeout }\n\nfunc g() []byte { return make([]byte, 1<<24) }\n")
	over, under := budgetCheck(swapped, budget)
	if len(over) != 1 || !strings.Contains(over[0], "1<<24") {
		t.Errorf("the new unnamed allocation should be the one finding over the budget, got %v", over)
	}
	if len(under) != 1 || !strings.Contains(under[0], "5 * time.Second") {
		t.Errorf("the named timeout's entry should be the one left over, got %v", under)
	}

	// A file whose last unnamed limit is named has no findings at all, and
	// its entry has to be reported all the same.
	named := scan("// lookupTimeout bounds one lookup.\n//\n//mutant:limit duration\nconst lookupTimeout = 5 * time.Second\n\n" +
		"func f() time.Duration { return lookupTimeout }\n")
	if over, under := budgetCheck(named, budget); len(over) != 0 || len(under) != 1 {
		t.Errorf("a file with nothing left unnamed should leave its one entry over: over %v, under %v", over, under)
	}
}

// A directive that does not parse is a claim nobody can check, so malformed
// directives are never budgeted.
func TestLimitDirectivesAreWellFormed(t *testing.T) {
	result := scanLimits(t)
	for _, p := range result.Problems {
		t.Errorf("%s\n%s", p, limitHowTo)
	}
}

// TestLimitGuardScansTheRepository makes a wrong root or a skipped build tag
// fail as itself rather than as a quietly empty scan.
func TestLimitGuardScansTheRepository(t *testing.T) {
	result := scanLimits(t)
	for _, want := range []string{
		"main.go",
		"runner/runner.go",
		"builtin/archive.go",
		"security/sandbox_windows.go",
		"security/sandbox_linux.go",
		"builtin/system_forensics_memscan_linux.go",
	} {
		if !result.Scanned[want] {
			t.Errorf("the limit guard did not scan %s", want)
		}
	}
	for file := range result.Scanned {
		if strings.HasSuffix(file, "_test.go") {
			t.Errorf("the limit guard scanned the test file %s; test values are not limits", file)
		}
	}
}

// TestTheLimitGuardCatchesEachRule pins what each rule recognises, and what it
// deliberately leaves alone, so a rule that silently stops matching fails here
// instead of letting its whole class of limit back in.
func TestTheLimitGuardCatchesEachRule(t *testing.T) {
	const header = scanHeader

	catches := []struct {
		rule string
		src  string
	}{
		{limitscan.RuleAllocation, "func f() { _ = make([]byte, 4096) }"},
		{limitscan.RuleAllocation, "func f() { _ = make([]byte, 0, 64*1024) }"},
		{limitscan.RuleIOCap, "func f(s *bufio.Scanner, b []byte) { s.Buffer(b, 1<<20) }"},
		{limitscan.RuleDuration, "func f() time.Duration { return 5 * time.Second }"},
		{limitscan.RuleDuration, "func f() time.Duration { return time.Duration(250) }"},
		{limitscan.RuleBound, "func f(depth int) bool { return depth > 64 }"},
		{limitscan.RuleBound, "func f(b []byte) bool { return len(b) > 1000000 }"},
		{limitscan.RuleLoop, "func f() { for attempt := 0; attempt < 5; attempt++ {} }"},
		{limitscan.RuleLoop, "func f() { for i := 0; i < 5000; i++ {} }"},
		{limitscan.RuleFlagDefault, "func f(fs *flag.FlagSet) { _ = fs.Int(\"levels\", 10, \"how many\") }"},
		{limitscan.RuleLimitField, "type c struct{ MaxItems int }\n\nfunc f() c { return c{MaxItems: 500} }"},
		{limitscan.RuleLimitField, "func f() int { maxItems := 500; return maxItems }"},
		{limitscan.RuleLocalConst, "func f() int { const maxItems = 500; return maxItems }"},
		{limitscan.RuleLargeArg, "func g(int) {}\n\nfunc f() { g(1 << 20) }"},
		{limitscan.RuleUndocumented, "const maxItems = 500"},
		{limitscan.RuleUndocumented, "const sqliteMaxRows = 1_000_000"},
		{limitscan.RuleUndocumented, "const DefaultSegmentSize = 64 << 10"},
	}
	for _, c := range catches {
		result, err := limitscan.ScanSource("p/p.go", []byte(header+c.src+"\n"))
		if err != nil {
			t.Fatalf("%s: %v", c.src, err)
		}
		if len(result.Findings) != 1 || result.Findings[0].Rule != c.rule {
			t.Errorf("%s should produce exactly one %s finding, got %v", c.src, c.rule, result.Findings)
		}
	}

	ignores := []string{
		// Named and documented: the whole point.
		"// maxItems bounds the result.\n//\n//mutant:limit count\nconst maxItems = 500",
		"// headerSize is fixed by the format.\n//\n//mutant:format RFC 9999 section 2\nconst headerSize = 16",
		// Format checks: hex, or small against a name that is only weakly a bound.
		"func f(b []byte) bool { return len(b) < 0x4000 }",
		"func f(size int) bool { return size < 8 }",
		// Small buffers are format facts; unit conversion is not a limit.
		"func f() { _ = make([]byte, 8) }",
		"func f(n int64) int64 { return n / 1000 }",
		// Named constants used through a name are the fix, not the finding.
		"// maxItems bounds it.\n//\n//mutant:limit count\nconst maxItems = 500\n\nfunc f(n int) bool { return n > maxItems }",
		// A string constant with a limit-like name is not a number.
		"const defaultOutputPath = \"docs/x.md\"",
		// -1, 0, 1 and 2 are never limits.
		"func f(depth int) bool { return depth > 2 }",
	}
	for _, src := range ignores {
		result, err := limitscan.ScanSource("p/p.go", []byte(header+src+"\n"))
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if len(result.Findings) != 0 || len(result.Problems) != 0 {
			t.Errorf("%s should produce nothing, got findings %v problems %v", src, result.Findings, result.Problems)
		}
	}

	malformed := []string{
		"// why.\n//\n//mutant:limit furlongs\nconst maxItems = 500",
		"//mutant:limit count\nconst maxItems = 500",
		"// why.\n//\n//mutant:limit count flag=levels\nconst maxItems = 500",
		"// why.\n//\n//mutant:limit count\nvar maxItems = 500",
		"// why.\n//\n//mutant:format\nconst headerSize = 16",
		"// why.\n//\n//mutant:guess count\nconst maxItems = 500",
	}
	for _, src := range malformed {
		result, err := limitscan.ScanSource("p/p.go", []byte(header+src+"\n"))
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if len(result.Problems) == 0 {
			t.Errorf("%s should be reported as a malformed directive", src)
		}
	}
}

// TestLimitValuesAreShownInTheirUnits pins how the reference prints a value: a
// size as a size and a time as a time, whatever the constant counts in. An
// integer of milliseconds printed as a duration would read as nanoseconds.
func TestLimitValuesAreShownInTheirUnits(t *testing.T) {
	cases := []struct{ unit, expr, want string }{
		{"bytes", "64 << 10", "64 KiB"},
		{"bytes", "1000", "1,000 bytes"},
		{"duration", "30 * time.Second", "30s"},
		{"milliseconds", "250", "250ms"},
		{"milliseconds", "30_000", "30s"},
		{"microseconds", "200000", "200ms"},
		{"kibibytes", "64 * 1024", "64 MiB"},
		{"count", "1_000_000", "1,000,000"},
		{"score", "70", "70"},
	}
	for _, c := range cases {
		src := scanHeader + "// why.\n//\n//mutant:limit " + c.unit + "\nconst maxThing = " + c.expr + "\n"
		result, err := limitscan.ScanSource("p/p.go", []byte(src))
		if err != nil {
			t.Fatalf("%s %s: %v", c.unit, c.expr, err)
		}
		if len(result.Problems) != 0 || len(result.Limits) != 1 {
			t.Fatalf("%s %s: problems %v, limits %v", c.unit, c.expr, result.Problems, result.Limits)
		}
		if got := result.Limits[0].Value; got != c.want {
			t.Errorf("%s in %s is shown as %q, want %q", c.expr, c.unit, got, c.want)
		}
	}
}

// fuzzTarget matches the declaration of a Go fuzz target.
var fuzzTarget = regexp.MustCompile(`(?m)^func Fuzz\w*\(\s*\w+\s+\*testing\.F\s*\)`)

// TestTheLimitsSectionSaysWhetherAnythingIsFuzzed holds the policy's one
// sentence about fuzzing to the tree (M26-LIM-002). The section excused
// binary-format offsets from the guard because "their bounds are tested by
// fuzzing instead" while the tree had no fuzz target at all. While there are
// none it has to say so; once there are, it has to stop saying so.
func TestTheLimitsSectionSaysWhetherAnythingIsFuzzed(t *testing.T) {
	var targets []string
	err := filepath.WalkDir(repositoryRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".codegraph", "node_modules", "testdata", "mutant-vscode-extension":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if fuzzTarget.Match(src) {
			targets = append(targets, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	doc, err := os.ReadFile(filepath.Join(repositoryRoot, "docs", "CONFIGURATION_POLICY.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(doc), "## 6. Limits")
	if !found {
		t.Fatal("docs/CONFIGURATION_POLICY.md has no \"## 6. Limits\" section")
	}
	saysNone := strings.Contains(section, "no fuzz targets")
	switch {
	case len(targets) == 0 && !saysNone:
		t.Error("the tree has no fuzz targets, and the Limits section of docs/CONFIGURATION_POLICY.md must say " +
			"so (\"no fuzz targets\") rather than leave a reader to assume the offsets it does not guard are fuzzed")
	case len(targets) > 0 && saysNone:
		t.Errorf("the tree has fuzz targets (%s), and the Limits section of docs/CONFIGURATION_POLICY.md still "+
			"says there are none; say what they cover", strings.Join(targets, ", "))
	}
}
