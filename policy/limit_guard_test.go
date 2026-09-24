package policy

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"mutant/policy/limitscan"
)

// limitPolicyDoc is named in every limit-guard failure.
const limitPolicyDoc = "docs/CONFIGURATION_POLICY.md (\"Limits\") and docs/LIMITS_REFERENCE.md"

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

// TestUnnamedLimitsStayWithinBudget is the guard. Each file may hold exactly as
// many unnamed limits as policy.LimitBudget says: more fails because a new
// literal limit appeared, fewer fails because the budget must come down with
// the fix, so the number only ever shrinks.
func TestUnnamedLimitsStayWithinBudget(t *testing.T) {
	result := scanLimits(t)

	byFile := map[string][]limitscan.Finding{}
	for _, f := range result.Findings {
		byFile[f.File] = append(byFile[f.File], f)
	}

	files := make([]string, 0, len(byFile))
	for file := range byFile {
		files = append(files, file)
	}
	sort.Strings(files)

	var over, under []string
	for _, file := range files {
		got, allowed := len(byFile[file]), LimitBudget[file]
		if got > allowed {
			var b strings.Builder
			fmt.Fprintf(&b, "%s holds %d unnamed limit(s); its budget is %d:\n", file, got, allowed)
			for _, f := range byFile[file] {
				fmt.Fprintf(&b, "    %s\n", f)
			}
			over = append(over, b.String())
		}
	}
	for file, allowed := range LimitBudget {
		if got := len(byFile[file]); got < allowed {
			under = append(under, fmt.Sprintf("%s: budget %d, now %d -- lower policy.LimitBudget[%q] to %d%s",
				file, allowed, got, file, got, deleteHint(got)))
		}
	}
	sort.Strings(under)

	if len(over) > 0 {
		t.Errorf("unnamed limits beyond policy.LimitBudget:\n\n%s\n%s\n\nSee %s.",
			strings.Join(over, "\n"), limitHowTo, limitPolicyDoc)
	}
	if len(under) > 0 {
		t.Errorf("limits were named -- thank you. The budget has to come down with them, or the\n"+
			"headroom would let a new unnamed limit in unnoticed:\n  %s", strings.Join(under, "\n  "))
	}
}

func deleteHint(got int) string {
	if got == 0 {
		return " (delete the entry)"
	}
	return ""
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
	for file, allowed := range LimitBudget {
		if allowed < 1 {
			t.Errorf("policy.LimitBudget[%q] is %d; an entry that allows nothing should be deleted", file, allowed)
		}
		if filepath.ToSlash(file) != file || strings.HasPrefix(file, "/") || strings.HasPrefix(file, "./") {
			t.Errorf("policy.LimitBudget[%q]: use a repository-relative path with forward slashes", file)
		}
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
	const header = "package p\n\nimport (\n\t\"bufio\"\n\t\"flag\"\n\t\"time\"\n)\n\nvar _ = bufio.NewScanner\nvar _ = flag.Int\nvar _ = time.Now\n\n"

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
