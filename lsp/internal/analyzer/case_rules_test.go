package analyzer

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The four rules about the case builtins -- roleLiteral, filteredLedgerHandle,
// secretOption and lifecycleState -- each say the run time refuses the call, and
// each message carries a phrase no other rule's does.
var caseRuleMarkers = map[string]string{
	"roleLiteral":          "refuses this role: ",
	"filteredLedgerHandle": "does not read under a view, and argument 1 is a handle",
	"secretOption":         "refuses an option named ",
	"lifecycleState":       "never moves a case to ",
}

// caseRuleMessages returns the messages of one of those rules' diagnostics in
// src.
func caseRuleMessages(t *testing.T, rule, src string, config LintConfig) []string {
	t.Helper()
	marker, known := caseRuleMarkers[rule]
	if !known {
		t.Fatalf("no marker for %s", rule)
	}
	snapshot := New().Analyze(src)
	out := []string{}
	for _, d := range Diagnostics(snapshot, config) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, marker) {
			out = append(out, d.Message)
		}
	}
	return out
}

// Every example is a program that runs, so none of them makes a call these
// rules say is refused. A report here is a false positive, or an example that
// no longer runs.
func TestTheCaseRulesAreQuietOverTheExamples(t *testing.T) {
	root := filepath.Join("..", "..", "..", "examples")
	programs := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".mut" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		programs++
		for rule := range caseRuleMarkers {
			if got := caseRuleMessages(t, rule, string(data), DefaultLintConfig()); len(got) != 0 {
				t.Errorf("%s: %s reports %q", path, rule, got)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if programs < 100 {
		t.Fatalf("read %d example programs; the walk is not reaching them", programs)
	}
}

// Each rule answers to its own setting and to no other.
func TestEachCaseRuleCanBeSwitchedOffAlone(t *testing.T) {
	src := `case_open("IR-1", "examiner", {"role": "legal"});
let under, err = ledger_under_view(1, "counsel");
ledger_stats(under["handle"]);
record_open("exhibit.mrec", {"passphrase": "hunter2"});
case_transition(1, "in_review", "ready");
`
	for rule := range caseRuleMarkers {
		if got := caseRuleMessages(t, rule, src, DefaultLintConfig()); len(got) != 1 {
			t.Fatalf("%s: got %q at its default, want one report", rule, got)
		}
	}
	for off := range caseRuleMarkers {
		config := DefaultLintConfig()
		switch off {
		case "roleLiteral":
			config.RoleLiteral = LintSeverityOff
		case "filteredLedgerHandle":
			config.FilteredLedgerHandle = LintSeverityOff
		case "secretOption":
			config.SecretOption = LintSeverityOff
		case "lifecycleState":
			config.LifecycleState = LintSeverityOff
		}
		for rule := range caseRuleMarkers {
			got := caseRuleMessages(t, rule, src, config)
			if want := map[bool]int{true: 0, false: 1}[rule == off]; len(got) != want {
				t.Errorf("with %s off, %s reported %q, want %d", off, rule, got, want)
			}
		}
	}
}
