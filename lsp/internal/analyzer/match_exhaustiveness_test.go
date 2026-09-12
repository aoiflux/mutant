package analyzer

import (
	"strings"
	"testing"
)

// exhaustivenessMessages keeps the tests to the one rule under test. The corpus
// these sources come from is small, but a `match` sitting in a file also draws
// unused-declaration and semicolon reports, and a test that asserted on the
// whole list would pass or fail for reasons that have nothing to do with it.
func exhaustivenessMessages(t *testing.T, src string) []string {
	t.Helper()

	kept := make([]string, 0, 1)
	for _, message := range lintMessages(t, src) {
		if strings.Contains(message, "covers only part of") {
			kept = append(kept, message)
		}
	}
	return kept
}

func TestAMatchMissingAnEnumVariantIsReported(t *testing.T) {
	src := "enum Status { Ok, Failed, Pending }\n" +
		"let label = match (current()) { Status.Ok => \"fine\", Status.Failed => \"bad\" };\n" +
		"putln(label);\n"

	messages := exhaustivenessMessages(t, src)
	if len(messages) != 1 {
		t.Fatalf("want one report, got %d: %v", len(messages), messages)
	}
	if !strings.Contains(messages[0], "`Status.Pending`") {
		t.Errorf("the report does not name the missing variant: %s", messages[0])
	}
}

func TestAMatchCoveringEveryVariantIsQuiet(t *testing.T) {
	src := "enum Status { Ok, Failed }\n" +
		"let label = match (current()) { Status.Ok => \"fine\", Status.Failed => \"bad\" };\n" +
		"putln(label);\n"

	if messages := exhaustivenessMessages(t, src); len(messages) != 0 {
		t.Fatalf("a total match was reported: %v", messages)
	}
}

// A wildcard is how a program says "and everything else". The rule going quiet
// on one is not a concession -- it is the construct working.
func TestAWildcardSuppressesTheReport(t *testing.T) {
	src := "enum Status { Ok, Failed, Pending }\n" +
		"let label = match (current()) { Status.Ok => \"fine\", _ => \"other\" };\n" +
		"putln(label);\n"

	if messages := exhaustivenessMessages(t, src); len(messages) != 0 {
		t.Fatalf("a match with `_` was reported: %v", messages)
	}
}

func TestAlternativesInOneArmCountAsCovered(t *testing.T) {
	src := "enum Status { Ok, Failed, Pending }\n" +
		"let label = match (current()) { Status.Ok | Status.Failed => \"known\", Status.Pending => \"wait\" };\n" +
		"putln(label);\n"

	if messages := exhaustivenessMessages(t, src); len(messages) != 0 {
		t.Fatalf("variants named through `|` were not counted as covered: %v", messages)
	}
}

func TestSeveralMissingVariantsAreNamedTogether(t *testing.T) {
	src := "enum Status { Ok, Failed, Pending }\n" +
		"let label = match (current()) { Status.Ok => \"fine\" };\n" +
		"putln(label);\n"

	messages := exhaustivenessMessages(t, src)
	if len(messages) != 1 {
		t.Fatalf("want one report, got %d: %v", len(messages), messages)
	}
	if !strings.Contains(messages[0], "`Status.Failed`") || !strings.Contains(messages[0], "`Status.Pending`") {
		t.Errorf("the report does not name both missing variants: %s", messages[0])
	}
}

// The guards. Each of these is a case where the rule cannot be certain what the
// total set of values is, and a warning it cannot back up is worse than none.
func TestTheRuleIsQuietWhereItCannotBeCertain(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			"a literal pattern means this is not a match over an enum",
			"enum Status { Ok, Failed, Pending }\n" +
				"let label = match (current()) { Status.Ok => \"fine\", 1 => \"one\" };\n",
		},
		{
			"two enums in one match is not a shape the rule models",
			"enum Status { Ok, Failed }\nenum Level { Low, High }\n" +
				"let label = match (current()) { Status.Ok => \"fine\", Level.Low => \"low\" };\n",
		},
		{
			"an imported enum's variants live in a file this document cannot see",
			"import \"lib/state.mut\";\n" +
				"let label = match (current()) { state.Status.Ok => \"fine\" };\n",
		},
		{
			"an enum with no declaration here could have any variants at all",
			"let label = match (current()) { Status.Ok => \"fine\" };\n",
		},
		{
			"a name that is both an enum and a binding is ambiguous",
			"enum Status { Ok, Failed, Pending }\nlet Status = 1;\n" +
				"let label = match (current()) { Status.Ok => \"fine\" };\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if messages := exhaustivenessMessages(t, tc.src+"putln(label);\n"); len(messages) != 0 {
				t.Fatalf("the rule reported where it cannot be certain: %v", messages)
			}
		})
	}
}

func TestTheRuleCanBeTurnedOff(t *testing.T) {
	src := "enum Status { Ok, Failed, Pending }\n" +
		"let label = match (current()) { Status.Ok => \"fine\" };\n" +
		"putln(label);\n"

	config := DefaultLintConfig()
	config.MatchExhaustiveness = LintSeverityOff
	for _, diagnostic := range Diagnostics(New().Analyze(src), config) {
		if strings.Contains(diagnostic.Message, "covers only part of") {
			t.Fatalf("the rule reported with its severity off: %s", diagnostic.Message)
		}
	}
}

// An arm after `_` can never run, which is the same defect unreachableCode
// already reports for a statement after `return` -- so it is reported by that
// rule rather than by one of its own.
func TestAnArmAfterAWildcardIsUnreachable(t *testing.T) {
	src := "enum Status { Ok, Failed }\n" +
		"let label = match (current()) { Status.Ok => \"fine\", _ => \"other\", Status.Failed => \"bad\" };\n" +
		"putln(label);\n"

	if !mentions(lintMessages(t, src), "unreachable arm after `_`") {
		t.Errorf("an arm written after `_` went unreported")
	}
}

func TestAWildcardInLastPositionIsNotUnreachable(t *testing.T) {
	src := "enum Status { Ok, Failed }\n" +
		"let label = match (current()) { Status.Ok => \"fine\", _ => \"other\" };\n" +
		"putln(label);\n"

	if mentions(lintMessages(t, src), "unreachable arm") {
		t.Errorf("a trailing `_` was reported as making something unreachable")
	}
}
