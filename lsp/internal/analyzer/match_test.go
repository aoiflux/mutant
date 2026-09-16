package analyzer

import (
	"testing"
)

// The walker arms added for `match` exist to prevent one false-positive class:
// a name a match reads and nothing else reads being reported as never used -- a
// warning on correct code, which is worse than no warning.
func TestANameUsedOnlyAsAMatchSubjectIsUsed(t *testing.T) {
	src := "let code = 2;\nlet label = match (code) { 1 => \"one\", _ => \"many\" };\nputln(label);\n"
	if unusedNames(t, src)["code"] {
		t.Errorf("`code` is the subject of a match and was still reported unused")
	}
}

func TestANameUsedOnlyInAMatchArmBodyIsUsed(t *testing.T) {
	src := "let fallback = \"many\";\nlet label = match (2) { 1 => \"one\", _ => fallback };\nputln(label);\n"
	if unusedNames(t, src)["fallback"] {
		t.Errorf("`fallback` is read by an arm body and was still reported unused")
	}
}

// TestAnEnumUsedOnlyInAMatchPatternIsUsed is why patterns are walked by the
// reference collector and not only by the ones that resolve names. An enum
// whose every mention is an arm pattern is the ordinary case, not an edge one.
func TestAnEnumUsedOnlyInAMatchPatternIsUsed(t *testing.T) {
	src := "enum Status { Ok, Err }\nlet label = match (s()) { Status.Ok => \"fine\", _ => \"not\" };\nputln(label);\n"
	if unusedNames(t, src)["Status"] {
		t.Errorf("`Status` is named by an arm pattern and was still reported unused")
	}
}

func TestAnUnusedNameIsStillUnusedBesideAMatch(t *testing.T) {
	// The other half: the arms must not make the rule blind. A name nothing
	// reads is still reported when a match stands next to it.
	src := "let spare = 1;\nlet label = match (2) { 1 => \"one\", _ => \"many\" };\nputln(label);\n"
	if !unusedNames(t, src)["spare"] {
		t.Errorf("`spare` is never read and should still be reported")
	}
}

func TestATypoInAMatchSubjectIsUndefined(t *testing.T) {
	src := "let code = 2;\nlet label = match (cdoe) { 1 => \"one\", _ => \"many\" };\nputln(label);\n"
	if !mentions(lintMessages(t, src), "cdoe") {
		t.Errorf("a misspelled match subject went unreported")
	}
}

func TestATypoInAMatchArmBodyIsUndefined(t *testing.T) {
	src := "let fallback = \"many\";\nlet label = match (2) { 1 => \"one\", _ => falback };\nputln(label);\n"
	if !mentions(lintMessages(t, src), "falback") {
		t.Errorf("a misspelled name in an arm body went unreported")
	}
}

func TestATypoInAnEnumPatternIsUndefined(t *testing.T) {
	src := "enum Status { Ok, Err }\nlet label = match (s()) { Sttaus.Ok => \"fine\", _ => \"not\" };\nputln(label);\n"
	if !mentions(lintMessages(t, src), "Sttaus") {
		t.Errorf("a misspelled enum in an arm pattern went unreported")
	}
}

// TestTheMatchWildcardIsNotAName is what the no-patterns representation buys.
// Were `_` stored as an identifier, this rule would have to know that this one
// name is not a name -- and here it would report it undefined.
func TestTheMatchWildcardIsNotAName(t *testing.T) {
	src := "let label = match (2) { 1 => \"one\", _ => \"many\" };\nputln(label);\n"
	if mentions(lintMessages(t, src), "\"_\"") {
		t.Errorf("the match wildcard was reported as a name: %v", lintMessages(t, src))
	}
}

func TestACallInAMatchSubjectIsArgumentChecked(t *testing.T) {
	// The subject is an ordinary expression, so every builtin rule reaches it.
	src := "let label = match (str_upper(42)) { \"A\" => 1, _ => 2 };\nputln(\"${label}\");\n"
	if !mentions(lintMessages(t, src), "str_upper") {
		t.Errorf("a builtin call in a match subject was not checked")
	}
}

func TestACallInAMatchArmBodyIsArgumentChecked(t *testing.T) {
	src := "let label = match (1) { 1 => str_upper(42), _ => \"\" };\nputln(label);\n"
	if !mentions(lintMessages(t, src), "str_upper") {
		t.Errorf("a builtin call in an arm body was not checked")
	}
}

// TestALetInsideAMatchArmIsSeenByTheRules pins that arm bodies are walked as
// statements, not skipped as opaque. A `let` nothing reads is the cheapest
// thing to look for that only a real walk can find.
func TestALetInsideAMatchArmIsSeenByTheRules(t *testing.T) {
	src := "let label = match (1) { 1 => { let inner = 5; \"one\" }, _ => \"many\" };\nputln(label);\n"
	if !unusedNames(t, src)["inner"] {
		t.Errorf("a `let` inside an arm body was never examined")
	}
}

// TestAMatchTypesAsTheJoinOfItsArms is where match does more than `if`, which
// settles for Any. An arm body is a block whose value is its trailing
// expression, which is exactly what the compiler keeps, so the arms can be
// joined the way a function's returns are.
func TestAMatchTypesAsTheJoinOfItsArms(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"all arms agree", "let x = match (n) { 1 => \"one\", _ => \"many\" };", "string"},
		{"all arms int", "let x = match (n) { 1 => 10, 2 => 20, _ => 30 };", "int"},
		// Arms that disagree have no single type, and the lattice carries no
		// union -- so Any, which this reports as no type at all rather than as
		// the type of whichever arms happen to be alike.
		{"arms disagree", "let x = match (n) { 1 => \"one\", _ => 2 };", ""},
		// A body that computes nothing produces null at run time, so joining it
		// in has to collapse the answer too.
		{"an arm leaves no value", "let x = match (n) { 1 => \"one\", _ => { let y = 1; } };", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := typeAt(t, c.src, 0, 4); got != c.want {
				t.Fatalf("type of the bound name = %q, want %q", got, c.want)
			}
		})
	}
}

// TestAFunctionEndingInAMatchTakesTheMatchType is the reason match is not
// excluded from tail position the way `if` is: `if` types as Any there, so
// appending it would only poison the join, but a match carries a real type.
func TestAFunctionEndingInAMatchTakesTheMatchType(t *testing.T) {
	src := "let describe = fn(n) { match (n) { 0 => \"zero\", _ => \"some\" } };\nlet label = describe(1);\n"
	if got := typeAt(t, src, 1, 4); got != "string" {
		t.Fatalf("the call's type is %q, want %q", got, "string")
	}
}
