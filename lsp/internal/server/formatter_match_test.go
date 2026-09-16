package server

import (
	"strings"
	"testing"
)

func TestFormatterPrintsMatchArmsOnePerLine(t *testing.T) {
	got := format(t, `match(n){1=>"one",2=>"two",_=>"many"}`)
	for _, want := range []string{
		"match (n) {",
		indentUnit + `1 => "one",`,
		indentUnit + `2 => "two",`,
		indentUnit + `_ => "many",`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("formatted to %q, want it to contain %q", got, want)
		}
	}
}

// TestFormatterWritesATrailingComma pins the shape, not a preference: the
// parser accepts the trailing comma, and writing it means adding an arm touches
// one line rather than two.
func TestFormatterWritesATrailingComma(t *testing.T) {
	got := format(t, `match (n) { 1 => "one", _ => "many" }`)
	if !strings.Contains(got, `_ => "many",`) {
		t.Errorf("formatted to %q, want the last arm to end in a comma", got)
	}
}

// TestFormatterPrintsNegativePatternsUnparenthesised is the one place the
// canonical form has to give way. Every operator expression is parenthesised so
// precedence is explicit, but a pattern has no precedence to make explicit and
// the pattern grammar has no `(` in it -- so `(-1)` would be source the parser
// then rejects, which is the one thing a formatter must never emit.
func TestFormatterPrintsNegativePatternsUnparenthesised(t *testing.T) {
	got := format(t, `match (n) { -1 => "neg", _ => "other" }`)
	if !strings.Contains(got, `-1 => "neg",`) {
		t.Errorf("formatted to %q, want the pattern printed as `-1`", got)
	}
	if strings.Contains(got, "(-1)") {
		t.Errorf("formatted to %q, want no parentheses around the pattern", got)
	}
}

// TestFormatterKeepsTheArmBodyFormThatWasWritten: a block is how an arm does
// more than one thing, and rewriting one form into the other would churn every
// file that picked the other.
func TestFormatterKeepsTheArmBodyFormThatWasWritten(t *testing.T) {
	bare := format(t, `match (n) { 1 => "one", _ => "many" }`)
	if strings.Contains(bare, "=> {") {
		t.Errorf("a bare arm body was rewritten into a block: %q", bare)
	}

	braced := format(t, `match (n) { 1 => { "one" }, _ => "many" }`)
	if !strings.Contains(braced, "1 => {") {
		t.Errorf("a braced arm body lost its block: %q", braced)
	}
}

func TestFormatterKeepsAlternativesJoinedByPipe(t *testing.T) {
	got := format(t, `match (n) { 1|2|3 => "few", _ => "many" }`)
	if !strings.Contains(got, `1 | 2 | 3 => "few",`) {
		t.Errorf("formatted to %q, want the alternatives joined by ` | `", got)
	}
}

func TestFormatterKeepsEnumVariantPatterns(t *testing.T) {
	got := format(t, `match (s) { Status.Ok => 1, _ => 2 }`)
	if !strings.Contains(got, "Status.Ok => 1,") {
		t.Errorf("formatted to %q, want the variant printed as `Status.Ok`", got)
	}
}

func TestFormatterIsIdempotentOverMatch(t *testing.T) {
	src := "let describe = fn(s) {\nreturn match (s) {\nStatus.Ok => \"fine\",\nStatus.Retry | Status.Failed => { let note = \"not fine\"; note },\n_ => \"unknown\",\n};\n};\n"
	once := format(t, src)
	twice := format(t, once)
	if once != twice {
		t.Errorf("second format changed the text:\n%q\n%q", once, twice)
	}
}

func TestFormatterIndentsNestedMatchBodies(t *testing.T) {
	got := format(t, `match (a) { 1 => match (b) { 2 => c(), _ => d() }, _ => e() }`)
	if strings.Count(got, "match (") != 2 {
		t.Errorf("formatted to %q, want both matches kept", got)
	}
	if !strings.Contains(got, indentUnit+indentUnit+"2 => c(),") {
		t.Errorf("formatted to %q, want the inner arms indented twice", got)
	}
}

// TestFormatterAddsNoSemicolonAfterMatch pins that a match standing alone as a
// statement is brace-terminated. A stray `;` would be re-parsed as an empty
// statement and reported redundant on the next pass -- the formatter creating
// the warning it then reports.
func TestFormatterAddsNoSemicolonAfterMatch(t *testing.T) {
	got := strings.TrimSpace(format(t, `match (n) { 1 => a(), _ => b() }`))
	if strings.HasSuffix(got, ";") {
		t.Errorf("formatted to %q, want no trailing semicolon", got)
	}
}
