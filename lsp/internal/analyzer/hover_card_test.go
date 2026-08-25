package analyzer

import (
	"fmt"
	"strings"
	"testing"

	"mutant/builtin"
)

// TestEveryBuiltinRendersTheSameCardShape is what makes "unified" a property
// rather than a claim.
//
// The old renderer had three paths — a full one, a family-summary one, and a
// bare "Builtin function." — so what a reader learned from hover depended on
// which builtin they picked. This walks all 399 and requires every card to carry
// the same sections, so a builtin added without a contract fails here rather
// than shipping a card that is quietly thinner than its neighbours.
func TestEveryBuiltinRendersTheSameCardShape(t *testing.T) {
	var rendered int

	for _, def := range builtin.Builtins {
		if def.Name == "" {
			continue
		}
		text, ok := builtinHoverText(def.Name)
		if !ok {
			t.Errorf("builtin %q has no hover card", def.Name)
			continue
		}
		rendered++

		for _, required := range []string{
			"builtin `" + def.Name + "(",
			"**Parameters**",
			"**Returns**",
		} {
			if !strings.Contains(text, required) {
				t.Errorf("builtin %q: hover card is missing %q\n%s", def.Name, required, text)
			}
		}

		// The signature line must state a return, which is the fact no card
		// carried before.
		signature, _, _ := strings.Cut(strings.TrimPrefix(text, "builtin `"), "`")
		if !strings.Contains(signature, ") -> ") {
			t.Errorf("builtin %q: signature %q states no return type", def.Name, signature)
		}

		// A summary sits between the signature line and the Parameters heading.
		_, body, _ := strings.Cut(text, "`\n\n")
		summary, _, _ := strings.Cut(body, "\n\n**Parameters**")
		if strings.TrimSpace(summary) == "" {
			t.Errorf("builtin %q: hover card has no summary", def.Name)
		}
	}

	if rendered != len(builtin.Builtins) {
		t.Errorf("rendered %d cards for %d builtins", rendered, len(builtin.Builtins))
	}
	t.Logf("rendered a uniform card for all %d builtins", rendered)
}

// TestBuiltinCardShowsParameterTypesInBothPlaces pins the layout decision that
// each parameter's kinds appear inline in the signature *and* again on its own
// bullet. A long signature wraps in the hover popup, and when it does, a bullet
// that carries only prose leaves the reader counting commas to find which type
// belongs to which name.
func TestBuiltinCardShowsParameterTypesInBothPlaces(t *testing.T) {
	text, ok := builtinHoverText("str_substr")
	if !ok {
		t.Fatal("str_substr has no hover card")
	}

	if !strings.Contains(text, "str_substr(s: STRING, start: INTEGER, length: INTEGER) -> STRING") {
		t.Errorf("signature line does not carry the parameter kinds:\n%s", text)
	}
	for _, bullet := range []string{
		"- `s` · `STRING` — Source string.",
		"- `start` · `INTEGER` — Starting rune index; must be non-negative.",
		"- `length` · `INTEGER` — Number of runes to take; must be non-negative.",
	} {
		if !strings.Contains(text, bullet) {
			t.Errorf("missing parameter bullet %q:\n%s", bullet, text)
		}
	}
}

// TestBuiltinCardExplainsThePairShape covers the card's most useful line.
//
// Mutant splits its standard library between builtins that return a bare value
// and builtins that return a (value, err) pair, and which binding of
// `let a, b = f()` receives the error depends on which shape the builtin has.
// Nothing in the editor said which was which before.
func TestBuiltinCardExplainsThePairShape(t *testing.T) {
	pair, ok := builtinHoverText("fs_read")
	if !ok {
		t.Fatal("fs_read has no hover card")
	}
	if !strings.Contains(pair, "fs_read(path: STRING) -> (STRING, ERROR)") {
		t.Errorf("pair builtin's signature does not show the pair return:\n%s", pair)
	}
	if !strings.Contains(pair, "- bind both: `let value, err = fs_read(path);`") {
		t.Errorf("pair builtin's card does not show how to destructure it:\n%s", pair)
	}

	bare, ok := builtinHoverText("str_upper")
	if !ok {
		t.Fatal("str_upper has no hover card")
	}
	if !strings.Contains(bare, "str_upper(s: STRING) -> STRING") {
		t.Errorf("bare builtin's signature is wrong:\n%s", bare)
	}
	if strings.Contains(bare, "bind both") {
		t.Errorf("bare builtin's card promises a second binding it never returns:\n%s", bare)
	}
}

// TestBuiltinCardNamesHashFields checks the field names the metadata extracted
// from the implementations reach the reader. A hash return whose keys are
// unnamed is the least useful thing hover can say.
func TestBuiltinCardNamesHashFields(t *testing.T) {
	text, ok := builtinHoverText("time_now")
	if !ok {
		t.Fatal("time_now has no hover card")
	}
	for _, field := range []string{"`day`", "`hour`", "`iso`", "`unix`", "`year`"} {
		if !strings.Contains(text, field) {
			t.Errorf("time_now's card does not name the %s field:\n%s", field, text)
		}
	}
}

// TestBuiltinCardMarksOptionalAndVariadicParameters checks the `?` and `...`
// spellings are spelled out rather than left as convention a reader has to know.
func TestBuiltinCardMarksOptionalAndVariadicParameters(t *testing.T) {
	text, ok := builtinHoverText("help")
	if !ok {
		t.Fatal("help has no hover card")
	}
	if !strings.Contains(text, "- `topic?` · `STRING` _(optional)_") {
		t.Errorf("optional parameter is not marked:\n%s", text)
	}

	text, ok = builtinHoverText("putln")
	if !ok {
		t.Fatal("putln has no hover card")
	}
	if !strings.Contains(text, "_(variadic)_") {
		t.Errorf("variadic parameter is not marked:\n%s", text)
	}
}

// TestBuiltinCardShowsNoneForZeroParameters keeps the Parameters heading present
// even when there is nothing under it. Dropping the section would make a
// zero-argument builtin's card a different shape from every other one, which is
// exactly the inconsistency this work removes.
func TestBuiltinCardShowsNoneForZeroParameters(t *testing.T) {
	text, ok := builtinHoverText("time_now")
	if !ok {
		t.Fatal("time_now has no hover card")
	}
	if !strings.Contains(text, "**Parameters**\n- _none_") {
		t.Errorf("zero-parameter builtin does not say so:\n%s", text)
	}
}

// TestBuiltinCardShowsArrayElementContracts checks an array parameter that
// rejects other element kinds says so, matching what the element-type diagnostic
// enforces at the call site.
func TestBuiltinCardShowsArrayElementContracts(t *testing.T) {
	text, ok := builtinHoverText("str_join")
	if !ok {
		t.Fatal("str_join has no hover card")
	}
	if !strings.Contains(text, "`ARRAY of STRING`") {
		t.Errorf("str_join's array parameter does not name its element kind:\n%s", text)
	}
}

// TestSampleCardsForReview prints a few whole cards so a reviewer can read what
// the editor will actually show, rather than inferring it from assertions.
func TestSampleCardsForReview(t *testing.T) {
	for _, name := range []string{"fs_read", "time_now", "str_join", "vhdi_read_at"} {
		text, ok := builtinHoverText(name)
		if !ok {
			t.Fatalf("%s has no hover card", name)
			continue
		}
		fmt.Printf("\n======== %s ========\n%s\n", name, text)
	}
}
