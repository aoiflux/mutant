package analyzer

import (
	"testing"
)

// TestANameUsedOnlyInAHoleIsUsed is the false positive this rule exists to
// avoid. Before the walkers descended into a template, every variable an
// interpolated string read was reported unused -- a warning on correct code.
func TestANameUsedOnlyInAHoleIsUsed(t *testing.T) {
	src := "let host = \"db01\";\nputln(\"host=${host}\");\n"
	if unusedNames(t, src)["host"] {
		t.Errorf("`host` is read inside the string and was still reported unused")
	}
}

func TestAnUnusedNameIsStillUnusedWhenAnotherIsInterpolated(t *testing.T) {
	src := "let host = \"db01\";\nlet spare = 1;\nputln(\"host=${host}\");\n"
	unused := unusedNames(t, src)
	if unused["host"] {
		t.Errorf("`host` is used")
	}
	if !unused["spare"] {
		t.Errorf("`spare` is never read and should be reported")
	}
}

func TestATypoInAHoleIsUndefined(t *testing.T) {
	src := "let host = \"db01\";\nputln(\"host=${hsot}\");\n"
	if !mentions(lintMessages(t, src), "hsot") {
		t.Errorf("a misspelled name inside a hole went unreported")
	}
}

func TestACallInAHoleIsArgumentChecked(t *testing.T) {
	// The holes are ordinary expressions, so every builtin rule reaches them.
	src := "putln(\"upper=${ str_upper(42) }\");\n"
	if !mentions(lintMessages(t, src), "str_upper") {
		t.Errorf("a builtin call inside a hole was not checked")
	}
}

func TestARawStringHasNoHoles(t *testing.T) {
	// r"${x}" is text. Reporting `x` undefined there would be a hard error on
	// a correct program.
	src := "putln(r\"${nothing_here}\");\n"
	if mentions(lintMessages(t, src), "nothing_here") {
		t.Errorf("a raw string's ${...} was read as a hole")
	}
}

func TestAnInterpolatedStringInfersAsAString(t *testing.T) {
	// Whatever the holes hold, the result is a string; str_upper takes one, so
	// passing a template must not be reported as a type mismatch.
	src := "let n = 1;\nputln(str_upper(\"n=${n}\"));\n"
	if mentions(lintMessages(t, src), "argument 1 to `str_upper`") {
		t.Errorf("an interpolated string was not treated as a string argument")
	}
}
