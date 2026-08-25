package api

import (
	"strings"
	"testing"
)

func TestFormatCanonicalizesAndIsIdempotent(t *testing.T) {
	messy := "let   x=1\nlet y = fn(a,b){return a+b}\n"
	formatted := Format(messy)

	if formatted == messy {
		t.Fatal("expected Format to change messy input")
	}
	if !strings.Contains(formatted, "let x = 1;") {
		t.Fatalf("expected canonical `let x = 1;`, got:\n%s", formatted)
	}
	if !strings.HasSuffix(formatted, "\n") {
		t.Fatal("expected a trailing newline")
	}
	if again := Format(formatted); again != formatted {
		t.Fatalf("Format is not idempotent:\nfirst:\n%s\nsecond:\n%s", formatted, again)
	}
}

func TestLintReportsUndefinedAndUnused(t *testing.T) {
	src := "let a = 1;\nputln(undefined_thing);\n"
	diags := Lint(src)

	var haveErr, haveWarn bool
	for _, d := range diags {
		if d.Severity == SeverityError && strings.Contains(d.Message, "undefined_thing") {
			haveErr = true
			if d.Line != 2 {
				t.Fatalf("undefined diagnostic line = %d, want 2", d.Line)
			}
		}
		if d.Severity == SeverityWarning && strings.Contains(d.Message, "`a`") {
			haveWarn = true
		}
	}
	if !haveErr {
		t.Fatalf("expected an error diagnostic for undefined_thing, got %+v", diags)
	}
	if !haveWarn {
		t.Fatalf("expected an unused-declaration warning for a, got %+v", diags)
	}
}

func TestLintCleanSourceHasNoErrors(t *testing.T) {
	for _, d := range Lint("let a = 1;\nputln(a);\n") {
		if d.Severity == SeverityError {
			t.Fatalf("clean source produced an error diagnostic: %+v", d)
		}
	}
}
