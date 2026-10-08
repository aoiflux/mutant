package api

import (
	"strings"
	"testing"
)

func TestFormatCanonicalizesAndIsIdempotent(t *testing.T) {
	messy := "let   x=1\nlet y = fn(a,b){return a+b}\n"
	formatted, parseErrors := Format(messy)
	if len(parseErrors) > 0 {
		t.Fatalf("Format refused source that parses: %+v", parseErrors)
	}

	if formatted == messy {
		t.Fatal("expected Format to change messy input")
	}
	if !strings.Contains(formatted, "let x = 1;") {
		t.Fatalf("expected canonical `let x = 1;`, got:\n%s", formatted)
	}
	if !strings.HasSuffix(formatted, "\n") {
		t.Fatal("expected a trailing newline")
	}
	again, againErrors := Format(formatted)
	if len(againErrors) > 0 {
		t.Fatalf("Format refused its own output: %+v", againErrors)
	}
	if again != formatted {
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

// TestFormatRefusesSourceThatDoesNotParse is M26-TOOL-014 at the api seam the
// CLI calls. The contract the CLI relies on is the whole point: on a refusal
// the source comes back byte-for-byte, and the diagnostic slice is never
// empty, so `len(errs) > 0` is the single question "may I write this?".
func TestFormatRefusesSourceThatDoesNotParse(t *testing.T) {
	src := "let banner = \"\"\"\nrow one   \nrow two\n\"\"\";\nlet broken = ;\n"

	formatted, parseErrors := Format(src)
	if len(parseErrors) == 0 {
		t.Fatal("Format accepted source that does not parse")
	}
	if formatted != src {
		t.Errorf("Format changed source it refused:\n got %q\nwant %q", formatted, src)
	}
	for _, d := range parseErrors {
		if d.Severity != SeverityError {
			t.Errorf("refusal diagnostic severity = %q, want %q", d.Severity, SeverityError)
		}
		if d.Line < 1 || d.Column < 1 {
			t.Errorf("refusal diagnostic position = %d:%d, want 1-based", d.Line, d.Column)
		}
	}
}
