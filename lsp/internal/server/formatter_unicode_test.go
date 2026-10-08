package server

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The formatter writes a token's own text back to the file, so a lexer that cut
// an identifier through the middle of a rune did not merely misread the program
// -- running `mutant fmt` over it replaced the author's source with bytes that
// are not UTF-8 at all. These tests are on the formatter rather than the lexer
// because the lexer is where the fix is, and this is the file that would be
// damaged. (M26-LEX-002)

func TestFormattingKeepsANonASCIINameIntact(t *testing.T) {
	for _, tt := range []struct{ name, src string }{
		{"a letter with an umlaut", "let grün = 1;\nputln(grün);\n"},
		{"two names that share a leading byte", "let xà = 7;\nlet xÅ = 8;\nputln(xà);\n"},
		{"a Cyrillic name", "let вода = 1;\nputln(вода);\n"},
		{"an accented name", "let café = \"open\";\nputln(café);\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, _, ok := FormatSource(tt.src)
			if !ok {
				t.Fatalf("the formatter refused %q, which parses", tt.src)
			}

			if !utf8.ValidString(got) {
				t.Fatalf("formatting %q produced bytes that are not valid UTF-8: %q", tt.src, got)
			}

			// Every name the author wrote is still spelled the way they wrote it.
			for _, name := range namesIn(tt.src) {
				if !strings.Contains(got, name) {
					t.Errorf("formatting %q dropped or rewrote the name %q; got:\n%s", tt.src, name, got)
				}
			}
		})
	}
}

// TestFormattingANonASCIIProgramIsIdempotent is the property `mutant fmt`
// actually has to hold: running it twice changes nothing the first run did not.
// A name cut mid-rune fails this, because the second run lexes the damaged
// bytes differently again.
func TestFormattingANonASCIIProgramIsIdempotent(t *testing.T) {
	for _, src := range []string{
		"let grün = 1;\nputln(grün);\n",
		"let xà = 7;\nlet xÅ = 8;\n",
		"let вода = 1;\n",
		"// a comment with ü and 🙂\nlet x = 1;\n",
		"let s = \"héllo\";\n",
	} {
		once, _, ok := FormatSource(src)
		if !ok {
			t.Errorf("the formatter refused %q, which parses", src)
			continue
		}
		twice, _, ok := FormatSource(once)
		if !ok {
			t.Errorf("format(%q) = %q, which the formatter then refused", src, once)
			continue
		}
		if once != twice {
			t.Errorf("formatting %q is not idempotent:\n first: %q\nsecond: %q", src, once, twice)
		}
	}
}

// namesIn pulls the identifiers out of a `let NAME =` line without lexing, so
// the expectation does not come from the code under test.
func namesIn(src string) []string {
	var names []string
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "let ")
		if !ok {
			continue
		}
		if name, _, found := strings.Cut(rest, " ="); found {
			names = append(names, name)
		}
	}
	return names
}
