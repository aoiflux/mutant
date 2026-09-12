package server

import (
	"strings"
	"testing"
)

// TestFormatterKeepsRawStrings is the whole reason a literal's spelling is
// carried on its token. Re-quoting the decoded value is what the formatter does
// to an ordinary string and exactly what must not happen to a raw one: it would
// double every backslash and undo the spelling the author chose.
func TestFormatterKeepsRawStrings(t *testing.T) {
	for _, src := range []string{
		`let p = r"C:\Users\Public\AppData";`,
		`let p = r"\\?\GLOBALROOT\Device\HarddiskVolume2";`,
		`let re = r"\d{4}-\d{2}-\d{2}";`,
	} {
		got := format(t, src)
		want := src + "\n"
		if got != want {
			t.Errorf("formatted %q as %q, want it unchanged", src, got)
		}
	}
}

func TestFormatterKeepsTripleQuotedBlocks(t *testing.T) {
	src := "let banner = \"\"\"\nalpha\nbeta\n\"\"\";"
	got := format(t, src)
	if !strings.Contains(got, "\"\"\"\nalpha\nbeta\n\"\"\"") {
		t.Errorf("formatted to %q, want the block intact", got)
	}
	if strings.Contains(got, `\n`) {
		t.Errorf("formatted to %q, want no escaped newlines", got)
	}
}

func TestFormatterKeepsInterpolation(t *testing.T) {
	src := `let s = "host=${h} port=${p}";`
	got := format(t, src)
	if !strings.Contains(got, `"host=${h} port=${p}"`) {
		t.Errorf("formatted to %q, want the holes intact", got)
	}
}

// TestFormatterStillCanonicalisesOrdinaryStrings pins the other half: a literal
// with no spelling recorded is re-quoted, which is what normalises its escapes.
func TestFormatterStillCanonicalisesOrdinaryStrings(t *testing.T) {
	if got, want := format(t, `let s =   "a\tb"  ;`), "let s = \"a\\tb\";\n"; got != want {
		t.Errorf("formatted to %q, want %q", got, want)
	}
}

// TestFormattedSourceStillLexesTheSame is the property that matters more than
// any single spelling: formatting twice changes nothing.
func TestFormatterIsIdempotentOverStringForms(t *testing.T) {
	src := "let a = r\"C:\\x\";\nlet b = \"\"\"\nblock ${a}\n\"\"\";\nlet c = \"n=${1 + 2}\";\n"
	once := format(t, src)
	twice := format(t, once)
	if once != twice {
		t.Errorf("second format changed the text:\n%q\n%q", once, twice)
	}
}

// TestFormatterDoesNotCreateAHole is the case the example corpus caught: the
// escaped `\${` decodes to two ordinary characters, and re-quoting a value that
// contains them has to put the escape back. Without that, formatting a string
// that merely mentions ${...} turns it into one that interpolates -- the
// formatter changing what a program means.
func TestFormatterDoesNotCreateAHole(t *testing.T) {
	src := `putln("template \${name} stays text");`
	got := format(t, src)
	if !strings.Contains(got, `\${name}`) {
		t.Fatalf("formatted to %q, want the hole still escaped", got)
	}
	if format(t, got) != got {
		t.Fatalf("formatting again changed %q", got)
	}
}
