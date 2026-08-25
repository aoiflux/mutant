package server

import (
	"sort"
	"strings"
	"testing"

	mast "mutant/ast"
	"mutant/lexer"
	"mutant/parser"
)

// The formatter prints a string literal from its DECODED value, so it has to
// re-escape everything the lexer decoded. It used to handle only \\ and \", which
// meant formatting a file rewrote "HTTP/1.1 200 OK\r\n" as a literal carrying raw
// CR and LF bytes.
//
// The value survived that, so a runtime test would not have caught it. The damage
// is downstream: a carriage return in source is invisible, and anything that
// normalises line endings -- git's autocrlf, an editor, a CI checkout -- silently
// turns it into a bare newline and changes what the program writes to a socket.
// Every network example in the repo is written with \r\n for exactly that reason.

// stringLiteralValues returns the decoded value of every string literal in src,
// in source order, so a round-trip can be compared on values rather than text.
func stringLiteralValues(t *testing.T, src string) []string {
	t.Helper()

	p := parser.New(lexer.New(src))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("source did not parse: %s", errs[0])
	}

	// The parser's positions side-table holds every node it built, which is
	// enough to collect the literals without a bespoke AST walk.
	type literal struct {
		offset int
		value  string
	}
	var found []literal
	for node, rng := range program.NodePositions {
		lit, ok := node.(*mast.StringLiteral)
		if !ok || !rng.IsValid() {
			continue
		}
		found = append(found, literal{offset: rng.Start.Offset, value: lit.Value})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].offset < found[j].offset })

	values := make([]string, 0, len(found))
	for _, f := range found {
		values = append(values, f.value)
	}
	return values
}

func TestFormatterKeepsStringEscapesEscaped(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // the escape that must survive
		raw  string // the decoded byte that must NOT appear inside the literal
	}{
		{"crlf", `let a = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";`, `\r\n`, "\r"},
		{"newline", `let a = "line one\nline two";`, `\n`, "one\n"},
		{"tab", `let a = "col\tcol";`, `\t`, "\t"},
		{"nul", `let a = "field\0field";`, `\0`, "\x00"},
		{"quote", `let a = "she said \"hi\"";`, `\"`, `said "`},
		{"backslash", `let a = "C:\\Windows";`, `\\`, `C:\W`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := format(t, tc.src)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("formatting dropped the %s escape.\nsource:    %s\nformatted: %q", tc.name, tc.src, got)
			}
			if strings.Contains(got, tc.raw) {
				t.Fatalf("formatting left the decoded byte in place of the escape: %q", got)
			}
		})
	}
}

// The real guarantee: formatting must not change what the program means.
func TestFormattingPreservesStringValues(t *testing.T) {
	src := `let head = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
let path = "C:\\Windows\\System32";
let quoted = "she said \"hi\"";
let mixed = "a\tb\nc\0d";
let unicode = "héllo — wörld";
putln(head, path, quoted, mixed, unicode);
`

	before := stringLiteralValues(t, src)
	if len(before) < 5 {
		t.Fatalf("expected at least 5 string literals, found %d", len(before))
	}

	after := stringLiteralValues(t, format(t, src))
	if len(after) != len(before) {
		t.Fatalf("formatting changed the number of string literals: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("formatting changed string literal %d:\nbefore %q\nafter  %q", i, before[i], after[i])
		}
	}
}

// Formatting an already-formatted file must be a no-op, or `fmt --check` in CI
// disagrees with `fmt` on the same file forever.
func TestFormattingEscapesIsIdempotent(t *testing.T) {
	src := `let head = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
let mixed = "a\tb\nc\0d\\e\"f";
putln(head, mixed);
`

	once := format(t, src)
	twice := format(t, once)
	if once != twice {
		t.Fatalf("formatting is not idempotent over escapes:\nfirst  %q\nsecond %q", once, twice)
	}
}
