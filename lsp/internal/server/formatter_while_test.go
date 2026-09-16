package server

import (
	"strings"
	"testing"
)

func TestFormatterPrintsWhileAsWhile(t *testing.T) {
	// The reason WhileStatement is its own node: desugaring to a ForStatement
	// would make the formatter answer `for (; i < 10; )` here, rewriting the
	// author's choice of construct on every save.
	got := format(t, "while(i<10){i=i+1;}")
	if !strings.HasPrefix(strings.TrimSpace(got), "while (i < 10)") {
		t.Errorf("formatted to %q, want it to start `while (i < 10)`", got)
	}
	if strings.Contains(got, "for (") {
		t.Errorf("formatted to %q, want no for loop", got)
	}
}

func TestFormatterIsIdempotentOverWhile(t *testing.T) {
	src := "while (true) {\nlet n = next();\nif (n == 0) {\nbreak;\n}\n}\n"
	once := format(t, src)
	twice := format(t, once)
	if once != twice {
		t.Errorf("second format changed the text:\n%q\n%q", once, twice)
	}
}

// indentUnit is the formatter's own constant, so this test does not have to be
// edited if the indent ever changes.
func TestFormatterKeepsNestedWhileBodies(t *testing.T) {
	got := format(t, "while (a) { while (b) { c(); } }")
	if strings.Count(got, "while (") != 2 {
		t.Errorf("formatted to %q, want both loops kept", got)
	}
	if !strings.Contains(got, indentUnit+indentUnit+"c();") {
		t.Errorf("formatted to %q, want the inner body indented twice", got)
	}
}

// TestFormatterAddsNoSemicolonAfterWhile pins that the statement is treated as
// brace-terminated. A stray `;` would be re-parsed as an empty statement and
// reported as redundant on the next pass -- the formatter creating the warning.
func TestFormatterAddsNoSemicolonAfterWhile(t *testing.T) {
	got := strings.TrimSpace(format(t, "while (a) { b(); }"))
	if strings.HasSuffix(got, ";") {
		t.Errorf("formatted to %q, want no trailing semicolon", got)
	}
}

func TestFormatterPrintsForIn(t *testing.T) {
	cases := []struct{ src, want string }{
		{"for(v in xs){use(v);}", "for (v in xs) {"},
		{"for(i,v in xs){use(v);}", "for (i, v in xs) {"},
		{"for(n in range(0,10)){use(n);}", "for (n in range(0, 10)) {"},
	}
	for _, tc := range cases {
		got := format(t, tc.src)
		if !strings.HasPrefix(strings.TrimSpace(got), tc.want) {
			t.Errorf("formatted %q to %q, want it to start %q", tc.src, got, tc.want)
		}
	}
}

// TestFormatterKeepsTheTwoForLoopsApart is the point of ForInStatement being
// its own node. A shared node would have to guess which header to print.
func TestFormatterKeepsTheTwoForLoopsApart(t *testing.T) {
	if got := format(t, "for (v in xs) { use(v); }"); strings.Contains(got, ";") && !strings.Contains(got, "use(v);") {
		t.Errorf("a for-in printed with a C-style header: %q", got)
	}
	if got := format(t, "for (let i = 0; i < 3; i = i + 1) { use(i); }"); !strings.Contains(got, "; ") {
		t.Errorf("a classic for lost its header: %q", got)
	}
}

func TestFormatterIsIdempotentOverForIn(t *testing.T) {
	src := "for (k, v in h) {\nputln(\"${k}=${v}\");\n}\n"
	once := format(t, src)
	if twice := format(t, once); once != twice {
		t.Errorf("second format changed the text:\n%q\n%q", once, twice)
	}
}
