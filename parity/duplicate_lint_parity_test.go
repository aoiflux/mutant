package parity

// What the editor calls a duplicate declaration, held against what the program
// does.
//
// The rule's premise is that one of two declarations of a name is pointless.
// That is a claim about the program, so it is checkable against the program:
// every row below is compiled and run, and the value it produces is the reason
// the lint may or may not speak. A row that returns 6 because both `Point`s did
// work is not a row where one of them is redundant.
//
// It is written this way because the rule used to walk the file with a scope
// chain of its own, and that chain disagreed with the compiler twice: it
// reported a shadow as a duplicate, and it filed type names beside values. Both
// disagreements were silent, and both carried a quick fix -- "Remove duplicate
// top-level declaration" -- whose edit deletes a line of a working program.

import (
	"strings"
	"testing"

	"mutant/lsp/api"
)

// duplicateComplaints returns what the lint says about duplicate declarations,
// and nothing else: a row may legitimately draw an unused-declaration warning.
func duplicateComplaints(src string) []string {
	said := make([]string, 0, 2)
	for _, d := range api.Lint(src) {
		if d.Source == "mutant-lint" && strings.Contains(d.Message, "duplicate") {
			said = append(said, d.Message)
		}
	}
	return said
}

// TestNothingIsADuplicateWhileBothDeclarationsAreLive pins the silence, and
// pins it to a value rather than to an opinion: each program is run, and the
// number it produces is only reachable if both declarations of the name are
// doing something.
func TestNothingIsADuplicateWhileBothDeclarationsAreLive(t *testing.T) {
	for _, c := range []struct{ name, src, want string }{
		{
			// 20 is only 20 because the parameter shadows the top-level x. If
			// the outer x were what `x * 10` read, this would be 10.
			name: "a parameter shadows a top-level let",
			src: `let x = 1;
let f = fn(x) { return x * 10; };
f(2);
`,
			want: "INTEGER(20)",
		},
		{
			// ... and the outer one is still 1 after the function returns,
			// which is what makes it a shadow rather than a second attempt at
			// the same binding.
			name: "the shadowed let survives the scope that shadowed it",
			src: `let x = 1;
let f = fn() { let x = 2; return x; };
f();
x;
`,
			want: "INTEGER(1)",
		},
		{
			// 6 is 5 from the struct and 1 from the value, added in one
			// expression. A type name never enters the compiler's symbol table,
			// so it takes nothing from a value of the same name.
			name: "a struct name and a value of that name are both live",
			src: `struct Point { x };
let Point = 1;
let p = Point{x: 5};
p.x + Point;
`,
			want: "INTEGER(6)",
		},
		{
			name: "an enum name and a value of that name are both live",
			src: `enum Colour { Red, Green };
let Colour = 9;
let c = Colour.Red;
Colour;
`,
			want: "INTEGER(9)",
		},
		{
			// Two loops over one binding name in one scope is how the language
			// is written. The walk this replaced never recorded a loop binding
			// at all, which got the answer right for the wrong reason.
			name: "two loops bind the same name in one scope",
			src: `for (item in [1, 2]) { item; }
for (item in [3, 4]) { item; }
7;
`,
			want: "INTEGER(7)",
		},
		{
			// The discard may be bound as often as the error idiom needs it.
			name: "the discard is bound twice",
			src: `let a, _ = gets();
let b, _ = gets();
7;
`,
			want: "INTEGER(7)",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			value, err := evalViaVM(t, c.src)
			if err != nil {
				t.Fatalf("the program does not run, so it cannot show the "+
					"declarations are live: %v\n\n%s", err, c.src)
			}
			if got := normalize(value); got != c.want {
				t.Fatalf("value = %s, want %s\n\n%s", got, c.want, c.src)
			}
			if said := duplicateComplaints(c.src); len(said) != 0 {
				t.Fatalf("the editor calls a declaration of this running "+
					"program a duplicate: %v\n\n%s", said, c.src)
			}
		})
	}
}

// TestASecondDeclarationInOneScopeIsStillReported is the other direction, and
// the reason the rule exists: these really are two declarations of one binding,
// and the first one never gets read.
//
// The wording is asserted rather than merely the presence of a complaint,
// because the two spellings are not synonyms. Only "duplicate top-level
// declaration" is offered the quick fix that deletes the line, and a line is
// safe to delete only at the top level.
func TestASecondDeclarationInOneScopeIsStillReported(t *testing.T) {
	for _, c := range []struct{ name, src, want string }{
		{
			name: "two top-level lets",
			src: `let x = 1;
let x = 2;
x;
`,
			want: "duplicate top-level declaration `x`",
		},
		{
			name: "two lets in one function body",
			src: `let f = fn() { let a = 1; let a = 2; return a; };
f();
`,
			want: "duplicate declaration `a`",
		},
		{
			name: "two parameters of one function",
			src: `let f = fn(a, a) { return a; };
7;
`,
			want: "duplicate declaration `a`",
		},
		{
			name: "two structs of one name",
			src: `struct P { x };
struct P { y };
7;
`,
			want: "duplicate top-level declaration `P`",
		},
		{
			// A struct written inside a function is not a top-level statement,
			// so it gets the wording that carries no line-deleting quick fix.
			name: "two structs of one name inside a function",
			src: `let f = fn() {
  struct Inner { a };
  struct Inner { b };
  return 7;
};
f();
`,
			want: "duplicate declaration `Inner`",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := evalViaVM(t, c.src); err != nil {
				t.Fatalf("the program does not compile, so the rule is not "+
					"what is being tested: %v\n\n%s", err, c.src)
			}
			said := duplicateComplaints(c.src)
			for _, message := range said {
				if message == c.want {
					return
				}
			}
			t.Fatalf("duplicate complaints = %v, want one reading %q\n\n%s",
				said, c.want, c.src)
		})
	}
}

// TestTheErrorIdiomMayRebindTheValueHalf pins the exception, in both
// directions.
//
// `let text, err = read(path);` binds a pair. Reading the value half and then
// rebinding the name is the idiom, not a mistake -- the first binding was
// consumed. A rebinding with nothing in between is the thing the rule is for,
// and still reported.
func TestTheErrorIdiomMayRebindTheValueHalf(t *testing.T) {
	const consumed = `let abc, err = gets();
abc;
let abc = 1;
abc;
err;
`
	// The idiom's recommended shape, which is the one that used to be reported:
	// the error is checked first, so the value is never read on the line
	// directly below the binding.
	const checkedFirst = `let abc, err = gets();
if (err != null) { puts("bad"); }
abc;
let abc = 1;
abc;
`
	const notConsumed = `let abc, err = gets();
let abc = 1;
abc;
err;
`

	if said := duplicateComplaints(consumed); len(said) != 0 {
		t.Fatalf("rebinding a consumed half of a pair was reported: %v\n\n%s", said, consumed)
	}
	if said := duplicateComplaints(checkedFirst); len(said) != 0 {
		t.Fatalf("checking the error half before using the value half made the "+
			"rebinding a duplicate: %v\n\n%s", said, checkedFirst)
	}
	if said := duplicateComplaints(notConsumed); len(said) == 0 {
		t.Fatalf("a rebinding with no use in between went unreported\n\n%s", notConsumed)
	}

	// The exception is the PAIR, not the use. A plain let read on the next line
	// and then declared again is the thing the rule is for: nothing consumed
	// the first binding, it was simply replaced.
	const plainLet = `let x = 1;
x;
let x = 2;
x;
`
	if said := duplicateComplaints(plainLet); len(said) == 0 {
		t.Fatalf("a plain let declared twice went unreported because it was read "+
			"in between, which is the pair idiom's exception and not its own\n\n%s",
			plainLet)
	}
}
