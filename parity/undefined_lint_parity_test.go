package parity

// What the editor calls an undefined identifier, held against what the compiler
// accepts.
//
// This rule is reported at error severity: a red squiggle, and a non-zero exit
// from `mutant lint`. That makes both directions expensive, and they are
// expensive differently. A false positive stops a build that would have worked;
// silence on a name the compiler refuses hands the author a clean file and a
// failed build, which is worse, because nothing in the editor points at the
// line.
//
// Silence is what it used to do with a type name. The rule filed struct and
// enum names beside the file's lets, so a bare `Point` looked bound -- and a
// type name never enters the compiler's symbol table, so it is not. The
// positions where a type name IS legal are the literal and the enum value, and
// they are rows here too: fixing the silence must not cost either of them.

import (
	"strings"
	"testing"

	"mutant/compiler"
	"mutant/lexer"
	"mutant/lsp/api"
	"mutant/parser"
)

// compilerRefusesAName reports whether the compiler rejects the program for a
// name it cannot resolve, and returns what it said. Other refusals are not this
// rule's business, so they are not counted as agreement.
func compilerRefusesAName(src string) (string, bool) {
	err := compiler.New().Compile(parser.New(lexer.New(src)).ParseProgram())
	if err == nil {
		return "", false
	}
	message := strings.SplitN(err.Error(), "\n", 2)[0]
	return message, strings.Contains(message, "undefined")
}

func undefinedComplaints(src string) []string {
	said := make([]string, 0, 2)
	for _, d := range api.Lint(src) {
		if d.Source == "mutant-lint" && strings.Contains(d.Message, "undefined identifier") {
			said = append(said, d.Message)
		}
	}
	return said
}

// TestTheUndefinedRuleAgreesWithTheBuildAboutTypeNames drives every position a
// struct or enum name can be written in, and decides each row by compiling it
// rather than by asserting what the rule ought to say.
func TestTheUndefinedRuleAgreesWithTheBuildAboutTypeNames(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{
			// The silence this rule used to keep. A type name is not a value.
			name: "a bare struct name",
			src: `struct Point { x };
Point;
`,
		},
		{
			name: "a bare enum name",
			src: `enum Colour { Red };
Colour;
`,
		},
		{
			name: "a struct name passed as an argument",
			src: `struct Point { x };
let f = fn(p) { return p; };
f(Point);
`,
		},
		{
			// ... and the positions where the name is right, which is what
			// makes this more than deleting two lines.
			name: "a struct literal",
			src: `struct Point { x };
Point{x: 1};
`,
		},
		{
			name: "an enum value",
			src: `enum Colour { Red, Green };
let c = Colour.Red;
c;
`,
		},
		{
			name: "an enum in a match pattern",
			src: `enum Status { Ok, Bad };
let s = Status.Ok;
match s { Status.Ok => 1, Status.Bad => 2 };
`,
		},
		{
			// A name that declares no type is still a name: `Nope{x: 1}` is
			// refused by the build as surely as a bare `Nope` is.
			name: "a literal of an undeclared struct",
			src: `Nope{x: 1};
`,
		},
		{
			// The fold, which was already right and must stay right: `str` is
			// not a variable and reporting it would be a hard error on a
			// correct program.
			name: "a folded builtin family",
			src: `str.upper("a");
`,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			refusal, refused := compilerRefusesAName(c.src)
			said := undefinedComplaints(c.src)

			switch {
			case refused && len(said) == 0:
				t.Fatalf("the build refuses this program -- %s -- and the editor "+
					"reports nothing, so the file looks clean and will not "+
					"compile\n\n%s", refusal, c.src)
			case !refused && len(said) != 0:
				t.Fatalf("the editor reports %v on a program the compiler "+
					"accepts\n\n%s", said, c.src)
			}
		})
	}
}
