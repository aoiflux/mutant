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
	"fmt"
	"strings"
	"testing"

	"mutant/compiler"
	"mutant/global"
	"mutant/lexer"
	"mutant/lsp/api"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
	"mutant/security"
	"mutant/vm"
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
		// "undefined" rather than "undefined identifier": a struct literal
		// naming no type is reported in the compiler's words, `undefined
		// struct type`, because `len{x: 1}` is not a claim about the
		// identifier `len`, which exists.
		if d.Source == "mutant-lint" && strings.Contains(d.Message, "undefined") {
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
		{
			// A literal whose name is a builtin. The rule used to ask the
			// builtin registry to excuse a TYPE name, and `len` is in it, so a
			// program the build refuses drew nothing.
			name: "a literal named after a builtin",
			src: `len{x: 1};
`,
		},
		{
			// The same mistake against the other table: the name is bound, to
			// a value, and a struct literal does not want a value.
			name: "a literal named after a let",
			src: `let Nope = 1;
Nope{x: 1};
`,
		},
		{
			// An enum used before it is declared. The rule used to ask whether
			// the FILE declares one, which it does, three lines down; the
			// compiler asks whether it has been declared YET, which it has
			// not. The graph binds names as the walk reaches them, so it
			// answers the compiler's question.
			name: "an enum used above its declaration",
			src: `Colour.Red;
enum Colour { Red };
`,
		},
		{
			// ... and the same program in the order that works, so the fix is
			// not "report every enum value".
			name: "an enum used below its declaration",
			src: `enum Colour { Red };
Colour.Red;
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

// TestTheRuleIsSilentAboutFieldsOfThingsThatExist covers the receivers the rule
// deliberately says nothing about.
//
// All three of these COMPILE and all three fail at run time with "cannot access
// field on non-struct". That is not this rule's complaint to make: the receiver
// exists, which is the only question it asks, and a rule that reported them
// would be reporting a type error it has no way to be right about.
//
// The exception is a builtin FAMILY, `rand.nope`, where the receiver is not a
// value the author meant to reach into -- it is half of a name, and the other
// half is misspelled. That row is here too, with what the program does, because
// a rule that reports what the compiler accepts has to justify itself.
func TestTheRuleIsSilentAboutFieldsOfThingsThatExist(t *testing.T) {
	for _, c := range []struct {
		name, src string
		report    bool
	}{
		{
			name: "a field of a builtin that heads no family",
			src: `len.foo;
`,
		},
		{
			name: "a family head shadowed by a let",
			src: `let str = "x";
str.upper;
`,
		},
		{
			name: "a family head with no such member",
			src: `rand.nope(1);
`,
			report: true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if refusal, refused := compilerRefusesAName(c.src); refused {
				t.Fatalf("this row is about programs the build accepts, and the "+
					"build refused this one: %s\n\n%s", refusal, c.src)
			}
			if failure := runFails(t, c.src); failure == "" {
				t.Fatalf("this row is about programs that fail at run time, and "+
					"this one ran\n\n%s", c.src)
			}

			said := undefinedComplaints(c.src)
			if c.report && len(said) == 0 {
				t.Fatalf("the misspelled half of a builtin name drew nothing\n\n%s", c.src)
			}
			if !c.report && len(said) != 0 {
				t.Fatalf("the editor reports %v on a field access it cannot be "+
					"right about\n\n%s", said, c.src)
			}
		})
	}
}

// runFails compiles and runs the program on the production VM path and returns
// what went wrong, or "" if it produced a value.
func runFails(t *testing.T, src string) string {
	t.Helper()
	comp := compiler.New()
	if err := comp.Compile(parser.New(lexer.New(src)).ParseProgram()); err != nil {
		return "compile: " + err.Error()
	}
	byteCode := comp.ByteCode()
	password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
	byteCode = mutil.EncryptByteCode(byteCode, password)
	machine := vm.NewWithGlobalStoreAndPassword(byteCode, make([]object.Object, global.GlobalSize), password)
	if err := machine.Run(); err != nil {
		return "run: " + err.Error()
	}
	return ""
}

// TestTheNamesTheLanguageTreatsSpeciallyAreDecidedByTheBuild covers the three
// names that are not ordinary identifiers: the discard, and the two macro
// special forms.
//
// All three used to be excused by name, wherever they appeared, and the build
// excuses none of them in every position. A special form is a CALL the
// evaluator gives meaning to; the word on its own is a variable nobody
// declared. The discard is a binding, and a binding is not a value.
func TestTheNamesTheLanguageTreatsSpeciallyAreDecidedByTheBuild(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{
			name: "a discard in value position",
			src: `_;
`,
		},
		{
			name: "a discard passed as an argument",
			src: `len(_);
`,
		},
		{
			name: "a discard bound by a loop",
			src: `for (_ in [1]) { _; }
`,
		},
		{
			name: "a discard bound by a let",
			src: `let _ = 1;
_;
`,
		},
		{
			name: "a macro special form in call position",
			src: `let unless = macro(c, a) { quote(if (unquote(c)) { unquote(a); }); };
unless(true, 1);
`,
		},
		{
			name: "a macro special form on its own",
			src: `quote;
`,
		},
		{
			name: "the other macro special form on its own",
			src: `unquote;
`,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			refusal, refused := compilerRefusesAName(c.src)
			said := undefinedComplaints(c.src)

			switch {
			case refused && len(said) == 0:
				t.Fatalf("the build refuses this program -- %s -- and the editor "+
					"reports nothing\n\n%s", refusal, c.src)
			case !refused && len(said) != 0:
				t.Fatalf("the editor reports %v on a program the compiler "+
					"accepts\n\n%s", said, c.src)
			}
		})
	}
}
