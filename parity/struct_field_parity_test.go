package parity

import (
	"fmt"
	"strings"
	"testing"

	"mutant/compiler"
	"mutant/evaluator"
	"mutant/global"
	"mutant/lexer"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
	"mutant/security"
	"mutant/vm"
)

// Whether a struct literal is valid, and whether a field read or written is one
// the struct declares, asked of both engines.
//
// It is a parity question because the two engines used to answer it differently
// and one of them answered nothing at all. evalStructLiteral checked none of the
// three things compileStructLiteral checks, so `Undeclared { a: 1 }`,
// `P { a: 1 }` with a field missing and `P { a: 1, c: 3 }` were all values in
// the evaluator and all refused by the compiler. A field no struct declares was
// worse than that: both engines handed back null, so it was not refused
// anywhere.
//
// The evaluator is what computes `unquote(...)` during macro expansion, which is
// why its being laxer than the compiler mattered: a struct literal built there
// is a value that reached the program, not an error anybody saw.
//
// Each row asserts the two engines refuse the same program with the same words.
// Same words is the stronger claim and the one worth pinning -- the compiler
// refuses `p.zzz` before the program runs while the evaluator refuses it as it
// runs, and an author reading the message should not be able to tell which
// stage declined.

// refusalFromVM answers the message whichever stage of the compiled path
// declined, and "" if none did.
//
// evalViaVM cannot serve: it fails the test on a compiler error, and here a
// compiler error is the answer.
func refusalFromVM(t *testing.T, input string) string {
	t.Helper()

	comp := compiler.New()
	if err := comp.Compile(parser.New(lexer.New(input)).ParseProgram()); err != nil {
		return err.Error()
	}

	byteCode := comp.ByteCode()
	password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
	byteCode = mutil.EncryptByteCode(byteCode, password)

	machine := vm.NewWithGlobalStoreAndPassword(byteCode, make([]object.Object, global.GlobalSize), password)
	if err := machine.Run(); err != nil {
		return err.Error()
	}
	if errObj, isError := machine.LastPoppedStackElement().(*object.Error); isError {
		return errObj.Message
	}
	return ""
}

// expansionRefusal answers the message macro expansion declined with, and "" if
// it did not. evalViaVMWithMacros cannot serve: it fails the test on an
// expansion error, and here that error is the answer.
func expansionRefusal(input string) string {
	program := parser.New(lexer.New(input)).ParseProgram()
	macroEnv := object.NewEnvironment()
	evaluator.DefineMacros(program, macroEnv)
	if _, err := evaluator.ExpandMacros(program, macroEnv); err != nil {
		return err.Error()
	}
	return ""
}

func refusalFromEvaluator(input string) string {
	if errObj, isError := evalViaEvaluator(input).(*object.Error); isError {
		return errObj.Message
	}
	return ""
}

func TestBothEnginesRefuseAFieldNoStructDeclares(t *testing.T) {
	for _, tc := range []struct {
		name string
		// input must end in the offending expression, so that whichever engine
		// declines does so over that and not over something after it.
		input string
		// want is every word the refusal has to contain.
		want []string
	}{
		{
			name:  "a read of a field the declaration does not contain",
			input: "struct P { a; b; }; let p = P { a: 1, b: 2 }; p.zzz",
			want:  []string{"P", "zzz", "a, b"},
		},
		{
			name:  "a read through a parameter, which neither engine can type",
			input: "struct P { a; }; let f = fn(rec) { return rec.zzz; }; f(P { a: 1 })",
			want:  []string{"P", "zzz", "a"},
		},
		{
			name:  "a write to a field the declaration does not contain",
			input: "struct P { a; b; }; let p = P { a: 1, b: 2 }; p.zzz = 9",
			want:  []string{"P", "zzz", "a, b"},
		},
		{
			name:  "a literal naming a type nothing declared",
			input: "Undeclared { a: 1 }",
			want:  []string{"undefined struct type", "Undeclared"},
		},
		{
			name:  "a literal missing a declared field",
			input: "struct P { a; b; }; P { a: 1 }",
			want:  []string{"P", "b"},
		},
		{
			name:  "a literal naming a field the declaration does not contain",
			input: "struct P { a; b; }; P { a: 1, c: 3 }",
			want:  []string{"P", "c", "b"},
		},
		{
			name:  "a literal with more fields than the declaration has",
			input: "struct P { a; }; P { a: 1, b: 2, c: 3 }",
			want:  []string{"P", "b, c"},
		},
		{
			name:  "a declaration naming one field twice",
			input: "struct P { a; a; }; P { a: 1 }",
			want:  []string{"struct P declares field a twice"},
		},
		{
			name:  "a literal setting one field twice",
			input: "struct P { a; }; P { a: 1, a: 2 }",
			want:  []string{"struct P sets field a twice"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fromVM := refusalFromVM(t, tc.input)
			fromEvaluator := refusalFromEvaluator(tc.input)

			if fromVM == "" {
				t.Errorf("the compiled path accepted %q", tc.input)
			}
			if fromEvaluator == "" {
				t.Errorf("the evaluator accepted %q", tc.input)
			}
			if fromVM != fromEvaluator {
				t.Errorf("the two engines refuse %q differently:\n  compiled:  %s\n  evaluator: %s",
					tc.input, fromVM, fromEvaluator)
			}
			for _, want := range tc.want {
				if !strings.Contains(fromVM, want) {
					t.Errorf("refusal %q does not mention %q", fromVM, want)
				}
			}
		})
	}
}

// The other direction: a program that is right has to stay right in both
// engines, and answer the same thing.
func TestBothEnginesStillAcceptADeclaredField(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"struct P { a; b; }; let p = P { a: 1, b: 2 }; p.a", "1"},
		{"struct P { a; b; }; let p = P { a: 1, b: 2 }; p.b", "2"},
		{"struct P { a; b; }; let p = P { a: 1, b: 2 }; p.b = 9; p.b", "9"},
		{"struct P { a; b; }; P { b: 2, a: 1 }", "P { a: 1, b: 2 }"},
		{"struct P { a; }; let f = fn(rec) { return rec.a; }; f(P { a: 7 })", "7"},

		// An error's field set is not a struct's: an unknown name there is
		// still null, in both engines, and this row is what keeps the two
		// rules from being quietly merged again.
		{"let v, e = to_int(\"x\"); type_of(e.no_such_field)", "NULL"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if refusal := refusalFromVM(t, tc.input); refusal != "" {
				t.Fatalf("the compiled path refused it: %s", refusal)
			}
			if refusal := refusalFromEvaluator(tc.input); refusal != "" {
				t.Fatalf("the evaluator refused it: %s", refusal)
			}

			fromVM, err := evalViaVM(t, tc.input)
			if err != nil {
				t.Fatalf("vm error: %s", err)
			}
			fromEvaluator := evalViaEvaluator(tc.input)

			if fromVM.Inspect() != tc.want {
				t.Errorf("the compiled path answered %s, want %s", fromVM.Inspect(), tc.want)
			}
			if fromEvaluator.Inspect() != tc.want {
				t.Errorf("the evaluator answered %s, want %s", fromEvaluator.Inspect(), tc.want)
			}
		})
	}
}

// A struct cannot cross an unquote at all, and this is why M26-EVL-019 has no
// demonstrated reach into a .mut program.
//
// A struct literal in a macro body is expanded as AST and compiled, so the
// compiler validates it. One inside `unquote(...)` is evaluated instead, by the
// engine that used to validate nothing -- but convertObjectToASTNode has no
// *object.Struct case, so the struct it produced never had a source form to
// splice back. The laxness was real and unreachable from a program, which is
// what the row says and what this pins.
//
// The message is the assertion. "unquote: STRUCT has no source form" is the
// accurate refusal; "undefined struct type: P" would mean the declaration was
// not visible to the expansion, which is the thing DefineMacros now records.
func TestAStructCannotCrossAnUnquote(t *testing.T) {
	const input = `
	struct P { a; b; };
	let m = macro() { quote(unquote(P { a: 1, b: 2 })) };
	m();
	`
	refusal := expansionRefusal(input)
	if refusal == "" {
		t.Fatal("a struct was spliced back into the program by an unquote")
	}
	if !strings.Contains(refusal, "no source form") {
		t.Errorf("refusal %q is not the no-source-form one; a declared type may have looked undeclared", refusal)
	}
}

// The other half of that: a literal inside an unquote IS validated, and against
// the declaration the program made rather than against nothing. A wrong field
// name is refused before the no-source-form refusal is reached.
func TestAStructLiteralInsideUnquoteIsValidatedAgainstTheDeclaration(t *testing.T) {
	const input = `
	struct P { a; b; };
	let m = macro() { quote(unquote(P { a: 1, c: 3 })) };
	m();
	`
	refusal := expansionRefusal(input)
	if refusal == "" {
		t.Fatal("a struct literal evaluated during macro expansion was not validated")
	}
	if !strings.Contains(refusal, "has no field c") {
		t.Errorf("refusal %q does not name the field c", refusal)
	}
}
