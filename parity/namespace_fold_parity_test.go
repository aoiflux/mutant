package parity

import (
	"fmt"
	"strings"
	"testing"
)

// `ns.member` is `ns_member`, derived rather than tabulated, so every builtin
// family works the moment a builtin is added to it. The fold is implemented
// three times -- once in the compiler, once in the tree-walking evaluator, once
// in the language server -- and each one asks the same question before folding:
// is this name already taken by something the author bound?
//
// They asked it of three different things.
//
//   - compiler.compileFieldExpression asked c.symbolTable.Resolve, and
//     SymbolTable.DefineBuiltin writes every builtin into the very store that
//     Resolve reads. So for a family whose own name is also a registered
//     builtin, Resolve succeeded, the compiler concluded the name was taken,
//     skipped the fold, and emitted OpGetField against a builtin object. The VM
//     answers "cannot access field on non-struct: BUILTIN".
//   - evaluator.evalFieldExpression asked env.Get, and builtins do not live in
//     the environment. It folded, and the call worked.
//   - the language server asked its own boundAt, which is imports plus visible
//     bindings. It folded too: it offered the member in completion, painted it
//     as a builtin, and gave it a hover card and signature help.
//
// Four names are a registered builtin AND a family prefix -- rand, sort, assert
// and gunzip -- so nine builtins ran under one engine, failed under another,
// and were actively recommended by the editor. A bare builtin is not a binding:
// OpGetField on one has only ever been a run-time error, so there was never a
// program whose meaning the fold could have changed.
//
// These tests are asserted against values, not merely against the two engines
// agreeing. A fold that resolved to the wrong builtin would still agree.

// collidingFamilies is the four prefixes that are themselves builtins, with the
// members the collision made unreachable from the compiler. Listed by hand
// rather than computed, so that a future builtin named after an existing family
// has to be added here deliberately.
var collidingFamilies = []string{
	"rand.int", "rand.bytes",
	"sort.by",
	"assert.eq", "assert.ne", "assert.ok", "assert.err", "assert.contains",
	"gunzip.bytes",
}

// controlFamilies are prefixes that are not themselves builtins. They folded
// correctly before this defect was found and must keep doing so afterwards --
// without them, a fix that broke the fold outright would pass.
var controlFamilies = []string{
	"hash.blake2", "str.upper", "fs.read", "base64.encode",
}

func allFamilies() []string {
	return append(append([]string{}, collidingFamilies...), controlFamilies...)
}

// TestANamespacedBuiltinResolvesWhenTheFamilyNameIsItselfABuiltin is the defect
// itself, reduced to the smallest program that shows it: naming the function
// without calling it. Both engines must hand back the builtin.
func TestANamespacedBuiltinResolvesWhenTheFamilyNameIsItselfABuiltin(t *testing.T) {
	const wantBuiltin = "BUILTIN(builtin function)"

	for _, dotted := range allFamilies() {
		t.Run(dotted, func(t *testing.T) {
			evaluated := normalize(evalViaEvaluator(dotted))
			if evaluated != wantBuiltin {
				t.Fatalf("evaluator answered %s for %q, want %s", evaluated, dotted, wantBuiltin)
			}

			vmObj, vmErr := evalViaVM(t, dotted)
			if vmErr != nil {
				t.Fatalf("VM refused %q: %v (the evaluator resolved it to a builtin)", dotted, vmErr)
			}
			if compiled := normalize(vmObj); compiled != wantBuiltin {
				t.Fatalf("VM answered %s for %q, want %s", compiled, dotted, wantBuiltin)
			}
		})
	}
}

// TestTheTwoSpellingsAreOneFunction pins the property the fold exists to
// provide. It would pass trivially against a correct implementation and fail
// against one that folded to some builtin other than the one the flat name
// names -- which agreeing engines cannot rule out.
func TestTheTwoSpellingsAreOneFunction(t *testing.T) {
	for _, dotted := range allFamilies() {
		flat := strings.Replace(dotted, ".", "_", 1)

		t.Run(dotted, func(t *testing.T) {
			dottedObj, dottedErr := evalViaVM(t, dotted)
			if dottedErr != nil {
				t.Fatalf("VM refused %q: %v", dotted, dottedErr)
			}
			flatObj, flatErr := evalViaVM(t, flat)
			if flatErr != nil {
				t.Fatalf("VM refused %q: %v", flat, flatErr)
			}
			if dottedObj != flatObj {
				t.Fatalf("%q and %q are different objects: the fold resolved to the wrong builtin", dotted, flat)
			}
		})
	}
}

// TestACollidingFamilyCallRunsOnBothEngines is the value half. rand_int's range
// is half-open, so [5, 6) is the one deterministic call it has; rand_bytes is
// asserted through len for the same reason.
//
// The function-scope rows are not redundant. Resolve walks out to the enclosing
// table and returns a BuiltinScope symbol by an earlier return than the
// top-level lookup takes, so a fix that handled only one of the two paths would
// still pass on the other.
func TestACollidingFamilyCallRunsOnBothEngines(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"rand.int(5, 6)", "INTEGER(5)"},
		{"len(rand.bytes(4))", "INTEGER(4)"},
		{"len(rand.bytes(16))", "INTEGER(16)"},

		// The same calls from inside a function body.
		{"let f = fn() { return rand.int(5, 6); }; f()", "INTEGER(5)"},
		{"let f = fn(n) { return len(rand.bytes(n)); }; f(8)", "INTEGER(8)"},

		// One family nested inside another, so the fold has to survive being an
		// argument as well as a callee.
		{"len(str.upper(str.repeat(to_string(rand.int(5, 6)), 3)))", "INTEGER(3)"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			evaluated := normalize(evalViaEvaluator(tt.input))

			vmObj, vmErr := evalViaVM(t, tt.input)
			if vmErr != nil {
				t.Fatalf("VM refused %q: %v (the evaluator gave %s)", tt.input, vmErr, evaluated)
			}
			compiled := normalize(vmObj)

			if evaluated != compiled {
				t.Fatalf("engines disagree on %q: evaluator %s, VM %s", tt.input, evaluated, compiled)
			}
			if evaluated != tt.want {
				t.Fatalf("both engines answered %s for %q, want %s", evaluated, tt.input, tt.want)
			}
		})
	}
}

// TestABindingStillBeatsACollidingFamily is the other half of the rule, and the
// reason the fix narrows the shadow test rather than removing it. A struct in a
// variable called `rand` must still get field access, exactly as one called
// `str` always has.
func TestABindingStillBeatsACollidingFamily(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"global binding named rand", "struct Holder { int }\nlet rand = Holder{int: 7};\nrand.int", "INTEGER(7)"},
		{"global binding named sort", "struct Holder { by }\nlet sort = Holder{by: 9};\nsort.by", "INTEGER(9)"},
		{"global binding named str", "struct Holder { upper }\nlet str = Holder{upper: 1};\nstr.upper", "INTEGER(1)"},

		// A parameter shadows too, and it is a different scope class from a
		// global -- Local rather than Global -- so it is worth its own row.
		{"parameter named rand", "struct Holder { int }\nlet f = fn(rand) { return rand.int; };\nf(Holder{int: 4})", "INTEGER(4)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluated := normalize(evalViaEvaluator(tt.input))

			vmObj, vmErr := evalViaVM(t, tt.input)
			if vmErr != nil {
				t.Fatalf("VM refused %q: %v (the evaluator gave %s)", tt.input, vmErr, evaluated)
			}
			compiled := normalize(vmObj)

			if evaluated != compiled {
				t.Fatalf("engines disagree on %q: evaluator %s, VM %s", tt.input, evaluated, compiled)
			}
			if evaluated != tt.want {
				t.Fatalf("both engines answered %s for %q, want %s", evaluated, tt.input, tt.want)
			}
		})
	}
}

// TestANamespacedBuiltinInsideAMacroMatchesTheSameCallInline covers the path
// nothing covered: no test anywhere exercised the dotted spelling in the
// tree-walking evaluator, and the evaluator is what computes unquote(...) at
// expansion time. A divergence here means a line inside a macro means something
// different from the identical line written inline.
func TestANamespacedBuiltinInsideAMacroMatchesTheSameCallInline(t *testing.T) {
	inputs := []string{
		"rand.int(5, 6)",
		"len(rand.bytes(4))",
		"len(str.upper(\"shout\"))",
		"len(hash.blake2(\"x\"))",
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			direct, directErr := evalViaVM(t, input)
			if directErr != nil {
				t.Fatalf("inline compilation of %q failed: %s", input, directErr)
			}

			viaMacro, macroErr := evalViaVMWithMacros(t, fmt.Sprintf("let m = macro() { quote(unquote(%s)); }; m();", input))
			if macroErr != nil {
				t.Fatalf("macro expansion of %q failed: %s", input, macroErr)
			}

			if normalize(direct) != normalize(viaMacro) {
				t.Fatalf("macro/inline divergence for %q: inline=%s via-macro=%s",
					input, normalize(direct), normalize(viaMacro))
			}
		})
	}
}
