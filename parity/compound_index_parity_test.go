package parity

// A compound assignment evaluates its target's last index exactly once.
//
// `a[next()] += 1` called next() twice in both engines. The compiler rewrote
// `x op= v` into an infix expression over the whole target, so the index was
// compiled once as the store's operand and again inside that rewrite; the
// evaluator read the target back through node.Left and says in its own comment
// that it mirrors the compiler deliberately. Both engines therefore folded the
// element at one index into the slot of another, and agreed about it -- which is
// why a parity harness was not what found it.
//
// next() answers a different index each call, so the defect shows up in the
// array and not only in a call count: `[10, 20, 30]` came back as
// `[21, 20, 30]`, a[1] + 1 written into a[0]. `hist[read_next_byte()] += 1` is
// the shape this was reported from -- a histogram that is wrong and looks right.

import (
	"mutant/ast"
	"mutant/evaluator"
	"mutant/lexer"
	"mutant/object"
	"mutant/parser"
	"testing"
)

// evalViaEvaluatorWithMacros is evalViaVMWithMacros' counterpart: expand macros
// the way generator/generate.go does, then walk the expanded tree.
//
// It exists because the defect below has a form that only an expanded program
// can hold. evalViaVM refuses macro input outright, so before this helper the
// harness could compare the two engines on macro-free source only -- and the
// first attempt at fixing this row was wrong in exactly the gap that left.
func evalViaEvaluatorWithMacros(t *testing.T, input string) object.Object {
	t.Helper()
	program := parser.New(lexer.New(input)).ParseProgram()

	macroEnv := object.NewEnvironment()
	evaluator.DefineMacros(program, macroEnv)
	expandedNode, err := evaluator.ExpandMacros(program, macroEnv)
	if err != nil {
		t.Fatalf("macro expansion failed for %q: %s", input, err)
	}
	expanded, ok := expandedNode.(*ast.Program)
	if !ok {
		t.Fatalf("macro expansion did not yield a program for %q", input)
	}
	return evaluator.Eval(expanded, object.NewEnvironment())
}

// indexCounterPrelude gives the rows an index that answers 0, then 1, then 2.
// A counter rather than a recorder because the wrong answer is a wrong INDEX,
// and a call count alone cannot tell "ran twice" from "ran twice and landed in
// the right place".
const indexCounterPrelude = "let calls = 0;\n" +
	"let next = fn() { calls = calls + 1; return calls - 1; };\n"

func TestCompoundAssignmentEvaluatesItsLastIndexOnce(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			// The reported shape. HEAD answered ARRAY([2, [21, 20, 30]]).
			name:  "an array element through a call",
			input: indexCounterPrelude + "let a = [10, 20, 30];\na[next()] += 1;\n[calls, a];\n",
			want:  "ARRAY([1, [11, 20, 30]])",
		},
		{
			// The index is spilled into one slot per scope, and the
			// right-hand side is the only thing that could overwrite it
			// between the two reads. Here the right-hand side is an
			// assignment that claims the very same slot. Both reads are
			// emitted before it runs, so it cannot reach them -- this row is
			// what says so.
			name: "a nested compound assignment in the right-hand side",
			input: indexCounterPrelude + "let g = 0;\nlet gnext = fn() { g = g + 1; return g - 1; };\n" +
				"let a = [10, 20];\nlet b = [100, 200];\n" +
				"a[next()] += (b[gnext()] += 1);\n[calls, g, a, b];\n",
			want: "ARRAY([1, 1, [111, 20], [101, 200]])",
		},
		{
			// A loop re-enters the same emitted code, so a slot reused across
			// iterations would show here. HEAD could not even run this one:
			// it died with "unsupported types for binary operation: NULL,
			// INTEGER".
			name:  "inside a while loop",
			input: indexCounterPrelude + "let a = [10, 20, 30];\nlet i = 0;\nwhile (i < 2) { a[next()] += 1; i = i + 1; }\n[calls, a];\n",
			want:  "ARRAY([2, [11, 21, 30]])",
		},
		{
			name:  "inside a for loop with a break",
			input: indexCounterPrelude + "let a = [10, 20, 30];\nfor (let i = 0; i < 9; i = i + 1) { if (i > 1) { break; } a[next()] += 1; }\n[calls, a];\n",
			want:  "ARRAY([2, [11, 21, 30]])",
		},
		{
			// Only the LAST index is spilled. Every hop before it is already
			// restricted to a name or a literal, so this row pins that the
			// chain still loads through them unchanged.
			name:  "a chained target",
			input: indexCounterPrelude + "let g = [[10, 20], [30, 40]];\ng[1][next()] += 5;\n[calls, g];\n",
			want:  "ARRAY([1, [[10, 20], [35, 40]]])",
		},
		{
			name:  "a hash key through a call",
			input: indexCounterPrelude + "let h = {0: 10, 1: 20};\nh[next()] += 5;\n[calls, h[0], h[1]];\n",
			want:  "ARRAY([1, 15, 20])",
		},
		{
			// The control. A pure index is compiled exactly as it was before
			// -- no spill, no extra slot, the same instructions -- so this row
			// passes at HEAD too and is here to say the fix did not widen.
			name:  "a pure index is left alone",
			input: indexCounterPrelude + "let a = [10, 20];\na[1] += 5;\n[calls, a];\n",
			want:  "ARRAY([0, [10, 25]])",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evalRes := normalize(evalViaEvaluator(tc.input))
			vmObj, vmErr := evalViaVM(t, tc.input)
			if vmErr != nil {
				t.Fatalf("vm error: %s", vmErr)
			}
			vmRes := normalize(vmObj)
			if evalRes != vmRes {
				t.Errorf("engine divergence: evaluator=%s vm=%s", evalRes, vmRes)
			}
			if vmRes != tc.want {
				t.Errorf("compound assignment = %s, want %s", vmRes, tc.want)
			}
		})
	}
}

// The index is reached by passing the compiler's own slot, never by looking the
// index's AST node up, and these rows are why.
//
// A node pointer is not unique in an expanded program. quote() clones the macro
// TEMPLATE, but a substituted argument is spliced in by pointer:
// evaluator/macro_expansion.go's quoteArgs wraps the caller's node directly and
// the *object.Quote arm of convertObjectToASTNode hands it straight back. So a
// macro naming one parameter at N unquote sites puts ONE node at N places that
// have to compile to different things, and `mutant gen` expands macros
// unconditionally, so this is the production path. examples/modules/lib/stats.mut
// ships the shape.
//
// The first attempt at this row keyed the spilled index on that node and so
// substituted the index's value for the right-hand side: the first case below
// answered ARRAY([1, [10, 20]]) in the VM against ARRAY([2, [11, 20]]) in the
// evaluator, and the second became a hard compile error reading "internal: an
// assignment index spilled in scope 0 is being compiled in scope 1".
func TestCompoundAssignmentWithASharedIndexNode(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			// Expands to `a[next()] += next()`: the index runs once (0), the
			// element a[0]=10 is folded with the right-hand side's next() (1).
			// HEAD answered ARRAY([3, [22, 20]]).
			name: "one parameter as both the index and the right-hand side",
			input: "let bump = macro(arr, ix) { quote(unquote(arr)[unquote(ix)] += unquote(ix)); };\n" +
				indexCounterPrelude + "let a = [10, 20];\nbump(a, next());\n[calls, a];\n",
			want: "ARRAY([2, [11, 20]])",
		},
		{
			// The same sharing, with one use inside a function literal, so the
			// two uses are compiled in different scopes.
			name: "one parameter as the index and inside a function literal",
			input: "let call0 = fn(f) { return f(); };\n" +
				"let bump = macro(arr, ix) { quote(unquote(arr)[unquote(ix)] += call0(fn() { return unquote(ix); })); };\n" +
				indexCounterPrelude + "let a = [10, 20];\nbump(a, next());\n[calls, a];\n",
			want: "ARRAY([2, [11, 20]])",
		},
		{
			// The control, and the shape the repo itself ships: sharing alone
			// is harmless, so this passes at HEAD too. It is here so that a
			// future failure of the two rows above cannot be read as "macro
			// arguments are shared" when it means something narrower.
			name:  "the shipped doubling macro",
			input: "let doubled = macro(value) { quote(unquote(value) + unquote(value)); };\n" + indexCounterPrelude + "doubled(next());\n",
			want:  "INTEGER(1)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evalRes := normalize(evalViaEvaluatorWithMacros(t, tc.input))
			vmObj, vmErr := evalViaVMWithMacros(t, tc.input)
			if vmErr != nil {
				t.Fatalf("vm error: %s", vmErr)
			}
			vmRes := normalize(vmObj)
			if evalRes != vmRes {
				t.Errorf("engine divergence: evaluator=%s vm=%s", evalRes, vmRes)
			}
			if vmRes != tc.want {
				t.Errorf("shared index node = %s, want %s", vmRes, tc.want)
			}
		})
	}
}
