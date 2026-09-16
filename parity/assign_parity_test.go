package parity

import "testing"

// Index assignment was a one-sided feature: the VM compiled `arr[1] = 9` and
// mutated the container, while the evaluator had no *ast.IndexExpression branch
// in evalAssignExpression at all and answered "invalid assignment target" at
// every scope. That is a divergence in the opposite direction from the captured
// -variable defect, and the same probe surfaced both.
//
// It matters beyond the evaluator being incomplete: the evaluator is what
// computes `unquote(...)` during macro expansion, so an index assignment inside
// a macro produced an error where the same line written inline worked. And it
// is the reference implementation the rest of this file measures against, which
// only means something if it can run the programs being compared.
func TestIndexAssignmentParity(t *testing.T) {
	inputs := []string{
		// The measured row, at global scope and inside a function.
		"let arr = [1, 2, 3]; arr[1] = 9; arr",
		"let probe = fn() { let arr = [1, 2, 3]; arr[1] = 9; return arr; }; probe()",
		// Hashes go through the same opcode and the same evaluator branch.
		`let h = {"a": 1}; h["a"] = 2; h`,
		`let h = {"a": 1}; h["b"] = 2; h`,
		// Buffers accept a byte and reject anything that is not one, which is a
		// rule each engine could easily have implemented differently.
		`let b, e = string_to_bytes("abc", "raw"); b[0] = 122; b`,
		`let b, e = string_to_bytes("abc", "raw"); b[0] = 256; b`,
		`let b, e = string_to_bytes("abc", "raw"); b[0] = "z"; b`,
		// Both engines must decline the same out-of-range and mistyped writes.
		"let arr = [1, 2, 3]; arr[5] = 9; arr",
		"let arr = [1, 2, 3]; arr[-1] = 9; arr",
		`let arr = [1, 2, 3]; arr["k"] = 9; arr`,
		// A container that has no index assignment at all.
		`let s = "abc"; s[0] = "z"; s`,
		"let n = 1; n[0] = 2; n",
	}

	for _, input := range inputs {
		evalRes := normalize(evalViaEvaluator(input))
		vmObj, vmErr := evalViaVM(t, input)
		vmRes := normalize(vmObj)
		if vmErr != nil {
			vmRes = "ERROR"
		}
		if evalRes != vmRes {
			t.Errorf("engine divergence for %q: evaluator=%s vm=%s", input, evalRes, vmRes)
		}
	}
}

// The two accumulation shapes that were always correct in both engines, pinned
// so the refusal of the captured-variable shape stays as narrow as it is.
//
// Neither of these captures. At the top level the accumulator is a global, and
// a for loop keeps it in the enclosing frame, so both reach the accumulator
// through a scope the compiler has always written correctly. That is also the
// reason 105 example programs were unaffected by the defect: the corpus reaches
// for a for loop.
func TestNonCapturingAccumulationParity(t *testing.T) {
	inputs := []string{
		"let acc = 0; each([1, 2, 3], fn(x) { acc = acc + x; }); acc",
		"let probe = fn() { let acc = 0; for (let i = 1; i < 4; i = i + 1) { acc = acc + i; } return acc; }; probe()",
		"let acc = 0; for (let i = 1; i < 4; i = i + 1) { acc = acc + i; } acc",
		// A capture that is only read is untouched by any of this.
		"let probe = fn() { let base = 10; let inner = fn(x) { return x + base; }; return inner(1); }; probe()",
	}

	for _, input := range inputs {
		evalRes := normalize(evalViaEvaluator(input))
		vmObj, vmErr := evalViaVM(t, input)
		vmRes := normalize(vmObj)
		if vmErr != nil {
			vmRes = "ERROR"
		}
		if evalRes != vmRes {
			t.Errorf("engine divergence for %q: evaluator=%s vm=%s", input, evalRes, vmRes)
		}
	}
}

// An assignment evaluates to the value assigned.
//
// `arr[0] = 42` used to yield 42 in the evaluator and the whole container in
// the VM, and the VM was the odd one out against its own other forms:
// identifier assignment reloads the variable and field assignment emitted
// OpGetField, so both answered with the value, and only index assignment
// answered with whatever OpSetIndex had left on the stack.
//
// Which engine was right was never really open. Every language where assignment
// is an expression -- C, C++, Java, C#, JavaScript, PHP, Perl, Ruby -- yields
// the assigned value, and none yields the container; the other tradition makes
// assignment a statement with no value at all. Ruby is the closest precedent,
// because `a[0] = 42` there dispatches to a method and Ruby explicitly discards
// that method's return value in favour of the right-hand side, for exactly the
// reason this row exists: so indexed assignment cannot answer differently from
// plain assignment.
//
// The old comment here said the fix was unavailable without a stack-shuffling
// opcode or re-evaluating the index. There is a third way, which is what the
// compiler now does: spill the value to a slot of its own where it was already
// being compiled, and read it back after the stores. Nothing is re-evaluated,
// no opcode was added, and the last index stays free to be a call.
func TestAssignmentYieldsTheValueAssigned(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"let arr = [1, 2, 3]; arr[0] = 42", "INTEGER(42)"},
		{`let h = {"k": 1}; h["k"] = 7`, "INTEGER(7)"},
		{`let h = {"k": 1}; h["new"] = 7`, "INTEGER(7)"},
		{"let n = 0; n = 5", "INTEGER(5)"},
		{"let n = 5; n += 1", "INTEGER(6)"},
		{"struct P { x; }; let p = P { x: 1 }; p.x = 9", "INTEGER(9)"},
		// The shapes the write-back chain added. The value is the one the
		// program wrote, not the container it landed in at any depth.
		{"let g = [[1, 2]]; g[0][1] = 9", "INTEGER(9)"},
		{`let h = {"a": {"b": 1}}; h["a"]["b"] = 2`, "INTEGER(2)"},
		{"let d = [[[1]]]; d[0][0][0] = 5", "INTEGER(5)"},
		{`let c = {"n": [10]}; c["n"][0] += 5`, "INTEGER(15)"},
		{"struct I { v; }; struct O { i; }; let o = O { i: I { v: 1 } }; o.i.v = 42", "INTEGER(42)"},
		// A value that is not a number, in case anything ever reads the
		// container back instead of the value and gets away with it.
		{`let arr = [1]; arr[0] = "z"`, `STRING("z")`},
		{"let arr = [1]; arr[0] = [7]", "ARRAY([7])"},
	}

	for _, testCase := range cases {
		evalRes := normalize(evalViaEvaluator(testCase.input))
		vmObj, vmErr := evalViaVM(t, testCase.input)
		vmRes := normalize(vmObj)
		if vmErr != nil {
			vmRes = "ERROR: " + vmErr.Error()
		}
		if evalRes != vmRes {
			t.Errorf("engine divergence for %q: evaluator=%s vm=%s", testCase.input, evalRes, vmRes)
		}
		if vmRes != testCase.want {
			t.Errorf("%q = %s, want %s", testCase.input, vmRes, testCase.want)
		}
	}
}

// An assignment nested inside another one keeps its own value.
//
// The compiler spills the value being assigned to a slot, and there is one such
// slot per scope, so these are the shapes where the two could collide: an
// assignment in the index of a target, in the value of another assignment, and
// inside the fold of a compound one. They do not collide, because the spill is
// written where the value expression was already being compiled and read with
// nothing of the program's in between -- the inner assignment is always done
// with the slot before the outer writes it. These rows are what says so.
func TestAnAssignmentInsideAnotherKeepsItsOwnValue(t *testing.T) {
	inputs := []string{
		`let q = [0]; let r = [9, 9]; r[q[0] = 1] = 77; [q, r]`,
		`let b = [0]; let a = [0]; let v = (a[0] = (b[0] = 5)); [v, a, b]`,
		`let c = [1]; let d = [0]; let v = (c[0] += (d[0] = 5)); [v, c, d]`,
	}

	for _, input := range inputs {
		evalRes := normalize(evalViaEvaluator(input))
		vmObj, vmErr := evalViaVM(t, input)
		vmRes := normalize(vmObj)
		if vmErr != nil {
			vmRes = "ERROR: " + vmErr.Error()
		}
		if evalRes != vmRes {
			t.Errorf("engine divergence for %q: evaluator=%s vm=%s", input, evalRes, vmRes)
		}
	}

	const input = `let q = [0]; let r = [9, 9]; r[q[0] = 1] = 77; [q, r]`

	evalRes := normalize(evalViaEvaluator(input))
	vmObj, vmErr := evalViaVM(t, input)
	vmRes := normalize(vmObj)
	if vmErr != nil {
		vmRes = "ERROR: " + vmErr.Error()
	}
	if evalRes != vmRes {
		t.Errorf("engine divergence for %q: evaluator=%s vm=%s", input, evalRes, vmRes)
	}
	if want := "ARRAY([[1], [9, 77]])"; vmRes != want {
		t.Errorf("%q = %s, want %s", input, vmRes, want)
	}
}

// Spilling the value must not move it. A program's side effects run in the
// order it wrote them: the container, then the index, then the value.
func TestAssignmentEvaluatesItsPartsInSourceOrder(t *testing.T) {
	const input = `let order = [];
let note = fn(tag, n) { order = push(order, tag); return n; };
let a = [7, 7];
a[note("index", 0)] = note("value", 5);
order`

	evalRes := normalize(evalViaEvaluator(input))
	vmObj, vmErr := evalViaVM(t, input)
	vmRes := normalize(vmObj)
	if vmErr != nil {
		vmRes = "ERROR: " + vmErr.Error()
	}
	if evalRes != vmRes {
		t.Errorf("engine divergence: evaluator=%s vm=%s", evalRes, vmRes)
	}
	if want := "ARRAY([index, value])"; vmRes != want {
		t.Errorf("evaluation order = %s, want %s", vmRes, want)
	}
}

// `grid[0][1] = 9` used to mutate in the evaluator and vanish in the VM.
//
// It was the captured-variable defect wearing different clothes: one storage
// location, two copies of it. The compiler emitted the write-back store only
// when the container expression was a plain identifier, and here it is
// `grid[0]`. In the evaluator that costs nothing, because `grid[0]` is the same
// *object.Array the outer array holds. In the VM it was fatal, because
// OpGetGlobal hands back a decrypted copy -- the element mutated was inside a
// container nothing stored back, and the write disappeared with no error.
//
// The fix is the write-back chain the old comment here said would be needed:
// the compiler now flattens a target to a base variable plus its hops and
// stores every container it passed through back where it came from. Each row
// below is a shape that silently lost its write before that existed.
func TestNestedIndexAssignmentParity(t *testing.T) {
	inputs := []string{
		"let grid = [[1, 2], [3, 4]]; grid[0][1] = 9; grid",
		`let h = {"a": {"b": 1}}; h["a"]["b"] = 2; h`,
		`let rows = [{"n": 1}, {"n": 2}]; rows[0]["n"] = 99; rows`,
		`let deep = {"a": [1, 2]}; deep["a"][0] = 7; deep`,
		"let d3 = [[[1]]]; d3[0][0][0] = 5; d3",
		"let i = 0; let vi = [[1, 2]]; vi[i][i] = 3; vi",
		`let c = {"n": [10]}; c["n"][0] += 5; c`,
		`struct Inner { v; }; let db = {"rows": [Inner { v: 1 }]}; db["rows"][0].v = 7; db["rows"][0].v`,
		"struct Inner { v; }; struct Outer { inner; }; let o = Outer { inner: Inner { v: 1 } }; o.inner.v = 42; o.inner.v",
		`let probe = fn() { let m = {"k": [1, 2]}; m["k"][1] = 99; return m; }; probe()`,
	}

	for _, input := range inputs {
		evalRes := normalize(evalViaEvaluator(input))
		vmObj, vmErr := evalViaVM(t, input)
		vmRes := normalize(vmObj)
		if vmErr != nil {
			vmRes = "ERROR: " + vmErr.Error()
		}
		if evalRes != vmRes {
			t.Errorf("engine divergence for %q: evaluator=%s vm=%s", input, evalRes, vmRes)
		}
	}
}

// A compound assignment reads its target before its right-hand side.
//
// The compiler desugars `x += v` to `x = x <op> v` and compiles that infix
// expression left to right, so the target is read first. The evaluator folds
// the two itself and could pick either order; it used to pick the other one.
//
// Both halves have to have a side effect for the order to be visible at all,
// which is why the target's index is a call here: `a[note("idx")] += note("val")`
// reads the index, reads it again as part of reading the target, and only then
// evaluates the right-hand side.
func TestCompoundAssignmentReadsItsTargetFirst(t *testing.T) {
	const input = `let order = [];
let note = fn(tag, n) { order = push(order, tag); return n; };
let a = [1, 1];
a[note("idx", 0)] += note("val", 5);
[order, a]`

	evalRes := normalize(evalViaEvaluator(input))
	vmObj, vmErr := evalViaVM(t, input)
	vmRes := normalize(vmObj)
	if vmErr != nil {
		vmRes = "ERROR: " + vmErr.Error()
	}
	if evalRes != vmRes {
		t.Errorf("engine divergence: evaluator=%s vm=%s", evalRes, vmRes)
	}
	if want := "ARRAY([[idx, idx, val], [6, 1]])"; vmRes != want {
		t.Errorf("compound assignment = %s, want %s", vmRes, want)
	}
}
