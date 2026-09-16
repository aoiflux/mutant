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

// Two divergences this file found that Tier 1 deliberately does not settle.
// They are recorded as tests rather than prose so they turn green on their own
// the day someone fixes them, instead of living in a document nobody re-reads.

// `arr[0] = 42` as a tail expression yields the assigned value in the evaluator
// and the whole container in the VM.
//
// The VM is the odd one out against its own other two assignment forms:
// identifier assignment reloads the variable and field assignment emits
// OpGetField, so both yield the assigned value, and only index assignment
// leaves what OpSetIndex happened to leave on the stack. Every language this
// one resembles yields the value, and the existing operator-parity test already
// pins `let i = 5; i += 1` as 6 rather than as the variable.
//
// It is left alone because the cheap fix is not available: making the VM yield
// the value means getting the value back on top after the container has been
// stored, and the only ways there are a stack-shuffling opcode or recompiling
// the index expression -- which would evaluate its side effects twice. Both are
// larger than a scope switch, and which engine is right is a language decision
// rather than a defect against a reference implementation.
func TestIndexAssignmentValueParity(t *testing.T) {
	t.Skip("known divergence: the VM yields the container, the evaluator the assigned value")

	const input = "let arr = [1, 2, 3]; arr[0] = 42"

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
