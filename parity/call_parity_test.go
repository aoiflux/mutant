package parity

import "testing"

// M26-VM-003. Calling a value that is not a function has to be refused by both
// engines, because the evaluator computes the body of a macro and the VM runs
// everything else: a call the VM refuses and the evaluator performs would mean
// the same expression means two things depending on where it was written.
//
// The evaluator always refused this ("not a function: INTEGER"). The VM did not
// -- it called vm.stack[0] instead -- so this is the divergence the fix closes,
// and the wording is deliberately not compared: normalize() reduces both to
// ERROR, which is the whole of what parity requires here.
func TestCallingANonFunctionIsRefusedByBothEngines(t *testing.T) {
	inputs := []string{
		`let x = 5; x()`,
		`let s = "hi"; s()`,
		`let a = [1]; a()`,
		`let f = fn() { let x = 5; return x(); }; f()`,
		`let h = {"ntfs": fn() { 1 }}; let g = h["ext4"]; g()`,
		// The shape that used to return a number: the fallback re-invoked the
		// enclosing function, so the VM answered 99 where the evaluator errored.
		`let outer = fn(n) { if (n > 0) { return 99; } let x = 5; return x(1); }; outer(0)`,
	}

	for _, input := range inputs {
		evalRes := normalize(evalViaEvaluator(input))
		vmObj, vmErr := evalViaVM(t, input)
		vmRes := normalize(vmObj)
		if vmErr != nil {
			vmRes = "ERROR"
		}
		if evalRes != "ERROR" {
			t.Errorf("the evaluator did not refuse %q: %s", input, evalRes)
		}
		if evalRes != vmRes {
			t.Errorf("engine divergence for %q: evaluator=%s vm=%s", input, evalRes, vmRes)
		}
	}
}
