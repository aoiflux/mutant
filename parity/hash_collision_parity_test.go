package parity

import "testing"

// M26-EVL-003. Evidence names become hash keys -- file names, registry values,
// account names -- and two names whose FNV-1a-64 digests collide were one key
// in both engines: a count lost one of them, and a verdict table gave one the
// other's verdict. "e38154aa4dee0878" and "c4272bece7a8573e" are such a pair.
// Both engines now keep them apart, in a literal, by assignment, and as buffers.
func TestTwoNamesWithOneDigestAreTwoKeysInBothEngines(t *testing.T) {
	const names = `let a = "e38154aa4dee0878"; let b = "c4272bece7a8573e"; `
	for _, c := range []struct{ input, want string }{
		{names + `let counts = {}; for (n in [a, b]) { counts[n] = 1; } len(counts)`, "INTEGER(2)"},
		{names + `len({a: 1, b: 2})`, "INTEGER(2)"},
		{names + `let seen = {a: "clean.exe"}; seen[b] == "clean.exe"`, "BOOLEAN(false)"},
		{names + `let h = {a: "first"}; h[b] = "second"; h[a]`, `STRING("first")`},
		{names + `let x, e1 = string_to_bytes(a, "raw"); let y, e2 = string_to_bytes(b, "raw"); ` +
			`let h = {}; h[x] = 1; h[y] = 2; len(h)`, "INTEGER(2)"},
	} {
		evalRes := normalize(evalViaEvaluator(c.input))
		vmObj, vmErr := evalViaVM(t, c.input)
		if vmErr != nil {
			t.Fatalf("%s: the VM failed: %v", c.input, vmErr)
		}
		vmRes := normalize(vmObj)
		if evalRes != c.want || vmRes != c.want {
			t.Errorf("%s\n  evaluator=%s vm=%s, want %s", c.input, evalRes, vmRes, c.want)
		}
	}
}
