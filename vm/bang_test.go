package vm

// M26-VM-007 in the engine a compiled program runs on.
//
// execBangOperation switched on pointer identity against global.True, global.False
// and global.Null and pushed False for anything else. Those three are the only
// values such a rule can see, so the four falsy values that are not singletons --
// 0, 0.0, "" and an empty buffer -- came back false, which is the same answer as
// !true. Nothing caught it because every `!` test in this package used true, false
// or 5, and 5 is truthy.

import "testing"

// The falsy values that are not singletons, which is the whole of the fault.
func TestBangNegatesTruthinessForEveryFalsyValue(t *testing.T) {
	runVMTests(t, []vmTestCase{
		// What already worked: the three the identity switch could see.
		{"!true", false},
		{"!false", true},
		{"!(if (false) { 5; })", true},

		// What did not. Each of these answered false.
		{"!0", true},
		{"!0.0", true},
		{`!""`, true},
		{`let b, e = string_to_bytes("", "raw"); !b`, true},

		// And their truthy neighbours, which must not move.
		{"!1", false},
		{"!(0 - 1)", false},
		{"!1.5", false},
		{`!"a"`, false},
		{`!"0"`, false},
		{`!" "`, false},
		{`let b, e = string_to_bytes("ab", "raw"); !b`, false},
		{"![]", false},
		{"!{}", false},
	})
}

// `if (x)` and `if (!x)` cannot take the same branch. This is the fault stated as
// the program sees it: for 0 and "", both branches were skipped.
func TestAValueAndItsNegationTakeDifferentBranches(t *testing.T) {
	for _, value := range []string{"0", "0.0", `""`, "1", "1.5", `"a"`, "true", "false", "[]", "{}"} {
		runVMTests(t, []vmTestCase{
			// Exactly one of the two must yield 1.
			{"let a = 0; let b = 0; if (" + value + ") { a = 1; } if (!(" + value + ")) { b = 1; } a + b", 1},
		})
	}
}

// !!x has x's truthiness, so `!!0` is false. It was true.
func TestDoubleBangKeepsTruthiness(t *testing.T) {
	runVMTests(t, []vmTestCase{
		{"!!0", false},
		{"!!0.0", false},
		{`!!""`, false},
		{"!!1", true},
		{`!!"a"`, true},
		{"!!true", true},
		{"!!false", false},
		{"!![]", true},
	})
}

// The identity the old rule depended on did survive storage, which is why this
// change is about the default arm and not about pointers.
//
// A false put into a variable, an array, a hash or a parameter comes back as
// global.False: it survives encryptForStorage on the way onto the stack,
// mutil.EncryptObject on the way into the global store, and decryptForUse on the way
// out. Had it not, `let b = false; !b` would have reached the default arm and
// answered false, and this row would have been a much larger one. The rows are kept
// so that a later change to object storage cannot quietly make it true.
func TestBangIsRightWhereverTheValueCameFrom(t *testing.T) {
	runVMTests(t, []vmTestCase{
		{"let b = false; !b", true},
		{"let b = true; !b", false},
		{"let f = fn() { return false; }; !f()", true},
		{"![false][0]", true},
		{`let h = {"k": false}; !h["k"]`, true},
		{"let f = fn(p) { return !p; }; f(false)", true},
		{"!(2 < 1)", true},
		{"!(1 < 2)", false},

		// The same, for a falsy value that was never a singleton.
		{"let z = 0; !z", true},
		{"let f = fn() { return 0; }; !f()", true},
		{"![0][0]", true},
		{`let s = ""; !s`, true},
	})
}
