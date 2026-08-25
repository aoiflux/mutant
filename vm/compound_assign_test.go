package vm

import "testing"

func TestVMCompoundAssignment(t *testing.T) {
	tests := []vmTestCase{
		{"let i = 5; i += 3; i", 8},
		{"let i = 5; i -= 2; i", 3},
		{"let i = 4; i *= 3; i", 12},
		{"let i = 20; i /= 4; i", 5},
		{"let i = 17; i %= 5; i", 2},
		{"let i = 5; i += 1", 6},
		{"let i = 1; i += 2; i += 3; i", 6},
		// increment / decrement
		{"let i = 0; i++; i", 1},
		{"let i = 0; i++; i++; i++; i", 3},
		{"let i = 10; i--; i", 9},
		// float compound assignment
		{"let x = 1.5; x += 2.0; x", 3.5},
		{"let x = 3.0; x *= 2.0; x", 6.0},
		// string concatenation
		{`let s = "ab"; s += "cd"; s`, "abcd"},
		// compound assignment over an array element (index assignment is a
		// compiled-path capability)
		{"let a = [1, 2, 3]; a[1] += 10; a[1]", 12},
	}

	runVMTests(t, tests)
}
