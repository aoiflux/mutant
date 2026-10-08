package vm

// M26-VM-008 and M26-VM-009 in the engine that had them.
//
// Both faults were in the same two functions and both were reached by an
// ordinary program, with no bad bytecode and nothing out of the compiler's
// hands. What they produced was not an error: an index one past the start took
// the interpreter down an index out of range, and a string index returned a
// character the string did not hold.

import (
	"testing"

	"mutant/global"
	"mutant/security"
)

// TestNegativeIndexPastTheStartIsNull is the row's own acceptance test. Every
// input here reached a Go slice at a negative offset and panicked; the recovered
// panic became "vm_runtime_error: recovered panic: runtime error: index out of
// range [-3]", which names the interpreter's internals for something the program
// did.
//
// The boundary either side of each limit is included, because the interesting
// index is the first one that is not there.
func TestNegativeIndexPastTheStartIsNull(t *testing.T) {
	runVMTests(t, []vmTestCase{
		// Arrays: in range, at the first element, and one past it.
		{"[1, 2, 3][-1]", 3},
		{"[1, 2, 3][-3]", 1},
		{"[1, 2, 3][-4]", global.Null},
		{"[1, 2][-5]", global.Null},
		{"[1][-2]", global.Null},
		{"[][-1]", global.Null},
		{"[][0]", global.Null},

		// Strings, by rune. "apple" is ASCII, so bytes and runes agree and these
		// rows say only what the bound does.
		{`"apple"[-1]`, "e"},
		{`"apple"[-5]`, "a"},
		{`"apple"[-6]`, global.Null},
		{`"ab"[-5]`, global.Null},
		{`""[-1]`, global.Null},
		{`""[0]`, global.Null},

		// Buffers were already bounded; they are here so that a later change to
		// the shared rule cannot quietly take the bound away again.
		{`let b, e = string_to_bytes("ab", "raw"); b[-1]`, 98},
		{`let b, e = string_to_bytes("ab", "raw"); b[-2]`, 97},
		{`let b, e = string_to_bytes("ab", "raw"); b[-3]`, global.Null},
		{`let b, e = string_to_bytes("ab", "raw"); b[-5]`, global.Null},

		// A multi-value is ordered, so it counts from the end like the rest. It
		// answered null to every negative index before 2.6.0.
		{"let f = fn() { return 10, 20; }; f()[-1]", 20},
		{"let f = fn() { return 10, 20; }; f()[-2]", 10},
		{"let f = fn() { return 10, 20; }; f()[-3]", global.Null},
	})
}

// TestTheMostNegativeIndexIsOutOfRangeRatherThanAFault covers the index that
// breaks the arithmetic a bound of this kind is usually written with. The
// previous form, max+i+1 < 0, gave the right answer only because int64 wraps the
// way it does.
//
// The literal is written as an expression because -9223372036854775808 cannot be
// lexed: the magnitude is one past the largest int64 literal, so the negation has
// nothing to apply to.
func TestTheMostNegativeIndexIsOutOfRangeRatherThanAFault(t *testing.T) {
	runVMTests(t, []vmTestCase{
		{"[1, 2, 3][-9223372036854775807 - 1]", global.Null},
		{"[1, 2, 3][-9223372036854775807]", global.Null},
		{"[1, 2, 3][9223372036854775807]", global.Null},
		{`"apple"[-9223372036854775807 - 1]`, global.Null},
		{`"apple"[9223372036854775807]`, global.Null},
		{`let b, e = string_to_bytes("ab", "raw"); b[-9223372036854775807 - 1]`, global.Null},
	})
}

// TestAStringIsIndexedByRune is M26-VM-009.
//
// "h\xc3\xa9llo" is h, e-acute, l, l, o: six bytes and five runes. Indexing it by
// byte did not return a byte -- Go converts a byte to the rune of the same
// number, so s[1] was U+00C3, a character that is in no sense in this string, and
// s[2] was U+00A9. The string also appeared to have six characters when it has
// five.
//
// The strings are built with Go escapes so this file stays ASCII; the lexer is
// handed the real bytes either way, and a test file with literal high bytes in it
// is one encoding conversion away from testing something else.
func TestAStringIsIndexedByRune(t *testing.T) {

	hello := "h\xc3\xa9llo" // h e-acute l l o
	runVMTests(t, []vmTestCase{
		{`"` + hello + `"[0]`, "h"},
		{`"` + hello + `"[1]`, "\xc3\xa9"}, // the rune, not byte 0xc3
		{`"` + hello + `"[2]`, "l"},
		{`"` + hello + `"[3]`, "l"},
		{`"` + hello + `"[4]`, "o"},
		{`"` + hello + `"[5]`, global.Null}, // five runes, so this is past the end
		{`"` + hello + `"[6]`, global.Null}, // it has six bytes; that is not the count

		{`"` + hello + `"[-1]`, "o"},
		{`"` + hello + `"[-4]`, "\xc3\xa9"},
		{`"` + hello + `"[-5]`, "h"},
		{`"` + hello + `"[-6]`, global.Null},
	})
}

// TestABadByteReadsAsTheReplacementRune pins what a string that is not valid
// UTF-8 does, rather than leaving it to the decoder. U+FFFD is what the for-in
// iterator and str_char_at already answer, and parity/index_parity_test.go holds
// s[i] to them.
func TestABadByteReadsAsTheReplacementRune(t *testing.T) {
	bad := "h\xc3llo" // a lead byte with no continuation
	replacement := "\xef\xbf\xbd"
	runVMTests(t, []vmTestCase{
		{`"` + bad + `"[0]`, "h"},
		{`"` + bad + `"[1]`, replacement},
		{`"` + bad + `"[2]`, "l"},
		{`"` + bad + `"[-1]`, "o"},
		{`"` + bad + `"[-4]`, replacement},
		{`"` + bad + `"[-5]`, "h"},
		{`"` + bad + `"[-6]`, global.Null},
	})
}

// TestANegativeIndexIsNotAnIntegrityFailure is the half of M26-VM-008 that is
// not about the value.
//
// containFault records every recovered Go panic as security.RecordIntegrityFailure
// ("vm-panic"), which means "the program running is not the program that was
// compiled". An index is not that. On the CLI the effect was visible in the audit
// chain: audit_head().entries stayed at 1 after a task divided by zero and went
// to 2 after one evaluated xs[-5] -- so an ordinary mistake in a script left a
// tamper record behind in the one log that is supposed to be worth trusting.
//
// This is the inverse of TestAContainedFaultIsRecordedAsAnIntegrityFailure in
// fault_test.go, and the pair is the point: a real fault still counts, and this
// no longer does.
func TestANegativeIndexIsNotAnIntegrityFailure(t *testing.T) {
	for _, input := range []string{
		"[1, 2][-5]",
		`"ab"[-5]`,
		"[][-1]",
		"let f = fn() { return 10, 20; }; f()[-9]",
	} {
		before := security.SecurityTelemetrySnapshot()["integrity_failed"]

		if _, err := runEncryptedVM(input); err != nil {
			t.Fatalf("%s: %v", input, err)
		}

		if after := security.SecurityTelemetrySnapshot()["integrity_failed"]; after != before {
			t.Errorf("%s left an integrity failure behind: integrity_failed %d -> %d",
				input, before, after)
		}
	}
}
