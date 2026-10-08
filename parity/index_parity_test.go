package parity

// Indexing, in both engines, on the same program.
//
// M26-VM-008 and M26-VM-009 were each a divergence as well as a fault. `xs[-1]`
// was the last element when a program was compiled and null when the same program
// was interpreted; `s[0]` was a character in the VM and "index operator not
// supported: STRING" in the evaluator, which had never indexed a string at all.
// Of the 32 inputs the baseline probe for this change ran, 26 gave two different
// answers.
//
// The tree-walking evaluator is not dead code: it is what computes unquote(...)
// during macro expansion, so a program could get either answer depending on where
// the expression sat.
//
// Every non-ASCII string is built with a Go escape in a double-quoted Go literal,
// so this file stays ASCII and the lexer still receives the real bytes. The mutant
// lexer's own unescape handles only \n \r \t \\ \$ and \", so a mutant program
// cannot write \xc3 itself -- which is also why the strings are assembled here
// rather than inside the source under test.

import (
	"fmt"
	"testing"
)

// hello is "h" + U+00E9 + "llo": six bytes, five runes, the wide rune second.
const hello = "h\xc3\xa9llo"

// badLead is "h" + a lone 0xc3 + "llo": five bytes, five runes once the byte that
// begins no sequence decodes to U+FFFD.
const badLead = "h\xc3llo"

// wide is "a" + U+1D11E (four bytes) + "b": six bytes, three runes.
const wide = "a\xf0\x9d\x84\x9eb"

func TestBothEnginesAgreeOnEveryIndex(t *testing.T) {
	inputs := []string{
		// Arrays, including both boundaries and past both ends.
		"[1, 2, 3][0]",
		"[1, 2, 3][2]",
		"[1, 2, 3][3]",
		"[1, 2, 3][-1]",
		"[1, 2, 3][-3]",
		"[1, 2, 3][-4]",
		"[1, 2][-5]",
		"[][0]",
		"[][-1]",
		"[1, 2, 3][-9223372036854775807 - 1]",
		"[1, 2, 3][9223372036854775807]",

		// Strings. The evaluator answered an error to every one of these.
		`"apple"[0]`,
		`"apple"[4]`,
		`"apple"[5]`,
		`"apple"[-1]`,
		`"apple"[-5]`,
		`"apple"[-6]`,
		`""[0]`,
		`""[-1]`,
		`"apple"[-9223372036854775807 - 1]`,

		// Strings that are not all ASCII, where byte and rune disagree.
		`"` + hello + `"[0]`,
		`"` + hello + `"[1]`,
		`"` + hello + `"[2]`,
		`"` + hello + `"[4]`,
		`"` + hello + `"[5]`,
		`"` + hello + `"[6]`,
		`"` + hello + `"[-1]`,
		`"` + hello + `"[-4]`,
		`"` + hello + `"[-5]`,
		`"` + hello + `"[-6]`,
		`"` + wide + `"[1]`,
		`"` + wide + `"[2]`,
		`"` + wide + `"[3]`,
		`"` + wide + `"[-1]`,
		`"` + wide + `"[-3]`,

		// A string that is not valid UTF-8 at all.
		`"` + badLead + `"[1]`,
		`"` + badLead + `"[-4]`,

		// Buffers, which were already right in both, and are here so a change to
		// the shared rule cannot take that away unnoticed.
		`let b, e = string_to_bytes("ab", "raw"); b[0]`,
		`let b, e = string_to_bytes("ab", "raw"); b[-1]`,
		`let b, e = string_to_bytes("ab", "raw"); b[-3]`,

		// Multi-values. Both engines answered null to a negative index before.
		"let f = fn() { return 10, 20; }; f()[0]",
		"let f = fn() { return 10, 20; }; f()[-1]",
		"let f = fn() { return 10, 20; }; f()[-2]",
		"let f = fn() { return 10, 20; }; f()[-3]",

		// Hashes take no negative rule: a key is a key. An integer key that looks
		// like an index must keep hitting the key.
		"{1: 10, 2: 20}[1]",
		"{-1: 10}[-1]",
		"{-1: 10}[-2]",

		// The index is an expression, so the sign can arrive at runtime rather
		// than in the source. This is what a bound on the literal alone misses.
		"let i = 0 - 1; [1, 2, 3][i]",
		"let i = 0 - 4; [1, 2, 3][i]",
		`let i = 0 - 4; "` + hello + `"[i]`,
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

// TestAStringIndexAgreesWithTheRuneOperations is the reason s[i] is by rune, made
// a test rather than a comment.
//
// str_char_at, str_substr, str_reverse and the for-in iterator all worked in runes
// before this change; object.NewIterator's comment says why ("iterating text by
// byte would hand back half a rune"). s[i] was the one place that worked in bytes,
// and Go's byte-to-rune conversion meant it did not even return the byte: it
// returned the character whose code point is that byte's value.
//
// For every rune of every string here, in both engines, s[i] must equal
// str_char_at(s, i), str_substr(s, i, 1), and the value the for-in loop binds at
// that position.
func TestAStringIndexAgreesWithTheRuneOperations(t *testing.T) {
	for _, s := range []string{
		"apple",
		hello,
		wide,
		badLead,
		"e\xcc\x81",                // a combining accent: two runes
		"\xe6\x97\xa5\xe6\x9c\xac", // 3-byte runes
		"\x80\x80",                 // two bytes that begin no sequence
	} {
		runes := []rune(s)
		for i := range runes {
			// Positive, and the same rune addressed from the other end.
			from := fmt.Sprintf("%d", i)
			back := fmt.Sprintf("0 - %d", len(runes)-i)

			index := `"` + s + `"[` + from + `]`
			indexBack := `"` + s + `"[` + back + `]`
			charAt := `str_char_at("` + s + `", ` + from + `)`
			substr := `str_substr("` + s + `", ` + from + `, 1)`
			forIn := `let o = []; for (c in "` + s + `") { o = push(o, c); } o[` + from + `]`

			for _, engine := range []struct {
				name string
				run  func(string) string
			}{
				{"evaluator", func(src string) string { return normalize(evalViaEvaluator(src)) }},
				{"vm", func(src string) string {
					obj, err := evalViaVM(t, src)
					if err != nil {
						return "ERROR"
					}
					return normalize(obj)
				}},
			} {
				want := engine.run(charAt)
				for _, other := range []struct{ what, src string }{
					{"s[i]", index},
					{"s[i-len]", indexBack},
					{"str_substr(s, i, 1)", substr},
					{"the for-in value at i", forIn},
				} {
					if got := engine.run(other.src); got != want {
						t.Errorf("%s: %s on %q at %d = %s, str_char_at = %s",
							engine.name, other.what, s, i, got, want)
					}
				}
			}
		}
	}
}

// TestLenStillCountsBytes states what this change did NOT do, because the next
// reader will reasonably wonder.
//
// len(s) is the byte length and stays the byte length: it is what every read,
// write and offset in this language is measured in, and it is what len() means
// for a buffer. So len(s) is not the number of indices s has once s is indexed by
// rune -- for an all-ASCII string it is, and for any other it is larger. That gap
// is older than this change: str_char_at and str_substr have always been rune
// based, and the way to walk a string's characters has always been for (c in s).
func TestLenStillCountsBytes(t *testing.T) {
	for _, tt := range []struct {
		src       string
		wantBytes string
	}{
		{`len("apple")`, "INTEGER(5)"},
		{`len("` + hello + `")`, "INTEGER(6)"}, // five runes
		{`len("` + wide + `")`, "INTEGER(6)"},  // three runes
	} {
		evalRes := normalize(evalViaEvaluator(tt.src))
		vmObj, vmErr := evalViaVM(t, tt.src)
		vmRes := normalize(vmObj)
		if vmErr != nil {
			vmRes = "ERROR"
		}
		if evalRes != tt.wantBytes || vmRes != tt.wantBytes {
			t.Errorf("%s: evaluator=%s vm=%s, want %s", tt.src, evalRes, vmRes, tt.wantBytes)
		}
	}
}
