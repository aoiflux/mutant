package builtin

import (
	"strings"
	"testing"
	"unicode/utf8"

	"mutant/object"
)

// resultLimitError returns the message a refusal carried, and fails when the
// builtin produced a value instead. A value here is megabytes wide, so the
// failure reports its type and size rather than Inspect()ing it -- a test log
// is not improved by eight million zeroes.
func resultLimitError(t *testing.T, name string, res object.Object) string {
	t.Helper()
	if s, ok := res.(*object.String); ok {
		t.Fatalf("%s: expected ERROR, got a STRING of %d bytes", name, len(s.Value))
	}
	e, ok := res.(*object.Error)
	if !ok {
		t.Fatalf("%s: expected ERROR, got %T", name, res)
	}
	return e.Message
}

// TestResultLimitRefusesOneByteOver pins the boundary of maxBuiltinResultBytes
// for every builtin whose result size the script picks outright.
//
// Each case asks for one unit more than the limit, not the tebibyte an
// examiner would actually mistype, and that is deliberate. The failure this
// limit exists to prevent is not a fast one: on a build without the cap, the
// tebibyte call does not return an error and does not abort. It takes tens of
// gibibytes of the host's commit charge and stops answering to any ordinary
// kill, which is a test that damages the machine running it. A boundary case
// catches the same regressions -- a cap that drifts, a comparison written the
// wrong way round, a check placed after the allocation -- and costs 32 MiB in
// the worst case if the cap is ever removed.
func TestResultLimitRefusesOneByteOver(t *testing.T) {
	// The pad builtins bound the padding they add, not the width asked for,
	// and the source here is one rune. A width of maxRunes+2 therefore needs
	// maxRunes+1 runes of padding, which is the first width over the line.
	const maxRunes = maxBuiltinResultBytes / utf8.UTFMax

	cases := []struct {
		name    string
		builtin string
		res     object.Object
	}{
		{"str_repeat", "str_repeat", StrRepeat(stringObj("a"), intObj(maxBuiltinResultBytes+1))},
		{"str_repeat by unit", "str_repeat", StrRepeat(stringObj("ab"), intObj(maxBuiltinResultBytes/2+1))},
		{"str_pad_left", "str_pad_left", StrPadLeft(stringObj("7"), intObj(maxRunes+2), stringObj("0"))},
		{"str_pad_right", "str_pad_right", StrPadRight(stringObj("7"), intObj(maxRunes+2), stringObj("0"))},
		{"rand_bytes", "rand_bytes", RandBytes(intObj(maxBuiltinResultBytes + 1))},
		{"random_hex", "random_hex", RandomHex(intObj(maxBuiltinResultBytes/2 + 1))},
		{"nanoid", "nanoid", NanoID(intObj(maxBuiltinResultBytes + 1))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := resultLimitError(t, c.name, c.res)
			if !strings.Contains(msg, "limit on one builtin result") {
				t.Fatalf("%s: the message does not name the limit: %s", c.name, msg)
			}
			if !strings.Contains(msg, c.builtin) {
				t.Fatalf("%s: the message does not name the builtin: %s", c.name, msg)
			}
		})
	}
}

// TestResultLimitRefusesJustUnderTheLine is the other half of the boundary for
// the pad builtins, where the check is on the padding and not on the width.
// maxRunes+1 asks for exactly maxRunes runes of padding and must be allowed,
// so a check written against the width instead of the padding fails here.
func TestResultLimitRefusesJustUnderTheLine(t *testing.T) {
	const maxRunes = maxBuiltinResultBytes / utf8.UTFMax
	got := strResult(t, StrPadRight(stringObj("7"), intObj(maxRunes+1), stringObj("0")))
	if n := utf8.RuneCountInString(got); n != maxRunes+1 {
		t.Fatalf("str_pad_right one under the line: got %d runes, want %d", n, maxRunes+1)
	}
}

// TestResultLimitAllowsTheLimitItself checks the other side of each boundary,
// so the cap cannot be satisfied by refusing everything.
func TestResultLimitAllowsTheLimitItself(t *testing.T) {
	if got := strResult(t, StrRepeat(stringObj("ab"), intObj(maxBuiltinResultBytes/2))); len(got) != maxBuiltinResultBytes {
		t.Fatalf("str_repeat at the limit: got %d bytes, want %d", len(got), maxBuiltinResultBytes)
	}
	padded := strResult(t, StrPadLeft(stringObj("7"), intObj(maxBuiltinResultBytes/utf8.UTFMax), stringObj("0")))
	if n := utf8.RuneCountInString(padded); n != maxBuiltinResultBytes/utf8.UTFMax {
		t.Fatalf("str_pad_left at the limit: got %d runes, want %d", n, maxBuiltinResultBytes/utf8.UTFMax)
	}
	if got := strResult(t, RandBytes(intObj(maxBuiltinResultBytes))); len(got) != maxBuiltinResultBytes {
		t.Fatalf("rand_bytes at the limit: got %d bytes, want %d", len(got), maxBuiltinResultBytes)
	}
	if got := strResult(t, RandomHex(intObj(maxBuiltinResultBytes/2))); len(got) != maxBuiltinResultBytes {
		t.Fatalf("random_hex at the limit: got %d hex characters, want %d", len(got), maxBuiltinResultBytes)
	}
	if got := strResult(t, NanoID(intObj(1024))); len(got) != 1024 {
		t.Fatalf("nanoid: got %d characters, want 1024", len(got))
	}
}

// TestResultLimitKeepsTheFreeCases guards the short-circuit that makes the
// str_repeat check safe. An empty source or a zero count produces nothing at
// any count, and must not be refused -- and must not reach the int conversion
// with a count that would not fit in an int on a 32-bit host.
func TestResultLimitKeepsTheFreeCases(t *testing.T) {
	const huge = 1 << 40
	if got := strResult(t, StrRepeat(stringObj(""), intObj(huge))); got != "" {
		t.Fatalf("str_repeat of an empty string: got %q, want %q", got, "")
	}
	if got := strResult(t, StrRepeat(stringObj("mutant"), intObj(0))); got != "" {
		t.Fatalf("str_repeat zero times: got %q, want %q", got, "")
	}
	if got := strResult(t, StrPadLeft(stringObj("abcd"), intObj(huge*-1), stringObj("0"))); got != "abcd" {
		t.Fatalf("str_pad_left with a negative width: got %q, want %q", got, "abcd")
	}
}
