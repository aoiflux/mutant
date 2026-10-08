package repl

import (
	"bytes"
	"strings"
	"testing"
)

// runReplLines drives Start the way a user does, without a terminal.
//
// Start builds its line reader from `in` only when `in` is os.Stdin and `out`
// is os.Stdout; given anything else newInteractiveLineReader returns nil and
// Start falls back to a bufio.Scanner, which is what makes a strings.Reader a
// usable keyboard. Start returns when the scan fails, so EOF ends the session.
func runReplLines(t *testing.T, lines ...string) []string {
	t.Helper()

	var out bytes.Buffer
	Start(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, "test", false, "")

	text := out.String()
	if strings.Contains(text, "unknown opcode") {
		t.Errorf("the VM refused an instruction it could not decode:\n%s", text)
	}

	// Every iteration prints "\n\n" followed by the prompt, so splitting on the
	// prompt separates the banner from one segment per line entered, plus a
	// final empty segment for the prompt printed before EOF.
	segments := strings.Split(text, PROMPT)
	if len(segments) < 2 {
		t.Fatalf("no prompt in REPL output:\n%s", text)
	}

	results := make([]string, 0, len(segments)-1)
	for _, segment := range segments[1:] {
		// The value is the first line of the segment; an easter egg, if one
		// fires, is printed after it.
		results = append(results, strings.TrimSpace(strings.SplitN(segment, "\n", 2)[0]))
	}
	return results
}

// A function defined on one line and called on a later one is the first thing
// anyone does with a REPL, and until M26-TOOL-013 was fixed it could not be
// done in either front end.
//
// Each line of a session is its own program, and mutil.EncryptByteCode seeds
// its keystream from that program's instruction length -- the number the VM
// recovers as len(bc.Instructions) and derives its one decryption key from.
// Because the constant pool carries forward, calling EncryptByteCode once per
// line XORed a function compiled on an earlier line a second time, under the
// new line's key; the VM then decrypted it under that same new key and
// executed the earlier line's ciphertext as opcodes. The session was told the
// program had been built by a newer version of mutant.
//
// The cases below are the shapes where it mattered most: a plain helper, a
// closure (whose captured cells live in a global while its body lives in the
// pool), a recursive function (which calls itself through the same global the
// bug corrupted), and a call several lines after the definition with unrelated
// lines in between -- the last of which is the case a fix that merely skipped
// the constants it had already encrypted would still have got wrong, because
// such a function stays under the key of the line that defined it while the VM
// has moved on to this line's.
//
// Three of these subtests also fail on M26-TOOL-040, the per-line stack sweep
// that emptied the shared constants, which is why both were fixed together.
func TestReplFunctionDefinedOnOneLineRunsOnTheNext(t *testing.T) {
	t.Run("plain helper", func(t *testing.T) {
		got := runReplLines(t,
			"let add = fn(a, b) { a + b };",
			"add(1, 2);",
		)
		if len(got) < 2 || got[1] != "3" {
			t.Fatalf("add(1, 2) on the next line = %q, want 3", got)
		}
	})

	t.Run("closure", func(t *testing.T) {
		got := runReplLines(t,
			"let adder = fn(x) { fn(y) { x + y } };",
			"let add5 = adder(5);",
			"add5(3);",
		)
		if len(got) < 3 || got[2] != "8" {
			t.Fatalf("add5(3) three lines on = %q, want 8", got)
		}
	})

	t.Run("recursive function", func(t *testing.T) {
		got := runReplLines(t,
			"let fact = fn(n) { if (n < 2) { 1 } else { n * fact(n - 1) } };",
			"fact(5);",
		)
		if len(got) < 2 || got[1] != "120" {
			t.Fatalf("fact(5) on the next line = %q, want 120", got)
		}
	})

	t.Run("called three lines later", func(t *testing.T) {
		got := runReplLines(t,
			"let triple = fn(n) { n * 3 };",
			"let p = 1;",
			"let q = 2;",
			"p + q;",
			"triple(7);",
		)
		if len(got) < 5 || got[4] != "21" {
			t.Fatalf("triple(7) four lines on = %q, want 21", got)
		}
	})

	// Not named by the register row, but it follows from the same bug and is
	// the case an index-based fix can still get wrong: the function is used
	// once immediately, which is when a per-line scheme looks correct, and then
	// again after three unrelated lines have each changed the instruction
	// length the key is derived from.
	t.Run("called again after three unrelated lines", func(t *testing.T) {
		got := runReplLines(t,
			"let double = fn(n) { n * 2 };",
			"double(4);",
			"let a = 10;",
			"let b = 20;",
			"a + b;",
			"double(50);",
		)
		if len(got) < 6 {
			t.Fatalf("expected six results, got %q", got)
		}
		if got[1] != "8" {
			t.Fatalf("double(4) on line 2 = %q, want 8", got[1])
		}
		if got[5] != "100" {
			t.Fatalf("double(50) on line 6 = %q, want 100", got[5])
		}
	})

	// A function defined on line one, a second defined on line three, and both
	// called on line five: the pool then holds entries sealed at two different
	// points, and both have to end up under line five's key.
	t.Run("two functions from different lines", func(t *testing.T) {
		got := runReplLines(t,
			"let inc = fn(n) { n + 1 };",
			"inc(1);",
			"let dec = fn(n) { n - 1 };",
			"dec(1);",
			"inc(dec(10));",
		)
		if len(got) < 5 || got[4] != "10" {
			t.Fatalf("inc(dec(10)) = %q, want 10", got)
		}
	})

	// Strings and integers bound on an earlier line were never affected --
	// EncryptObject records the seed it used on the *object.Encrypted it
	// returns and DecryptObject prefers that recorded seed -- but the fix
	// changes the path they travel, so the test says so out loud.
	t.Run("scalars still carry across lines", func(t *testing.T) {
		got := runReplLines(t,
			`let greeting = "hi";`,
			"let n = 41;",
			"n + 1;",
			"greeting;",
		)
		if len(got) < 4 {
			t.Fatalf("expected four results, got %q", got)
		}
		if got[2] != "42" {
			t.Fatalf("n + 1 = %q, want 42", got[2])
		}
		if got[3] != "hi" {
			t.Fatalf("greeting = %q, want hi", got[3])
		}
	})
}

// A line that compiles to no instructions at all seals under seed zero, and a
// line that never reaches the sealer leaves the pool under the seed it was
// already under. Both are easy to get wrong in a scheme that tracks a seed
// across lines, and neither is exotic: an empty line, a comment, a bare
// semicolon and a typo are what a session is mostly made of.
//
// The last two cases are the ones worth stating. A parse error returns before
// the sealer is reached, so the pool must still be readable on the line after
// it. A runtime error reaches the sealer, so the pool is re-keyed and the VM
// then fails for its own reason -- and the next line must still work, which it
// would not if the failing line had left the pool half-re-keyed or if the
// error path still wiped the session.
func TestReplSealingSurvivesLinesThatProduceNoInstructions(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{"empty line between", []string{"let add = fn(a, b) { a + b };", "", "add(1, 2);"}},
		{"whitespace line between", []string{"let add = fn(a, b) { a + b };", "   ", "add(1, 2);"}},
		{"comment line between", []string{"let add = fn(a, b) { a + b };", "// nothing", "add(1, 2);"}},
		{"bare semicolon between", []string{"let add = fn(a, b) { a + b };", ";", "add(1, 2);"}},
		{"two empty lines", []string{"let add = fn(a, b) { a + b };", "", "", "add(1, 2);"}},
		{"empty line first", []string{"", "let add = fn(a, b) { a + b };", "add(1, 2);"}},
		{"parse error between", []string{"let add = fn(a, b) { a + b };", "let = = ;", "add(1, 2);"}},
		{"runtime error between", []string{"let add = fn(a, b) { a + b };", "undefinedthing();", "add(1, 2);"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runReplLines(t, tc.lines...)
			last := ""
			for _, result := range got {
				if result != "" {
					last = result
				}
			}
			if last != "3" {
				t.Fatalf("the session's last value = %q, want 3; results were %q", last, got)
			}
		})
	}
}
