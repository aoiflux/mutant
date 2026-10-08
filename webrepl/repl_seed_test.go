package webrepl

import (
	"strings"
	"testing"
)

// The browser REPL carried the identical defect to the terminal one: a
// constant pool threaded from one Eval to the next, sealed again on every
// line by mutil.EncryptByteCode under a key derived from that line's own
// instruction length. See mutil.ReplSealer and the terminal REPL's copy of
// this test.
//
// The two front ends now share one helper, which is the point of the row:
// they cannot drift.
func TestReplFunctionDefinedOnOneLineRunsOnTheNext(t *testing.T) {
	evalAll := func(t *testing.T, lines ...string) []string {
		t.Helper()
		r := New()
		results := make([]string, 0, len(lines))
		for i, line := range lines {
			out, err := r.Eval(line)
			if err != nil {
				t.Fatalf("line %d (%q): %v", i+1, line, err)
			}
			results = append(results, strings.TrimSpace(out))
		}
		return results
	}

	t.Run("plain helper", func(t *testing.T) {
		got := evalAll(t, "let add = fn(a, b) { a + b };", "add(1, 2);")
		if got[1] != "3" {
			t.Fatalf("add(1, 2) on the next line = %q, want 3", got[1])
		}
	})

	t.Run("closure", func(t *testing.T) {
		got := evalAll(t,
			"let adder = fn(x) { fn(y) { x + y } };",
			"let add5 = adder(5);",
			"add5(3);",
		)
		if got[2] != "8" {
			t.Fatalf("add5(3) three lines on = %q, want 8", got[2])
		}
	})

	t.Run("recursive function", func(t *testing.T) {
		got := evalAll(t,
			"let fact = fn(n) { if (n < 2) { 1 } else { n * fact(n - 1) } };",
			"fact(5);",
		)
		if got[1] != "120" {
			t.Fatalf("fact(5) on the next line = %q, want 120", got[1])
		}
	})

	t.Run("called three lines later", func(t *testing.T) {
		got := evalAll(t,
			"let triple = fn(n) { n * 3 };",
			"let p = 1;",
			"let q = 2;",
			"p + q;",
			"triple(7);",
		)
		if got[4] != "21" {
			t.Fatalf("triple(7) four lines on = %q, want 21", got[4])
		}
	})

	t.Run("called again after three unrelated lines", func(t *testing.T) {
		got := evalAll(t,
			"let double = fn(n) { n * 2 };",
			"double(4);",
			"let a = 10;",
			"let b = 20;",
			"a + b;",
			"double(50);",
		)
		if got[1] != "8" {
			t.Fatalf("double(4) on line 2 = %q, want 8", got[1])
		}
		if got[5] != "100" {
			t.Fatalf("double(50) on line 6 = %q, want 100", got[5])
		}
	})

	t.Run("two functions from different lines", func(t *testing.T) {
		got := evalAll(t,
			"let inc = fn(n) { n + 1 };",
			"inc(1);",
			"let dec = fn(n) { n - 1 };",
			"dec(1);",
			"inc(dec(10));",
		)
		if got[4] != "10" {
			t.Fatalf("inc(dec(10)) = %q, want 10", got[4])
		}
	})

	t.Run("printing from a function defined earlier", func(t *testing.T) {
		got := evalAll(t,
			`let shout = fn(s) { putln(s) };`,
			"let x = 1;",
			`shout("hello");`,
		)
		if !strings.Contains(got[2], "hello") {
			t.Fatalf("shout(\"hello\") printed %q, want it to contain hello", got[2])
		}
	})
}

// Two sessions must not share a sealer's state. Each REPL is its own key
// schedule over its own pool, and a sealer carried between them would try to
// re-key one session's constants with the other's seed.
func TestTwoBrowserSessionsAreIndependent(t *testing.T) {
	first := New()
	second := New()

	if _, err := first.Eval("let add = fn(a, b) { a + b };"); err != nil {
		t.Fatalf("first session line 1: %v", err)
	}
	if _, err := second.Eval("let mul = fn(a, b) { a * b };"); err != nil {
		t.Fatalf("second session line 1: %v", err)
	}

	got, err := first.Eval("add(2, 3);")
	if err != nil {
		t.Fatalf("first session line 2: %v", err)
	}
	if strings.TrimSpace(got) != "5" {
		t.Fatalf("first session add(2, 3) = %q, want 5", got)
	}

	got, err = second.Eval("mul(2, 3);")
	if err != nil {
		t.Fatalf("second session line 2: %v", err)
	}
	if strings.TrimSpace(got) != "6" {
		t.Fatalf("second session mul(2, 3) = %q, want 6", got)
	}
}
