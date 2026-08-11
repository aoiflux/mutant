package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

func TestHashBuiltins(t *testing.T) {
	// Known vectors for "abc".
	checks := map[string]struct {
		got  object.Object
		want string
	}{
		"md5":    {HashMD5(stringObj("abc")), "900150983cd24fb0d6963f7d28e17f72"},
		"sha1":   {HashSHA1(stringObj("abc")), "a9993e364706816aba3e25717850c26c9cd0d89d"},
		"sha256": {HashSHA256(stringObj("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		"crc32":  {HashCRC32(stringObj("abc")), "352441c2"},
	}
	for name, c := range checks {
		t.Run(name, func(t *testing.T) {
			if got := strResult(t, c.got); got != c.want {
				t.Fatalf("%s(abc) = %q, want %q", name, got, c.want)
			}
		})
	}

	// hmac sha256 of message "hi" with key "k" — verify it's stable and hex.
	h1 := strResult(t, HMAC(stringObj("k"), stringObj("hi"), stringObj("sha256")))
	h2 := strResult(t, HMAC(stringObj("k"), stringObj("hi"), stringObj("sha256")))
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("hmac unstable or wrong length: %q vs %q", h1, h2)
	}
	if _, ok := HMAC(stringObj("k"), stringObj("hi"), stringObj("bogus")).(*object.Error); !ok {
		t.Fatal("hmac with bad algo should error")
	}

	// uuid_v4 shape + uniqueness.
	u1 := strResult(t, UUIDv4())
	u2 := strResult(t, UUIDv4())
	if len(u1) != 36 || strings.Count(u1, "-") != 4 || u1 == u2 {
		t.Fatalf("uuid_v4 invalid or not unique: %q %q", u1, u2)
	}
	if len(strResult(t, UUIDv7())) != 36 {
		t.Fatal("uuid_v7 wrong length")
	}

	// random_hex / nanoid lengths.
	if got := strResult(t, RandomHex(intObj(8))); len(got) != 16 {
		t.Fatalf("random_hex(8) len = %d, want 16", len(got))
	}
	if got := strResult(t, NanoID(intObj(21))); len(got) != 21 {
		t.Fatalf("nanoid(21) len = %d, want 21", len(got))
	}
}

func TestMathBuiltins(t *testing.T) {
	mustInt := func(res object.Object) int64 {
		t.Helper()
		i, ok := res.(*object.Integer)
		if !ok {
			t.Fatalf("expected INTEGER, got %T (%s)", res, res.Inspect())
		}
		return i.Value
	}
	mustFloat := func(res object.Object) float64 {
		t.Helper()
		f, ok := res.(*object.Float)
		if !ok {
			t.Fatalf("expected FLOAT, got %T (%s)", res, res.Inspect())
		}
		return f.Value
	}

	if got := mustInt(Abs(intObj(-5))); got != 5 {
		t.Fatalf("abs(-5) = %d", got)
	}
	if got := mustFloat(Abs(floatObj(-2.5))); got != 2.5 {
		t.Fatalf("abs(-2.5) = %v", got)
	}
	if got := mustInt(Min(intObj(3), intObj(1), intObj(2))); got != 1 {
		t.Fatalf("min = %d", got)
	}
	if got := mustInt(Max(intObj(3), intObj(1), intObj(2))); got != 3 {
		t.Fatalf("max = %d", got)
	}
	if got := mustInt(Clamp(intObj(15), intObj(0), intObj(10))); got != 10 {
		t.Fatalf("clamp = %d", got)
	}
	if got := mustFloat(Pow(intObj(2), intObj(10))); got != 1024 {
		t.Fatalf("pow = %v", got)
	}
	if got := mustFloat(Sqrt(intObj(16))); got != 4 {
		t.Fatalf("sqrt = %v", got)
	}
	if got := mustInt(Mod(intObj(10), intObj(3))); got != 1 {
		t.Fatalf("mod = %d", got)
	}
	if _, ok := Mod(intObj(1), intObj(0)).(*object.Error); !ok {
		t.Fatal("mod by zero should error")
	}
	if got := mustInt(Floor(floatObj(3.7))); got != 3 {
		t.Fatalf("floor = %d", got)
	}
	if got := mustInt(Ceil(floatObj(3.2))); got != 4 {
		t.Fatalf("ceil = %d", got)
	}
	if got := mustInt(Round(floatObj(3.5))); got != 4 {
		t.Fatalf("round = %d", got)
	}
	arr := &object.Array{Elements: []object.Object{intObj(1), intObj(2), intObj(3)}}
	if got := mustInt(Sum(arr)); got != 6 {
		t.Fatalf("sum = %d", got)
	}
	if got := mustFloat(Avg(arr)); got != 2 {
		t.Fatalf("avg = %v", got)
	}
	if _, ok := Avg(&object.Array{Elements: nil}).(*object.Error); !ok {
		t.Fatal("avg of empty should error")
	}
	// rand_int within range.
	for i := 0; i < 50; i++ {
		got := mustInt(RandInt(intObj(5), intObj(8)))
		if got < 5 || got >= 8 {
			t.Fatalf("rand_int out of range: %d", got)
		}
	}
	if r := mustFloat(Rand()); r < 0 || r >= 1 {
		t.Fatalf("rand out of range: %v", r)
	}
	if len(RandBytes(intObj(16)).(*object.String).Value) != 16 {
		t.Fatal("rand_bytes wrong length")
	}
	if got := mustFloat(MathPi()); got < 3.14 || got > 3.15 {
		t.Fatalf("math_pi = %v", got)
	}
}
