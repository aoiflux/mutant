package object

import (
	"strings"
	"testing"
)

func buildHash(t *testing.T, keys ...Object) *Hash {
	t.Helper()

	pairs := map[HashKey]HashPair{}
	for i, key := range keys {
		hashable, ok := key.(Hashable)
		if !ok {
			t.Fatalf("%T cannot be a hash key", key)
		}
		pairs[hashable.HashKey()] = HashPair{Key: key, Value: &Integer{Value: int64(i)}}
	}
	return &Hash{Pairs: pairs}
}

// Pairs are stored in a Go map, and ranging a map gives a different order every
// run. Printing straight from that range meant the same program on the same
// input produced different text run to run -- which for output that gets
// diffed, hashed or committed is a defect, not a cosmetic detail.
func TestHashInspectIsStableAcrossRuns(t *testing.T) {
	h := buildHash(t,
		&String{Value: "zeta"}, &String{Value: "alpha"}, &String{Value: "mu"},
		&String{Value: "beta"}, &String{Value: "omega"}, &String{Value: "kappa"},
		&String{Value: "delta"}, &String{Value: "sigma"},
	)

	first := h.Inspect()
	for i := 0; i < 200; i++ {
		if got := h.Inspect(); got != first {
			t.Fatalf("Inspect changed between calls:\n first: %s\n now:   %s", first, got)
		}
	}
}

// Two hashes holding the same pairs must print identically. Built in different
// insertion orders so any dependence on how the map was filled shows up.
func TestEqualHashesPrintIdentically(t *testing.T) {
	forward := buildHash(t, &String{Value: "a"}, &String{Value: "b"}, &String{Value: "c"}, &String{Value: "d"})

	backward := &Hash{Pairs: map[HashKey]HashPair{}}
	for _, p := range forward.Pairs {
		backward.Pairs[p.Key.(Hashable).HashKey()] = p
	}

	if forward.Inspect() != backward.Inspect() {
		t.Fatalf("the same pairs printed two ways:\n %s\n %s", forward.Inspect(), backward.Inspect())
	}
}

// Integer keys sort numerically. A plain string sort would put 10 before 2.
func TestIntegerKeysAreOrderedNumerically(t *testing.T) {
	h := buildHash(t,
		&Integer{Value: 10}, &Integer{Value: 2}, &Integer{Value: 33},
		&Integer{Value: 1}, &Integer{Value: 100}, &Integer{Value: -5},
	)

	got := h.Inspect()
	want := []string{"-5", "1", "2", "10", "33", "100"}

	at := -1
	for _, key := range want {
		next := strings.Index(got, key+":")
		if next < 0 {
			t.Fatalf("key %s missing from %s", key, got)
		}
		if next < at {
			t.Fatalf("integer keys are not in numeric order: %s", got)
		}
		at = next
	}
}

func TestStringKeysAreOrderedAlphabetically(t *testing.T) {
	h := buildHash(t, &String{Value: "delta"}, &String{Value: "alpha"}, &String{Value: "charlie"}, &String{Value: "bravo"})

	if got, want := h.Inspect(), "{alpha: 1, bravo: 3, charlie: 2, delta: 0}"; got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// A hash mixing key types still has to have one definite order.
func TestMixedKeyTypesStillHaveAStableOrder(t *testing.T) {
	h := buildHash(t,
		&String{Value: "b"}, &Integer{Value: 2}, &Boolean{Value: true},
		&String{Value: "a"}, &Integer{Value: 1}, &Boolean{Value: false},
	)

	first := h.Inspect()
	for i := 0; i < 100; i++ {
		if got := h.Inspect(); got != first {
			t.Fatalf("mixed-key hash is not stable:\n first: %s\n now:   %s", first, got)
		}
	}
}

func TestEmptyHashStillPrints(t *testing.T) {
	if got := (&Hash{Pairs: map[HashKey]HashPair{}}).Inspect(); got != "{}" {
		t.Fatalf("empty hash printed as %q, want %q", got, "{}")
	}
}
