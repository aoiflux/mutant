package builtin

import (
	"testing"

	"mutant/object"
)

func arr(elems ...object.Object) *object.Array { return &object.Array{Elements: elems} }

func mustArray(t *testing.T, res object.Object) *object.Array {
	t.Helper()
	if e, ok := res.(*object.Error); ok {
		t.Fatalf("unexpected error: %s", e.Message)
	}
	a, ok := res.(*object.Array)
	if !ok {
		t.Fatalf("expected ARRAY, got %T (%s)", res, res.Inspect())
	}
	return a
}

func intSlice(t *testing.T, a *object.Array) []int64 {
	t.Helper()
	out := make([]int64, len(a.Elements))
	for i, el := range a.Elements {
		iv, ok := el.(*object.Integer)
		if !ok {
			t.Fatalf("element %d not INTEGER: %s", i, el.Inspect())
		}
		out[i] = iv.Value
	}
	return out
}

func eqInts(a []int64, b ...int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestCollectionArrayOps(t *testing.T) {
	if got := intSlice(t, mustArray(t, Sort(arr(intObj(3), intObj(1), intObj(2))))); !eqInts(got, 1, 2, 3) {
		t.Fatalf("sort = %v", got)
	}
	if got := intSlice(t, mustArray(t, ReverseArray(arr(intObj(1), intObj(2), intObj(3))))); !eqInts(got, 3, 2, 1) {
		t.Fatalf("reverse = %v", got)
	}
	if !Contains(arr(intObj(1), intObj(2)), intObj(2)).(*object.Boolean).Value {
		t.Fatal("contains should be true")
	}
	if Contains(arr(intObj(1)), intObj(9)).(*object.Boolean).Value {
		t.Fatal("contains should be false")
	}
	if got := IndexOf(arr(stringObj("a"), stringObj("b")), stringObj("b")).(*object.Integer).Value; got != 1 {
		t.Fatalf("index_of = %d", got)
	}
	if got := IndexOf(arr(stringObj("a")), stringObj("z")).(*object.Integer).Value; got != -1 {
		t.Fatalf("index_of absent = %d", got)
	}
	if got := intSlice(t, mustArray(t, Slice(arr(intObj(1), intObj(2), intObj(3), intObj(4)), intObj(1), intObj(3)))); !eqInts(got, 2, 3) {
		t.Fatalf("slice = %v", got)
	}
	if got := intSlice(t, mustArray(t, Concat(arr(intObj(1)), arr(intObj(2), intObj(3))))); !eqInts(got, 1, 2, 3) {
		t.Fatalf("concat = %v", got)
	}
	if got := intSlice(t, mustArray(t, Flatten(arr(arr(intObj(1), intObj(2)), intObj(3))))); !eqInts(got, 1, 2, 3) {
		t.Fatalf("flatten = %v", got)
	}
	if got := intSlice(t, mustArray(t, Unique(arr(intObj(1), intObj(1), intObj(2), intObj(1), intObj(3))))); !eqInts(got, 1, 2, 3) {
		t.Fatalf("unique = %v", got)
	}
	if got := intSlice(t, mustArray(t, Range(intObj(0), intObj(5), intObj(2)))); !eqInts(got, 0, 2, 4) {
		t.Fatalf("range = %v", got)
	}
	if got := intSlice(t, mustArray(t, Range(intObj(3), intObj(0), intObj(-1)))); !eqInts(got, 3, 2, 1) {
		t.Fatalf("range desc = %v", got)
	}
	if _, ok := Range(intObj(0), intObj(5), intObj(0)).(*object.Error); !ok {
		t.Fatal("range step 0 should error")
	}
	zipped := mustArray(t, Zip(arr(intObj(1), intObj(2)), arr(stringObj("a"), stringObj("b"), stringObj("c"))))
	if len(zipped.Elements) != 2 {
		t.Fatalf("zip length = %d", len(zipped.Elements))
	}
	pair0 := zipped.Elements[0].(*object.Array)
	if pair0.Elements[0].(*object.Integer).Value != 1 || pair0.Elements[1].(*object.String).Value != "a" {
		t.Fatalf("zip pair0 = %s", pair0.Inspect())
	}
	if _, ok := Sort(arr(intObj(1), stringObj("x"))).(*object.Error); !ok {
		t.Fatal("sort of mixed types should error")
	}
}

func TestCollectionHashOps(t *testing.T) {
	h := makeHashObject(map[string]object.Object{"a": intObj(1), "b": intObj(2)})

	keys := mustArray(t, Keys(h))
	if len(keys.Elements) != 2 || keys.Elements[0].(*object.String).Value != "a" || keys.Elements[1].(*object.String).Value != "b" {
		t.Fatalf("keys = %s", keys.Inspect())
	}
	vals := mustArray(t, Values(h))
	if len(vals.Elements) != 2 || vals.Elements[0].(*object.Integer).Value != 1 {
		t.Fatalf("values = %s", vals.Inspect())
	}
	if len(mustArray(t, Entries(h)).Elements) != 2 {
		t.Fatal("entries length")
	}
	if !HasKey(h, stringObj("a")).(*object.Boolean).Value {
		t.Fatal("has_key a should be true")
	}
	if HasKey(h, stringObj("z")).(*object.Boolean).Value {
		t.Fatal("has_key z should be false")
	}
	if got := Get(h, stringObj("a"), intObj(-1)).(*object.Integer).Value; got != 1 {
		t.Fatalf("get a = %d", got)
	}
	if got := Get(h, stringObj("z"), intObj(-1)).(*object.Integer).Value; got != -1 {
		t.Fatalf("get default = %d", got)
	}

	// set returns a new hash; original unchanged.
	set := Set(h, stringObj("c"), intObj(3)).(*object.Hash)
	if len(set.Pairs) != 3 {
		t.Fatalf("set size = %d", len(set.Pairs))
	}
	if len(h.Pairs) != 2 {
		t.Fatal("set mutated the original hash")
	}

	merged := Merge(h, makeHashObject(map[string]object.Object{"b": intObj(20), "c": intObj(3)})).(*object.Hash)
	if len(merged.Pairs) != 3 {
		t.Fatalf("merge size = %d", len(merged.Pairs))
	}
	if Get(merged, stringObj("b"), intObj(0)).(*object.Integer).Value != 20 {
		t.Fatal("merge should let b win")
	}

	del := Delete(h, stringObj("a")).(*object.Hash)
	if len(del.Pairs) != 1 || len(h.Pairs) != 2 {
		t.Fatalf("delete wrong: del=%d orig=%d", len(del.Pairs), len(h.Pairs))
	}
	if _, ok := HasKey(del, stringObj("a")).(*object.Boolean); ok {
		if HasKey(del, stringObj("a")).(*object.Boolean).Value {
			t.Fatal("delete did not remove key")
		}
	}
}
