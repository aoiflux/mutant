package builtin

import (
	"testing"

	"mutant/object"
)

func tsNorm(t *testing.T, res object.Object) *object.Hash {
	t.Helper()
	payload, errObj := unwrapPair(t, res)
	if errObj != nil {
		t.Fatalf("timestamp_normalize error: %s", errObj.Inspect())
	}
	return payload.(*object.Hash)
}

func tlInt(t *testing.T, h *object.Hash, key string) int64 {
	t.Helper()
	return h.Pairs[(&object.String{Value: key}).HashKey()].Value.(*object.Integer).Value
}

func tlStr(t *testing.T, h *object.Hash, key string) string {
	t.Helper()
	return h.Pairs[(&object.String{Value: key}).HashKey()].Value.(*object.String).Value
}

func TestTimestampNormalize(t *testing.T) {
	const wantUnix = int64(1700000000) // 2023-11-14T22:13:20Z
	const wantISO = "2023-11-14T22:13:20Z"

	// unix seconds (auto).
	h := tsNorm(t, TimestampNormalize(intObj(wantUnix)))
	if tlInt(t, h, "unix") != wantUnix || tlStr(t, h, "iso") != wantISO {
		t.Fatalf("auto unix: %s", h.Inspect())
	}

	// unix_ms.
	h = tsNorm(t, TimestampNormalize(intObj(wantUnix*1000), stringObj("unix_ms")))
	if tlInt(t, h, "unix") != wantUnix {
		t.Fatalf("unix_ms: %s", h.Inspect())
	}

	// Windows FILETIME (100-ns since 1601).
	filetime := (wantUnix + filetimeEpochDeltaSec) * 10_000_000
	h = tsNorm(t, TimestampNormalize(intObj(filetime), stringObj("filetime")))
	if tlInt(t, h, "unix") != wantUnix {
		t.Fatalf("filetime -> unix = %d, want %d", tlInt(t, h, "unix"), wantUnix)
	}

	// WebKit/Chrome (us since 1601).
	webkit := (wantUnix + filetimeEpochDeltaSec) * 1_000_000
	h = tsNorm(t, TimestampNormalize(intObj(webkit), stringObj("webkit")))
	if tlInt(t, h, "unix") != wantUnix {
		t.Fatalf("webkit -> unix = %d, want %d", tlInt(t, h, "unix"), wantUnix)
	}

	// DOS packed date/time for 2023-11-14 22:13:20.
	dosDate := uint32(43<<9 | 11<<5 | 14) // year(2023-1980), month 11, day 14
	dosTime := uint32(22<<11 | 13<<5 | 10) // hour 22, min 13, sec 20/2
	dosVal := int64(dosDate<<16 | dosTime)
	h = tsNorm(t, TimestampNormalize(intObj(dosVal), stringObj("dos")))
	if tlStr(t, h, "iso") != wantISO {
		t.Fatalf("dos -> iso = %q, want %q", tlStr(t, h, "iso"), wantISO)
	}

	// ISO string round-trips.
	h = tsNorm(t, TimestampNormalize(stringObj(wantISO)))
	if tlInt(t, h, "unix") != wantUnix {
		t.Fatalf("iso string -> unix = %d", tlInt(t, h, "unix"))
	}

	// error paths.
	if _, errObj := unwrapPair(t, TimestampNormalize(stringObj("not a time"))); errObj == nil {
		t.Fatal("bad ISO string should error")
	}
	if _, errObj := unwrapPair(t, TimestampNormalize(intObj(5), stringObj("bogusfmt"))); errObj == nil {
		t.Fatal("unknown format should error")
	}
}

func TestTimelineSortAndMerge(t *testing.T) {
	ev := func(ts int64, name string) object.Object {
		return makeHashObject(map[string]object.Object{"ts": intObj(ts), "name": stringObj(name)})
	}

	unsorted := &object.Array{Elements: []object.Object{ev(30, "c"), ev(10, "a"), ev(20, "b")}}
	sortedObj := TimelineSort(unsorted)
	sorted, ok := sortedObj.(*object.Array)
	if !ok {
		t.Fatalf("timeline_sort payload: %s", sortedObj.Inspect())
	}
	order := ""
	for _, e := range sorted.Elements {
		order += tlStr(t, e.(*object.Hash), "name")
	}
	if order != "abc" {
		t.Fatalf("timeline_sort order = %q, want abc", order)
	}
	// original not mutated.
	if tlStr(t, unsorted.Elements[0].(*object.Hash), "name") != "c" {
		t.Fatal("timeline_sort mutated the input")
	}

	// merge two sources into one ordered supertimeline.
	src1 := &object.Array{Elements: []object.Object{ev(10, "a"), ev(40, "d")}}
	src2 := &object.Array{Elements: []object.Object{ev(20, "b"), ev(30, "c")}}
	mergedObj := TimelineMerge(&object.Array{Elements: []object.Object{src1, src2}})
	merged, ok := mergedObj.(*object.Array)
	if !ok || len(merged.Elements) != 4 {
		t.Fatalf("timeline_merge payload: %s", mergedObj.Inspect())
	}
	morder := ""
	for _, e := range merged.Elements {
		morder += tlStr(t, e.(*object.Hash), "name")
	}
	if morder != "abcd" {
		t.Fatalf("timeline_merge order = %q, want abcd", morder)
	}

	// custom field name.
	byWhen := &object.Array{Elements: []object.Object{
		makeHashObject(map[string]object.Object{"when": intObj(2)}),
		makeHashObject(map[string]object.Object{"when": intObj(1)}),
	}}
	s2 := TimelineSort(byWhen, stringObj("when")).(*object.Array)
	if s2.Elements[0].(*object.Hash).Pairs[(&object.String{Value: "when"}).HashKey()].Value.(*object.Integer).Value != 1 {
		t.Fatal("timeline_sort with custom field failed")
	}

	// error: non-hash event.
	if _, ok := TimelineSort(&object.Array{Elements: []object.Object{stringObj("x")}}).(*object.Error); !ok {
		t.Fatal("timeline_sort of non-hash events should error")
	}
}
