package builtin

import (
	"testing"

	"mutant/object"
)

func TestEncodingRoundTrips(t *testing.T) {
	msg := "mutant \x00\xffbinary"

	roundTrips := []struct {
		name    string
		encode  func() object.Object
		decode  func(string) object.Object // returns MultiValue pair
	}{
		{"base64", func() object.Object { return Base64Encode(stringObj(msg)) }, func(s string) object.Object { return Base64Decode(stringObj(s)) }},
		{"base64url", func() object.Object { return Base64URLEncode(stringObj(msg)) }, func(s string) object.Object { return Base64URLDecode(stringObj(s)) }},
		{"base32", func() object.Object { return Base32Encode(stringObj(msg)) }, func(s string) object.Object { return Base32Decode(stringObj(s)) }},
		{"hex", func() object.Object { return HexEncode(stringObj(msg)) }, func(s string) object.Object { return HexDecode(stringObj(s)) }},
		{"gzip", func() object.Object { return Gzip(stringObj(msg)) }, func(s string) object.Object { return Gunzip(stringObj(s)) }},
		{"zlib", func() object.Object { return ZlibCompress(stringObj(msg)) }, func(s string) object.Object { return ZlibDecompress(stringObj(s)) }},
	}
	for _, rt := range roundTrips {
		t.Run(rt.name, func(t *testing.T) {
			enc := strResult(t, rt.encode())
			dec, errObj := unwrapPair(t, rt.decode(enc))
			if errObj != nil {
				t.Fatalf("%s decode error: %s", rt.name, errObj.Inspect())
			}
			if s, ok := dec.(*object.String); !ok || s.Value != msg {
				t.Fatalf("%s round-trip mismatch: got %q", rt.name, dec.Inspect())
			}
		})
	}

	// url encode/decode.
	enc := strResult(t, URLEncode(stringObj("a b&c=d")))
	dec, errObj := unwrapPair(t, URLDecode(stringObj(enc)))
	if errObj != nil || dec.(*object.String).Value != "a b&c=d" {
		t.Fatalf("url round-trip failed: %v %v", dec, errObj)
	}

	// to_base / from_base.
	if got := strResult(t, ToBase(intObj(255), intObj(16))); got != "ff" {
		t.Fatalf("to_base(255,16) = %q", got)
	}
	v, errObj := unwrapPair(t, FromBase(stringObj("ff"), intObj(16)))
	if errObj != nil || v.(*object.Integer).Value != 255 {
		t.Fatalf("from_base failed: %v %v", v, errObj)
	}

	// decode error paths.
	if _, errObj := unwrapPair(t, HexDecode(stringObj("zz"))); errObj == nil {
		t.Fatal("hex_decode of invalid should error")
	}
}

func TestConvertBuiltins(t *testing.T) {
	i, errObj := unwrapPair(t, ToInt(stringObj("0x1F")))
	if errObj != nil || i.(*object.Integer).Value != 31 {
		t.Fatalf("to_int(0x1F) = %v %v", i, errObj)
	}
	if _, errObj := unwrapPair(t, ToInt(stringObj("nope"))); errObj == nil {
		t.Fatal("to_int of garbage should error")
	}
	f, errObj := unwrapPair(t, ToFloat(stringObj("3.14")))
	if errObj != nil || f.(*object.Float).Value != 3.14 {
		t.Fatalf("to_float = %v %v", f, errObj)
	}
	if got := ToString(intObj(42)); got.(*object.String).Value != "42" {
		t.Fatalf("to_string(42) = %s", got.Inspect())
	}
	b, errObj := unwrapPair(t, ToBool(stringObj("true")))
	if errObj != nil || !b.(*object.Boolean).Value {
		t.Fatalf("to_bool(true) = %v %v", b, errObj)
	}
	if got := TypeOf(&object.Array{}); got.(*object.String).Value != string(object.ARRAY_OBJ) {
		t.Fatalf("type_of array = %s", got.Inspect())
	}
	if !IsNull(&object.Null{}).(*object.Boolean).Value {
		t.Fatal("is_null(null) should be true")
	}
	if IsNull(intObj(0)).(*object.Boolean).Value {
		t.Fatal("is_null(0) should be false")
	}
}

func TestTimeBuiltins(t *testing.T) {
	now := TimeNow()
	h, ok := now.(*object.Hash)
	if !ok {
		t.Fatalf("time_now should be a HASH, got %T", now)
	}
	unixVal := h.Pairs[(&object.String{Value: "unix"}).HashKey()].Value.(*object.Integer).Value
	if unixVal < 1_700_000_000 {
		t.Fatalf("time_now unix implausibly small: %d", unixVal)
	}

	// format then parse round-trips a known timestamp.
	const layout = "2006-01-02 15:04:05"
	formatted := TimeFormat(intObj(1_700_000_000), stringObj(layout)).(*object.String).Value
	parsed, errObj := unwrapPair(t, TimeParse(stringObj(formatted), stringObj(layout)))
	if errObj != nil {
		t.Fatalf("time_parse error: %s", errObj.Inspect())
	}
	if parsed.(*object.Integer).Value != 1_700_000_000 {
		t.Fatalf("time round-trip mismatch: %d", parsed.(*object.Integer).Value)
	}

	if got := TimeDiff(intObj(100), intObj(40)).(*object.Integer).Value; got != 60 {
		t.Fatalf("time_diff = %d", got)
	}
	if got := TimeAdd(intObj(100), intObj(5)).(*object.Integer).Value; got != 105 {
		t.Fatalf("time_add = %d", got)
	}
}
