package builtin

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"mutant/object"
)

// A document's shape is measured from its bytes before the TOML and MessagePack
// libraries see it, because both recurse without a bound and MessagePack's
// allocates by what a header declares. These tests ask for each refusal by
// name, so a regression fails the assertion -- and the ones that would crash
// run under a small stack, so a regression costs megabytes, not the host.

// smallStack lowers the stack ceiling for one test. Unbounded recursion then
// dies at 64 MiB instead of the default gigabyte.
func smallStack(t *testing.T) {
	t.Helper()
	old := debug.SetMaxStack(64 << 20)
	t.Cleanup(func() { debug.SetMaxStack(old) })
}

// M26-DAT-004. Two million levels overflowed a 64 MiB stack inside the library
// before convertNative's depth check ever ran; a fatal overflow is not an error
// any recover can catch.
func TestTomlParseRefusesDeepNestingBeforeDecoding(t *testing.T) {
	smallStack(t)
	for _, doc := range []string{
		"a = " + strings.Repeat("[", 2_000_000),
		"a = " + strings.Repeat("{b = ", 2_000_000),
	} {
		errObj := callErr(t, TomlParse, str(doc))
		if !strings.Contains(errObj.Message, "nest more than 256 deep at line 1") {
			t.Errorf("got %q, want the depth refusal", errObj.Message)
		}
	}
}

// The library re-walks a dotted key once per part it adds: 16,000 parts took
// 7.9 s and doubling them quadrupled it. A key or table name of more than 256
// parts names a table deeper than any document may nest, so it is refused at
// once -- and one of exactly 256 still parses, so the limit refuses nothing
// that would have converted.
func TestTomlParseRefusesAKeyOfTooManyParts(t *testing.T) {
	long := strings.Repeat("a.", 15_999) + "a"
	for _, doc := range []string{
		long + " = 1\n",
		"[" + long + "]\nx = 1\n",
		"t = {" + long + " = 1}\n",
	} {
		start := time.Now()
		errObj := callErr(t, TomlParse, str(doc))
		if !strings.Contains(errObj.Message, "more than 256 dotted parts") {
			t.Errorf("got %q, want the key-parts refusal", errObj.Message)
		}
		if took := time.Since(start); took > 2*time.Second {
			t.Errorf("refusing a 16,000-part key took %v", took)
		}
	}

	parts := func(n int) string { return strings.Repeat("a.", n-1) + "a" }
	value := mustCall(t, TomlParse, str(parts(256)+" = 1\n"))
	for i := 0; i < 255; i++ {
		value = hashField(t, value, "a")
	}
	if got := hashInt(t, value, "a"); got != 1 {
		t.Errorf("the 256-part key's value = %d, want 1", got)
	}
	errObj := callErr(t, TomlParse, str(parts(257)+" = 1\n"))
	if !strings.Contains(errObj.Message, "more than 256 dotted parts") {
		t.Errorf("257 parts: got %q", errObj.Message)
	}
}

// The measurement reads strings and comments exactly as the lexer does, so a
// bracket or a dot inside either is not structure: 300 of each, in every kind
// of string, in a comment and in quoted keys, still parse -- with LF and CRLF.
func TestTomlShapeCheckSkipsStringsAndComments(t *testing.T) {
	brackets := strings.Repeat("[", 300) + strings.Repeat("{", 300)
	dots := strings.Repeat(".", 300)
	lines := []string{
		`a = "` + brackets + dots + `"`,
		`b = '` + brackets + dots + `'`,
		`c = """`, brackets + dots, `"""`,
		`d = '''` + brackets + `'''`,
		`e = "\"` + brackets + `"`,
		`f = """x""""`,
		`# ` + brackets + dots,
		`"` + dots + `" = 1`,
		`["x` + dots + `"]`,
		`g = [1, [2, [3]], {h.i = 4}] # ` + brackets,
	}
	for _, newline := range []string{"\n", "\r\n"} {
		value := mustCall(t, TomlParse, str(strings.Join(lines, newline)+newline))
		if got := hashStr(t, value, "a"); got != brackets+dots {
			t.Errorf("a = %d bytes, want the 900 written", len(got))
		}
		if got := hashStr(t, value, "e"); got != `"`+brackets {
			t.Errorf("e lost its escaped quote: %q...", got[:4])
		}
		if got := hashStr(t, value, "f"); got != `x"` {
			t.Errorf(`f = %q, want x" (four quotes: one kept, three closing)`, got)
		}
		if got := hashInt(t, value, dots); got != 1 {
			t.Errorf("the quoted key of dots = %d, want 1", got)
		}
		inner := hashField(t, hashField(t, value, "x"+dots), "g")
		if n := len(mustArray(t, inner).Elements); n != 3 {
			t.Errorf("g has %d elements, want 3", n)
		}
	}
}

// M26-DAT-004, the MessagePack half: two million nested one-element arrays.
func TestMsgpackParseRefusesDeepNestingBeforeDecoding(t *testing.T) {
	smallStack(t)
	doc := append(bytes.Repeat([]byte{0x91}, 2_000_000), 0xc0)
	errObj := callErr(t, MsgpackParse, &object.Bytes{Value: doc})
	if !strings.Contains(errObj.Message, "nests deeper than 256 levels") {
		t.Errorf("got %q, want the depth refusal", errObj.Message)
	}
}

// DecodeInterface made each container's slice or map at the size its header
// declares before reading one element: five bytes declaring 2^32-1 values ask
// for 64 GiB at once. The counts here are ones the host can afford should the
// check ever be lost; the refusal is asked for by name.
func TestMsgpackParseRefusesCountsItsBytesCannotHold(t *testing.T) {
	for _, doc := range [][]byte{
		{0xdc, 0xff, 0xff},             // array16 of 65,535 values, none present
		{0xde, 0xff, 0xff},             // map16 of 65,535 entries
		{0x92, 0xc0, 0xdc, 0xff, 0xff}, // the same one level down
	} {
		errObj := callErr(t, MsgpackParse, &object.Bytes{Value: doc})
		if !strings.Contains(errObj.Message, "declares") || !strings.Contains(errObj.Message, "bytes follow it") {
			t.Errorf("% x: got %q, want the declared-count refusal", doc, errObj.Message)
		}
	}
}

// The library's own map reader read every key as a string -- so {1: "v"} could
// not be read at all -- and kept the last of two copies of a key.
func TestMsgpackParseKeepsKeyTypesAndRefusesARepeat(t *testing.T) {
	value := mustCall(t, MsgpackParse, &object.Bytes{Value: []byte{0x81, 0x01, 0xa1, 'v'}})
	pair, ok := value.(*object.Hash).Pairs[(&object.Integer{Value: 1}).HashKey()]
	if !ok || pair.Value.(*object.String).Value != "v" {
		t.Errorf("{1: \"v\"} came back as %s", value.Inspect())
	}

	for doc, want := range map[string]string{
		"\x82\xa1a\x01\xa1a\x02":     "appears twice",          // {"a": 1, "a": 2}
		"\x82\xc4\x01a\x01\xa1a\x02": "appears twice",          // bin "a" then str "a"
		"\x81\x91\x01\xc0":           "an array, which cannot", // {[1]: nil}
		"\x81\x80\xc0":               "a map, which cannot",    // {{}: nil}
	} {
		errObj := callErr(t, MsgpackParse, &object.Bytes{Value: []byte(doc)})
		if !strings.Contains(errObj.Message, want) {
			t.Errorf("% x: got %q, want %q", doc, errObj.Message, want)
		}
	}
}
