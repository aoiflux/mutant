package builtin

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"mutant/object"

	"google.golang.org/protobuf/encoding/protowire"
)

// Each test here pins a value a decoder used to get wrong without saying so:
// a time moved to another zone, a key turned into text, a year a century off,
// a document read as its first half. Every one fails on the code before its
// fix with exactly the symptom its row describes.

// typedHash builds a hash whose keys keep their types: key, value, key, value.
func typedHash(pairs ...object.Object) *object.Hash {
	h := &object.Hash{Pairs: map[object.HashKey]object.HashPair{}}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Pairs[pairs[i].(object.Hashable).HashKey()] = object.HashPair{Key: pairs[i], Value: pairs[i+1]}
	}
	return h
}

func intVal(n int64) *object.Integer { return &object.Integer{Value: n} }

// --- TOML ---

// M26-DAT-015. A local date-time, date or time names no instant; it came back
// moved by the host's UTC offset and labelled Z, so the same file said a
// different time on every host -- and was wrong even on a UTC one, for the Z.
func TestTomlParseKeepsLocalTimesAsWritten(t *testing.T) {
	value := mustCall(t, TomlParse, str("when = 1979-05-27T07:32:00\nday = 1979-05-27\nat = 07:32:00.5\n"+
		"odt = 1979-05-27T07:32:00-07:00\n"))
	for key, want := range map[string]string{
		"when": "1979-05-27T07:32:00",
		"day":  "1979-05-27",
		"at":   "07:32:00.5",
		"odt":  "1979-05-27T14:32:00Z", // an offset date-time is an instant, so UTC
	} {
		if got := hashStr(t, value, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

// M26-DAT-016. [[x]] arrives as a slice of tables and was refused outright.
func TestTomlParseReadsArraysOfTables(t *testing.T) {
	value := mustCall(t, TomlParse, str("[[bin]]\nname = \"a\"\n[[bin]]\nname = \"b\"\n"))
	bins := mustArray(t, hashField(t, value, "bin"))
	if len(bins.Elements) != 2 || hashStr(t, bins.Elements[0], "name") != "a" || hashStr(t, bins.Elements[1], "name") != "b" {
		t.Fatalf("bin = %s, want [{name: a}, {name: b}]", bins.Inspect())
	}
}

// --- CBOR and MessagePack keys ---

// M26-DAT-014. Integer keys were written as text: COSE's {1: -7} did not
// round-trip, and {1: v} and {"1": v} encoded to the same bytes in both formats.
func TestCborAndMsgpackEncodeKeepIntegerKeys(t *testing.T) {
	cose, _ := hex.DecodeString("a10126")
	back := mustBytes(t, mustCall(t, CborEncode, mustCall(t, CborParse, &object.Bytes{Value: cose})))
	if got := hex.EncodeToString(back); got != "a10126" {
		t.Errorf("cbor round trip of {1: -7} = %s, want a10126", got)
	}

	numeric := typedHash(intVal(1), str("v"))
	text := typedHash(str("1"), str("v"))
	for name, encode := range map[string]func(...object.Object) object.Object{"cbor": CborEncode, "msgpack": MsgpackEncode} {
		a := mustBytes(t, mustCall(t, encode, numeric))
		b := mustBytes(t, mustCall(t, encode, text))
		if bytes.Equal(a, b) {
			t.Errorf("%s: {1: v} and {\"1\": v} both encode to %x", name, a)
		}
	}

	again := mustCall(t, MsgpackParse, mustCall(t, MsgpackEncode, numeric))
	if _, ok := again.(*object.Hash).Pairs[intVal(1).HashKey()]; !ok {
		t.Errorf("msgpack round trip of {1: v} = %s", again.Inspect())
	}
}

// The library sorts only maps of string keys; a map with typed keys came out
// in Go's map order. Now it is false, true, integers, then strings -- and a
// map of strings is byte for byte what it always was.
func TestMsgpackEncodeOrdersTypedKeys(t *testing.T) {
	mixed := typedHash(intVal(3), intVal(4), str("b"), intVal(6), &object.Boolean{Value: true}, intVal(2),
		intVal(-1), intVal(3), str("a"), intVal(5), &object.Boolean{Value: false}, intVal(1))
	want := "86c201c302ff030304a16105a16206"
	for i := 0; i < 20; i++ {
		if got := hex.EncodeToString(mustBytes(t, mustCall(t, MsgpackEncode, mixed))); got != want {
			t.Fatalf("encoding %d = %s, want %s", i, got, want)
		}
	}

	strings2 := typedHash(str("z"), intVal(1), str("a"), intVal(2))
	if got := hex.EncodeToString(mustBytes(t, mustCall(t, MsgpackEncode, strings2))); got != "82a16102a17a01" {
		t.Errorf("{z: 1, a: 2} = %s, want 82a16102a17a01 as before", got)
	}
}

// --- protobuf ---

// M26-DAT-011. The end-group marker carries the group's field number; the
// library was asked to match 0, so every real group failed the whole parse.
func TestProtobufParseReadsAGroup(t *testing.T) {
	fields := mustArray(t, mustCall(t, ProtobufParse, &object.Bytes{Value: []byte{0x0b, 0x10, 0x01, 0x0c}}))
	if len(fields.Elements) != 1 {
		t.Fatalf("got %d fields, want the one group", len(fields.Elements))
	}
	group := fields.Elements[0]
	if hashInt(t, group, "field") != 1 || hashStr(t, group, "wire_type") != "group" {
		t.Fatalf("group = %s", group.Inspect())
	}
	inner := mustArray(t, hashField(t, group, "message"))
	if len(inner.Elements) != 1 || hashInt(t, inner.Elements[0], "field") != 2 || hashInt(t, inner.Elements[0], "value") != 1 {
		t.Errorf("group contents = %s, want field 2 = 1", inner.Inspect())
	}
}

// M26-DAT-012. The field bound applied per message, and each nested payload
// started afresh: two payloads of 150,000 fields each passed it. The bound
// now covers the whole call.
func TestProtobufParseBoundsFieldsAcrossNestedMessages(t *testing.T) {
	payload := bytes.Repeat([]byte{0x08, 0x01}, 150_000)
	var data []byte
	for i := 0; i < 2; i++ {
		data = protowire.AppendTag(data, 1, protowire.BytesType)
		data = protowire.AppendBytes(data, payload)
	}
	errObj := callErr(t, ProtobufParse, &object.Bytes{Value: data})
	if !strings.Contains(errObj.Message, "expands past 262144 fields") {
		t.Errorf("got %q, want the whole-call field bound", errObj.Message)
	}
}

// Past 32 levels the nested reading is not tried. An absent "message" used to
// be all that showed it, which reads as "these bytes are not a message"; now
// message_unchecked says so. A group's contents are its fields, so a group
// that deep is refused rather than skipped.
func TestProtobufParseSaysWhereItStoppedLooking(t *testing.T) {
	data := []byte{0x08, 0x01}
	for i := 0; i < 34; i++ {
		data = protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), data)
	}
	field := mustArray(t, mustCall(t, ProtobufParse, &object.Bytes{Value: data})).Elements[0]
	for depth := 0; depth < 32; depth++ {
		field = mustArray(t, hashField(t, field, "message")).Elements[0]
	}
	if _, ok := hashValue(field.(*object.Hash), "message"); ok {
		t.Error("a field at depth 32 carries a message reading the limit says is not tried")
	}
	if !hashBool(t, field, "message_unchecked") {
		t.Error("the field at depth 32 does not say its message reading was not tried")
	}

	groups := append(bytes.Repeat([]byte{0x0b}, 40), bytes.Repeat([]byte{0x0c}, 40)...)
	errObj := callErr(t, ProtobufParse, &object.Bytes{Value: groups})
	if !strings.Contains(errObj.Message, "groups nest deeper than 32 levels") {
		t.Errorf("got %q, want the group-depth refusal", errObj.Message)
	}
}

// --- DER ---

// M26-DAT-013. Go's "06" puts 50-68 in the 2000s; X.509 puts 50-99 in the
// 1900s. The leap day shows the century move keeps a valid date valid.
func TestDerParseReadsUTCTimeYearsAsX509Does(t *testing.T) {
	for text, want := range map[string]string{
		"500101000000Z": "1950-01-01T00:00:00Z",
		"680229120000Z": "1968-02-29T12:00:00Z",
		"491231235959Z": "2049-12-31T23:59:59Z",
		"690101000000Z": "1969-01-01T00:00:00Z",
	} {
		data := append([]byte{0x17, byte(len(text))}, text...)
		node := mustArray(t, mustCall(t, DerParse, &object.Bytes{Value: data})).Elements[0]
		if got := hashStr(t, node, "decoded"); got != want {
			t.Errorf("UTCTime %s = %s, want %s", text, got, want)
		}
	}
}

// M26-DAT-029. Decimal conversion is superlinear: a 512 KiB INTEGER took 550
// ms. Past 4 KiB the text is hexadecimal, exact and linear; at 4 KiB and below
// it is decimal as before.
func TestDerParseRendersHugeIntegersExactly(t *testing.T) {
	der := func(content []byte) []byte {
		n := len(content)
		return append([]byte{0x02, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}, content...)
	}
	huge := bytes.Repeat([]byte{0x7f}, 1<<20)
	got := hashStr(t, mustArray(t, mustCall(t, DerParse, &object.Bytes{Value: der(huge)})).Elements[0], "decoded")
	if !strings.HasPrefix(got, "0x7f7f") || len(got) != 2+2*len(huge) {
		t.Fatalf("a 1 MiB INTEGER rendered as %d characters starting %.8q", len(got), got)
	}
	parsed, ok := new(big.Int).SetString(got[2:], 16)
	if !ok || parsed.Cmp(new(big.Int).SetBytes(huge)) != 0 {
		t.Error("the hexadecimal text is not the integer")
	}

	atLimit := append([]byte{0x01}, make([]byte, maxDecimalIntegerBytes-1)...)
	got = hashStr(t, mustArray(t, mustCall(t, DerParse, &object.Bytes{Value: der(atLimit)})).Elements[0], "decoded")
	if strings.HasPrefix(got, "0x") || got != new(big.Int).SetBytes(atLimit).String() {
		t.Errorf("a %d-byte INTEGER should still be decimal", len(atLimit))
	}
}

// --- JSON ---

// M26-DAT-017. One document is one value; trailing data used to be dropped,
// and ndjson_parse let a stray closer through.
func TestJsonParseReadsExactlyOneValue(t *testing.T) {
	for _, text := range []string{`{"a":1} {"b":2}`, `{"a":1} trailing garbage`, `{"a":1}}`, `1 2`} {
		callErr(t, JsonParse, str(text))
	}
	if got := hashInt(t, mustCall(t, JsonParse, str("{\"a\":1}\n\t ")), "a"); got != 1 {
		t.Errorf("trailing whitespace changed the value: a = %d", got)
	}
	errObj := callErr(t, NdjsonParse, str("{\"a\":1}}\n{\"b\":2}]\n"))
	if !strings.Contains(errObj.Message, "line 1") {
		t.Errorf("got %q, want line 1 named", errObj.Message)
	}
}

// The library keeps the last copy of a key written twice, so a document
// naming two users answered with one of them and hid the other.
func TestJsonParseRefusesARepeatedKey(t *testing.T) {
	errObj := callErr(t, JsonParse, str(`{"user":"alice","user":"mallory"}`))
	if !strings.Contains(errObj.Message, `"user" appears twice`) {
		t.Errorf("got %q, want the repeated key named", errObj.Message)
	}
	callErr(t, NdjsonParse, str("{\"a\":1,\"a\":2}\n"))
	value := mustCall(t, JsonParse, str(`{"a":{"a":1},"b":{"a":2}}`))
	if hashInt(t, hashField(t, value, "b"), "a") != 2 {
		t.Error("one key name in two different objects is not a repeat")
	}
}

// Bytes that are not UTF-8, and half a surrogate pair, came back as U+FFFD --
// a different string from the one in the file.
func TestJsonParseRefusesTextItWouldRewrite(t *testing.T) {
	for text, want := range map[string]string{
		"\"a\xffb\"":       "byte 2 is not UTF-8",
		`"\ud800"`:         "half of a surrogate pair",
		`"\uDC00x"`:        "half of a surrogate pair",
		`["\ud800\u0041"]`: "half of a surrogate pair",
	} {
		errObj := callErr(t, JsonParse, str(text))
		if !strings.Contains(errObj.Message, want) {
			t.Errorf("%q: got %q, want %q", text, errObj.Message, want)
		}
	}
	if got := mustCall(t, JsonParse, str(`"\ud83d\ude00"`)).(*object.String).Value; got != "\U0001F600" {
		t.Errorf("a whole surrogate pair = %q", got)
	}
	if got := mustCall(t, JsonParse, str(`"\\ud800"`)).(*object.String).Value; got != `\ud800` {
		t.Errorf("an escaped backslash before u = %q, want the six characters", got)
	}
}

// M26-DAT-018. An integer past INTEGER's range became a rounded FLOAT; every
// other decoder keeps the exact decimal text.
func TestJsonParseKeepsWideIntegersExact(t *testing.T) {
	for _, text := range []string{"18446744073709551615", "-9223372036854775809"} {
		got, ok := mustCall(t, JsonParse, str(text)).(*object.String)
		if !ok || got.Value != text {
			t.Errorf("%s came back as %v", text, got)
		}
	}
}

// Reading token by token keeps encoding/json's own depth bound: 10,000 levels
// parse, 10,001 do not.
func TestJsonParseKeepsItsDepthBound(t *testing.T) {
	mustCall(t, JsonParse, str(strings.Repeat("[", maxJSONDepth)+strings.Repeat("]", maxJSONDepth)))
	errObj := callErr(t, JsonParse, str(strings.Repeat("[", maxJSONDepth+1)+strings.Repeat("]", maxJSONDepth+1)))
	if !strings.Contains(errObj.Message, "nest deeper than 10000 levels") {
		t.Errorf("got %q", errObj.Message)
	}
}

// --- XML ---

func xmlIDs(t *testing.T, nodes object.Object) []string {
	t.Helper()
	var ids []string
	for _, node := range mustArray(t, nodes).Elements {
		ids = append(ids, hashStr(t, hashField(t, node, "attrs"), "id"))
	}
	return ids
}

// M26-DAT-019. ** reached one element once per way it could split the levels
// above, out of document order: "**/x" listed a direct child before a deeper
// one written first, "**/dir/**/file" found one file twice, and four ** over a
// chain of 60 elements returned 595,665 results.
func TestXmlFindReturnsEachElementOnceInDocumentOrder(t *testing.T) {
	doc := mustCall(t, XmlParse, str(`<r><a><x id="1"/></a><x id="2"/></r>`))
	if got := strings.Join(xmlIDs(t, mustCall(t, XmlFind, doc, str("**/x"))), ","); got != "1,2" {
		t.Errorf("**/x = [%s], want [1,2]", got)
	}

	doc = mustCall(t, XmlParse, str(`<r><dir id="d1"><dir id="d2"><file id="f"/></dir></dir></r>`))
	if got := strings.Join(xmlIDs(t, mustCall(t, XmlFind, doc, str("**/dir/**/file"))), ","); got != "f" {
		t.Errorf("**/dir/**/file = [%s], want [f]", got)
	}

	chain := strings.Repeat("<a>", 60) + strings.Repeat("</a>", 60)
	doc = mustCall(t, XmlParse, str("<r>"+chain+"</r>"))
	if n := len(mustArray(t, mustCall(t, XmlFind, doc, str("**/**/**/**/a"))).Elements); n != 60 {
		t.Errorf("**/**/**/**/a over 60 elements = %d results, want 60", n)
	}
	// "**" alone is the element itself and everything below it, root first.
	if n := len(mustArray(t, mustCall(t, XmlFind, doc, str("**"))).Elements); n != 61 {
		t.Errorf("** = %d results, want the root and its 60 descendants", n)
	}
}
