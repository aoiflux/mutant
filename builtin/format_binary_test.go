package builtin

import (
	"encoding/hex"
	"strings"
	"testing"

	"mutant/object"

	"github.com/fxamacker/cbor/v2"
	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/encoding/protowire"
)

// The binary formats are where the bytes type earns its keep: CBOR, MessagePack
// and DER all distinguish a byte string from a text string, and before L-4 that
// distinction had nowhere to land. These tests pin that it lands.

func mustBytes(t *testing.T, obj object.Object) []byte {
	t.Helper()

	buf, ok := obj.(*object.Bytes)
	if !ok {
		t.Fatalf("expected BYTES, got %s (%s)", obj.Type(), obj.Inspect())
	}
	return buf.Value
}

func fromHex(t *testing.T, s string) *object.Bytes {
	t.Helper()

	data, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return &object.Bytes{Value: data}
}

// --- CBOR ---

func TestCborParseKeepsBytesAsBytes(t *testing.T) {
	encoded, err := cbor.Marshal(map[string]any{"blob": []byte{0x4d, 0x5a}, "name": "evil.exe"})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	value := mustCall(t, CborParse, &object.Bytes{Value: encoded})
	if got := mustBytes(t, hashField(t, value, "blob")); string(got) != "MZ" {
		t.Errorf("blob = %v, want the two bytes MZ", got)
	}
	if got := hashStr(t, value, "name"); got != "evil.exe" {
		t.Errorf("name = %q", got)
	}
}

// COSE labels its map keys with integers throughout, so a decoder that only
// accepts string keys cannot read a signed token at all.
func TestCborParseAcceptsIntegerMapKeys(t *testing.T) {
	encoded, err := cbor.Marshal(map[int]any{1: -7, 4: "kid"})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	value, errObj := callPair(t, CborParse, &object.Bytes{Value: encoded})
	if errObj != nil {
		t.Fatalf("integer-keyed map was refused: %s", errObj.Message)
	}
	hash, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH, got %s", value.Type())
	}
	if len(hash.Pairs) != 2 {
		t.Fatalf("got %d pairs, want 2", len(hash.Pairs))
	}
}

// A tag is not decoration: tag 18 is a COSE_Sign1, and dropping it would
// silently turn a signed structure into an anonymous array.
func TestCborParsePreservesTags(t *testing.T) {
	encoded, err := cbor.Marshal(cbor.Tag{Number: 18, Content: []byte{1, 2, 3}})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	value := mustCall(t, CborParse, &object.Bytes{Value: encoded})
	if got := hashInt(t, value, "_cbor_tag"); got != 18 {
		t.Errorf("_cbor_tag = %d, want 18", got)
	}
	if got := mustBytes(t, hashField(t, value, "value")); len(got) != 3 || got[2] != 3 {
		t.Errorf("value = %v", got)
	}
}

// The standard time tags are the exception: the library resolves tag 1 to a
// time, and the shared bridge renders every time the same way, so an epoch in
// CBOR reads like an epoch from YAML or TOML rather than like a bare integer.
func TestCborParseResolvesTheStandardTimeTag(t *testing.T) {
	encoded, err := cbor.Marshal(cbor.Tag{Number: 1, Content: int64(1757160000)})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	value := mustCall(t, CborParse, &object.Bytes{Value: encoded})
	text, ok := value.(*object.String)
	if !ok {
		t.Fatalf("expected an RFC 3339 string, got %s", value.Type())
	}
	if !strings.HasPrefix(text.Value, "2025-") && !strings.HasPrefix(text.Value, "2026-") {
		t.Errorf("time = %q, want an RFC 3339 timestamp", text.Value)
	}
}

// Canonical encoding is what makes hash_sha256(cbor_encode(v)) an identifier
// for v rather than for one particular walk of a Go map.
func TestCborEncodeIsDeterministic(t *testing.T) {
	hash := &object.Hash{}
	setHashKey(t, hash, "z", str("last"))
	setHashKey(t, hash, "a", str("first"))
	setHashKey(t, hash, "m", str("middle"))

	first := mustBytes(t, mustCall(t, CborEncode, hash))
	for i := 0; i < 8; i++ {
		again := mustBytes(t, mustCall(t, CborEncode, hash))
		if string(again) != string(first) {
			t.Fatalf("encoding %d differs from the first", i)
		}
	}
}

func TestCborRoundTripsThroughTheSharedBridge(t *testing.T) {
	hash := &object.Hash{}
	setHashKey(t, hash, "buf", &object.Bytes{Value: []byte{0, 1, 2, 255}})
	setHashKey(t, hash, "n", &object.Integer{Value: -42})
	setHashKey(t, hash, "ok", &object.Boolean{Value: true})

	encoded := mustCall(t, CborEncode, hash)
	back := mustCall(t, CborParse, encoded)
	if got := mustBytes(t, hashField(t, back, "buf")); len(got) != 4 || got[3] != 255 {
		t.Errorf("buf = %v", got)
	}
	if got := hashInt(t, back, "n"); got != -42 {
		t.Errorf("n = %d", got)
	}
	if !hashBool(t, back, "ok") {
		t.Error("ok did not survive")
	}
}

// --- MessagePack ---

func TestMsgpackParseKeepsBinaryAsBytes(t *testing.T) {
	encoded, err := msgpack.Marshal(map[string]any{"blob": []byte{0x7f, 0x45, 0x4c, 0x46}, "n": 7})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	value := mustCall(t, MsgpackParse, &object.Bytes{Value: encoded})
	if got := mustBytes(t, hashField(t, value, "blob")); len(got) != 4 || got[0] != 0x7f {
		t.Errorf("blob = %v, want the ELF magic", got)
	}
	if got := hashInt(t, value, "n"); got != 7 {
		t.Errorf("n = %d", got)
	}
}

// A blob that decodes and then keeps going is either a stream or not what it
// was thought to be. Silently returning the first value hides both.
func TestMsgpackParseReportsTrailingBytes(t *testing.T) {
	first, _ := msgpack.Marshal(1)
	second, _ := msgpack.Marshal(2)
	errObj := callErr(t, MsgpackParse, &object.Bytes{Value: append(first, second...)})
	if !strings.Contains(errObj.Message, "stream") {
		t.Errorf("error should say the input is a stream; got %q", errObj.Message)
	}
}

func TestMsgpackEncodeIsDeterministic(t *testing.T) {
	hash := &object.Hash{}
	setHashKey(t, hash, "z", &object.Integer{Value: 1})
	setHashKey(t, hash, "a", &object.Integer{Value: 2})

	first := mustBytes(t, mustCall(t, MsgpackEncode, hash))
	for i := 0; i < 8; i++ {
		if string(mustBytes(t, mustCall(t, MsgpackEncode, hash))) != string(first) {
			t.Fatalf("encoding %d differs from the first", i)
		}
	}
}

func TestMsgpackRoundTripsBuffers(t *testing.T) {
	hash := &object.Hash{}
	setHashKey(t, hash, "buf", &object.Bytes{Value: []byte{0xde, 0xad, 0xbe, 0xef}})

	back := mustCall(t, MsgpackParse, mustCall(t, MsgpackEncode, hash))
	if got := mustBytes(t, hashField(t, back, "buf")); hex.EncodeToString(got) != "deadbeef" {
		t.Errorf("buf = %x", got)
	}
}

// --- protobuf ---

func protoFixture() []byte {
	var out []byte
	out = protowire.AppendTag(out, 1, protowire.VarintType)
	out = protowire.AppendVarint(out, 150)
	out = protowire.AppendTag(out, 2, protowire.BytesType)
	out = protowire.AppendString(out, "powershell.exe")

	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.VarintType)
	inner = protowire.AppendVarint(inner, 1)
	out = protowire.AppendTag(out, 3, protowire.BytesType)
	out = protowire.AppendBytes(out, inner)
	return out
}

// Without a .proto there is no way to know which reading of a varint was meant,
// so every reading is reported. Naming the ambiguity is the honest thing a
// schemaless reader can do.
func TestProtobufParseReportsEveryReadingOfAVarint(t *testing.T) {
	fields := mustArray(t, mustCall(t, ProtobufParse, &object.Bytes{Value: protoFixture()}))
	if len(fields.Elements) != 3 {
		t.Fatalf("got %d fields, want 3", len(fields.Elements))
	}

	first := fields.Elements[0]
	if got := hashInt(t, first, "field"); got != 1 {
		t.Errorf("field = %d, want 1", got)
	}
	if got := hashStr(t, first, "wire_type"); got != "varint" {
		t.Errorf("wire_type = %q", got)
	}
	if got := hashInt(t, first, "value"); got != 150 {
		t.Errorf("value = %d", got)
	}
	if got := hashInt(t, first, "zigzag"); got != 75 {
		t.Errorf("zigzag = %d, want 75", got)
	}
	if hashBool(t, first, "bool") != true {
		t.Error("bool reading of 150 should be true")
	}
}

func TestProtobufParseOffersTextAndMessageReadingsOfBytes(t *testing.T) {
	fields := mustArray(t, mustCall(t, ProtobufParse, &object.Bytes{Value: protoFixture()}))

	text := fields.Elements[1]
	if got := hashStr(t, text, "text"); got != "powershell.exe" {
		t.Errorf("text = %q", got)
	}
	if got := mustBytes(t, hashField(t, text, "value")); string(got) != "powershell.exe" {
		t.Errorf("the raw bytes must be reported alongside the text; got %v", got)
	}

	nested := fields.Elements[2]
	inner := mustArray(t, hashField(t, nested, "message"))
	if len(inner.Elements) != 1 {
		t.Fatalf("nested message has %d fields, want 1", len(inner.Elements))
	}
}

func TestProtobufParseRefusesATruncatedField(t *testing.T) {
	fixture := protoFixture()
	if errObj := callErr(t, ProtobufParse, &object.Bytes{Value: fixture[:len(fixture)-3]}); errObj.Message == "" {
		t.Error("a truncated message must be reported")
	}
}

// --- DER ---

// SEQUENCE { INTEGER 42, OBJECT IDENTIFIER 1.2.840.113549.1.1.11,
//
//	PrintableString "CA", BOOLEAN true }
const derFixture = "301c" +
	"02012a" +
	"06092a864886f70d01010b" +
	"13024341" +
	"0101ff" +
	"0500" +
	"0403010203"

func TestDerParseWalksAConstructedTree(t *testing.T) {
	nodes := mustArray(t, mustCall(t, DerParse, fromHex(t, derFixture)))
	if len(nodes.Elements) != 1 {
		t.Fatalf("got %d top-level nodes, want 1", len(nodes.Elements))
	}
	root := nodes.Elements[0]
	if got := hashStr(t, root, "tag_name"); got != "SEQUENCE" {
		t.Errorf("tag_name = %q", got)
	}
	if !hashBool(t, root, "constructed") {
		t.Error("a SEQUENCE is constructed")
	}
	children := mustArray(t, hashField(t, root, "children"))
	if len(children.Elements) != 6 {
		t.Fatalf("SEQUENCE has %d children, want 6", len(children.Elements))
	}
}

func TestDerParseDecodesUniversalPrimitives(t *testing.T) {
	nodes := mustArray(t, mustCall(t, DerParse, fromHex(t, derFixture)))
	children := mustArray(t, hashField(t, nodes.Elements[0], "children"))

	if got := hashInt(t, children.Elements[0], "decoded"); got != 42 {
		t.Errorf("INTEGER decoded = %d, want 42", got)
	}
	// The sha256WithRSAEncryption OID. A dotted string is the form every other
	// tool prints, so it is the form to hand back.
	if got := hashStr(t, children.Elements[1], "decoded"); got != "1.2.840.113549.1.1.11" {
		t.Errorf("OID decoded = %q", got)
	}
	if got := hashStr(t, children.Elements[2], "decoded"); got != "CA" {
		t.Errorf("PrintableString decoded = %q", got)
	}
	if !hashBool(t, children.Elements[3], "decoded") {
		t.Error("BOOLEAN 0xff should decode true")
	}
	// The raw bytes are always reported alongside whatever was decoded.
	if got := mustBytes(t, hashField(t, children.Elements[5], "value")); hex.EncodeToString(got) != "010203" {
		t.Errorf("OCTET STRING value = %x", got)
	}
}

// A serial reduced to its low 64 bits is a different serial. Decimal text is
// the only rendering that stays true for the 20-byte serials certificates use.
func TestDerParseRendersBigIntegersAsDecimalText(t *testing.T) {
	// INTEGER 0x0100000000000000000000 (2^80), which no int64 holds.
	nodes := mustArray(t, mustCall(t, DerParse, fromHex(t, "020b0100000000000000000000")))
	if got := hashStr(t, nodes.Elements[0], "decoded"); got != "1208925819614629174706176" {
		t.Errorf("decoded = %q, want 2^80 in decimal", got)
	}
}

// DER forbids indefinite length; a document using it is either not DER or is
// shaped to confuse a parser. Either way it is named rather than guessed at.
func TestDerParseRefusesBerIndefiniteLength(t *testing.T) {
	errObj := callErr(t, DerParse, fromHex(t, "3080050000 00"))
	if !strings.Contains(errObj.Message, "BER") {
		t.Errorf("error should name BER indefinite length; got %q", errObj.Message)
	}
}

func TestDerParseRefusesALengthPastTheEnd(t *testing.T) {
	errObj := callErr(t, DerParse, fromHex(t, "0420deadbeef"))
	if !strings.Contains(errObj.Message, "remain") {
		t.Errorf("error should say how many bytes remain; got %q", errObj.Message)
	}
}

func TestDerParseDecodesUtcTimeAsRfc3339(t *testing.T) {
	// UTCTime "260906120000Z"
	nodes := mustArray(t, mustCall(t, DerParse, fromHex(t, "170d3236303930363132303030305a")))
	if got := hashStr(t, nodes.Elements[0], "decoded"); !strings.HasPrefix(got, "2026-09-06T12:00:00") {
		t.Errorf("decoded = %q, want RFC 3339", got)
	}
}

// A context-class element carries no universal meaning, so it is described
// structurally and left as bytes rather than decoded as something it is not.
func TestDerParseLeavesContextTagsUndecoded(t *testing.T) {
	nodes := mustArray(t, mustCall(t, DerParse, fromHex(t, "80024142")))
	node := nodes.Elements[0]
	if got := hashStr(t, node, "class"); got != "context" {
		t.Errorf("class = %q", got)
	}
	if got := hashStr(t, node, "tag_name"); got != "[0]" {
		t.Errorf("tag_name = %q", got)
	}
	if _, ok := hashValueByStringKey(node.(*object.Hash), "decoded"); ok {
		t.Error("a context-class element must not carry a decoded rendering")
	}
}
