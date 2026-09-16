package builtin

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"mutant/object"

	"github.com/fxamacker/cbor/v2"
	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/encoding/protowire"
)

// The binary half of B-1: the serializations modern telemetry and modern
// cryptography arrive in. CBOR for COSE, WebAuthn and IoT; MessagePack for
// agent and queue traffic; protobuf for gRPC captures; DER for everything
// X.509 already reaches for internally.
//
// The last two are schemaless on purpose. An analyst holding a blob out of a
// packet capture or a certificate extension does not have the .proto or the
// ASN.1 module that produced it, and the question being asked is "what is in
// here" -- so both walk the encoding itself and report structure, rather than
// requiring a schema the evidence did not come with.

// cborDecMode carries the limits every decode runs under.
//
// The library's defaults already bound nesting, element counts and map pairs,
// which is most of the work; what is set here is the parts that matter for
// evidence. Duplicate map keys are rejected rather than resolved, because a
// COSE object with two of the same label is malformed and quietly keeping one
// of them answers a question only the analyst can. Indefinite-length items are
// allowed, since real streaming producers emit them.
var cborDecMode = mustCBORDecMode()

func mustCBORDecMode() cbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthAllowed,
		MaxNestedLevels:  maxCBORNesting,
		MaxArrayElements: maxCBORElements,
		MaxMapPairs:      maxCBORElements,
		UTF8:             cbor.UTF8DecodeInvalid,
	}.DecMode()
	if err != nil {
		panic("builtin: invalid CBOR decode options: " + err.Error())
	}
	return mode
}

// cborEncMode encodes canonically (RFC 8949 core deterministic encoding).
//
// Determinism is not a style preference here: a report that records the hash of
// a re-encoded structure has to produce the same bytes on the next run, and
// canonical ordering is what makes hash_sha256(cbor_encode(v)) a stable
// identifier for v.
var cborEncMode = mustCBOREncMode()

func mustCBOREncMode() cbor.EncMode {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic("builtin: invalid CBOR encode options: " + err.Error())
	}
	return mode
}

const (
	maxCBORNesting  = 64
	maxCBORElements = 1 << 20
)

func CborParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	data, errObj := requireBinaryArg(BuiltinNameCborParse, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var raw any
	if err := cborDecMode.Unmarshal(data, &raw); err != nil {
		return resultAndError(nil, newError("cbor_parse: %s", err.Error()))
	}
	value, err := nativeToObject(unwrapCBOR(raw, 0))
	if err != nil {
		return resultAndError(nil, newError("cbor_parse: %s", err.Error()))
	}
	return resultAndError(value, nil)
}

// unwrapCBOR rewrites tagged items into a shape the shared bridge understands.
//
// A tag is not decoration -- tag 1 is an epoch time, tag 2 a bignum, tag 18 a
// COSE_Sign1 -- so it cannot simply be dropped. It becomes a two-key hash,
// which keeps the number visible to a program that cares and out of the way of
// one that does not.
func unwrapCBOR(value any, depth int) any {
	if depth > maxNativeDepth {
		return value
	}
	switch v := value.(type) {
	case cbor.Tag:
		return map[string]any{
			"_cbor_tag": v.Number,
			"value":     unwrapCBOR(v.Content, depth+1),
		}
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = unwrapCBOR(item, depth+1)
		}
		return out
	case map[any]any:
		out := make(map[any]any, len(v))
		for key, item := range v {
			out[key] = unwrapCBOR(item, depth+1)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = unwrapCBOR(item, depth+1)
		}
		return out
	default:
		return value
	}
}

func CborEncode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	value, err := objectToNative(args[0], true)
	if err != nil {
		return resultAndError(nil, newError("cbor_encode: %s", err.Error()))
	}
	encoded, err := cborEncMode.Marshal(value)
	if err != nil {
		return resultAndError(nil, newError("cbor_encode: %s", err.Error()))
	}
	return resultAndError(&object.Bytes{Value: encoded}, nil)
}

// --- MessagePack ---

func MsgpackParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	data, errObj := requireBinaryArg(BuiltinNameMsgpackParse, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	decoder := msgpack.NewDecoder(strings.NewReader(string(data)))
	// Loose decoding coerces whatever it finds into the nearest Go kind, which
	// is exactly wrong for evidence: the point of reading a msgpack blob is to
	// learn that a field was a bin and not a str.
	decoder.UseLooseInterfaceDecoding(false)

	raw, err := decoder.DecodeInterface()
	if err != nil {
		return resultAndError(nil, newError("msgpack_parse: %s", err.Error()))
	}
	// Trailing bytes are reported rather than ignored: a blob that decodes and
	// then keeps going is either a stream (which needs decoding in a loop) or
	// not the thing it was thought to be, and both are worth knowing.
	if _, err := decoder.PeekCode(); err == nil {
		return resultAndError(nil, newError("msgpack_parse: input carries more than one value; this is a stream, not a single object"))
	}

	value, convErr := nativeToObject(raw)
	if convErr != nil {
		return resultAndError(nil, newError("msgpack_parse: %s", convErr.Error()))
	}
	return resultAndError(value, nil)
}

func MsgpackEncode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	value, err := objectToNative(args[0], true)
	if err != nil {
		return resultAndError(nil, newError("msgpack_encode: %s", err.Error()))
	}

	var out strings.Builder
	encoder := msgpack.NewEncoder(&out)
	// Sorted keys for the same reason CBOR encodes canonically: the bytes have
	// to be reproducible if anything downstream hashes them.
	encoder.SetSortMapKeys(true)
	encoder.UseCompactInts(true)
	if err := encoder.Encode(value); err != nil {
		return resultAndError(nil, newError("msgpack_encode: %s", err.Error()))
	}
	return resultAndError(&object.Bytes{Value: []byte(out.String())}, nil)
}

// --- Protocol Buffers (schemaless) ---

const (
	// maxProtobufDepth bounds how far the submessage heuristic will descend.
	maxProtobufDepth = 32
	// maxProtobufFields bounds fields reported from one message.
	maxProtobufFields = 1 << 18
)

// ProtobufParse walks a protobuf message without a schema.
//
// Wire format carries field numbers and wire types but no names and no
// declared types, so this reports what is actually there and every reading the
// bytes admit: a varint is shown as itself and as its zigzag decoding, because
// nothing in the encoding says which one the sender meant, and a length-
// delimited field is shown as bytes plus, when they happen to fit, as text and
// as a nested message. Naming the ambiguity is the honest thing a schemaless
// reader can do; picking one silently is not.
func ProtobufParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	data, errObj := requireBinaryArg(BuiltinNameProtobufParse, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	fields, err := walkProtobuf(data, 0)
	if err != nil {
		return resultAndError(nil, newError("protobuf_parse: %s", err.Error()))
	}
	return resultAndError(&object.Array{Elements: fields}, nil)
}

func walkProtobuf(data []byte, depth int) ([]object.Object, error) {
	fields := make([]object.Object, 0, 8)
	offset := 0
	for len(data) > 0 {
		if len(fields) >= maxProtobufFields {
			return nil, fmt.Errorf("message has more than %d fields", maxProtobufFields)
		}
		number, wireType, tagLen := protowire.ConsumeTag(data)
		if tagLen < 0 {
			return nil, fmt.Errorf("at offset %d: %s", offset, protowire.ParseError(tagLen).Error())
		}
		data = data[tagLen:]
		offset += tagLen

		field := map[string]object.Object{
			"field":     intObj(int64(number)),
			"wire_type": stringObj(protobufWireName(wireType)),
			"offset":    intObj(int64(offset - tagLen)),
		}

		consumed, err := decodeProtobufValue(field, data, wireType, depth)
		if err != nil {
			return nil, fmt.Errorf("field %d at offset %d: %s", number, offset-tagLen, err.Error())
		}
		data = data[consumed:]
		offset += consumed
		fields = append(fields, makeHashObject(field))
	}
	return fields, nil
}

func protobufWireName(t protowire.Type) string {
	switch t {
	case protowire.VarintType:
		return "varint"
	case protowire.Fixed32Type:
		return "fixed32"
	case protowire.Fixed64Type:
		return "fixed64"
	case protowire.BytesType:
		return "bytes"
	case protowire.StartGroupType:
		return "group"
	case protowire.EndGroupType:
		return "end-group"
	default:
		return "type-" + strconv.Itoa(int(t))
	}
}

func decodeProtobufValue(field map[string]object.Object, data []byte, wireType protowire.Type, depth int) (int, error) {
	switch wireType {
	case protowire.VarintType:
		value, n := protowire.ConsumeVarint(data)
		if n < 0 {
			return 0, protowire.ParseError(n)
		}
		field["value"] = uintToObject(value)
		field["zigzag"] = intObj(protowire.DecodeZigZag(value))
		field["bool"] = boolObj(value != 0)
		return n, nil

	case protowire.Fixed32Type:
		value, n := protowire.ConsumeFixed32(data)
		if n < 0 {
			return 0, protowire.ParseError(n)
		}
		field["value"] = intObj(int64(value))
		field["float"] = floatObj(float64(math.Float32frombits(value)))
		return n, nil

	case protowire.Fixed64Type:
		value, n := protowire.ConsumeFixed64(data)
		if n < 0 {
			return 0, protowire.ParseError(n)
		}
		field["value"] = uintToObject(value)
		field["float"] = floatObj(math.Float64frombits(value))
		return n, nil

	case protowire.BytesType:
		payload, n := protowire.ConsumeBytes(data)
		if n < 0 {
			return 0, protowire.ParseError(n)
		}
		field["value"] = &object.Bytes{Value: payload}
		field["length"] = intObj(int64(len(payload)))
		// The two interpretations a length-delimited field admits. Both are
		// heuristics and both are labelled as such by being separate keys: a
		// string field and a submessage field are indistinguishable on the
		// wire, and plenty of short byte strings parse as valid messages by
		// coincidence.
		if text, ok := printableProtobufString(payload); ok {
			field["text"] = stringObj(text)
		}
		if depth < maxProtobufDepth && len(payload) > 0 {
			if nested, err := walkProtobuf(payload, depth+1); err == nil {
				field["message"] = &object.Array{Elements: nested}
			}
		}
		return n, nil

	case protowire.StartGroupType:
		payload, n := protowire.ConsumeGroup(protowire.Number(0), data)
		if n < 0 {
			return 0, protowire.ParseError(n)
		}
		if depth < maxProtobufDepth {
			nested, err := walkProtobuf(payload, depth+1)
			if err != nil {
				return 0, err
			}
			field["message"] = &object.Array{Elements: nested}
		}
		return n, nil

	default:
		return 0, fmt.Errorf("wire type %d cannot start a field", wireType)
	}
}

// printableProtobufString reports whether a payload reads as text: valid UTF-8
// with no control characters other than tab, newline and carriage return.
func printableProtobufString(payload []byte) (string, bool) {
	if len(payload) == 0 {
		return "", false
	}
	text := string(payload)
	if !utf8.ValidString(text) {
		return "", false
	}
	for _, r := range text {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return text, true
}

// --- ASN.1 / DER ---

const (
	maxDERDepth = 64
	maxDERNodes = 1 << 18
)

// DerParse walks a DER-encoded structure without a schema.
//
// encoding/asn1 exists, but it unmarshals into a Go struct the caller has
// already written -- which is the one thing an analyst holding an unknown
// certificate extension, a PKCS#7 blob or a Kerberos ticket cannot do. This
// reports the tag-length-value tree itself, decoding the universal types whose
// meaning is unambiguous (OIDs, the string types, integers, times) and leaving
// everything else as the bytes it is.
func DerParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	data, errObj := requireBinaryArg(BuiltinNameDerParse, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	budget := maxDERNodes
	nodes, _, err := walkDER(data, 0, 0, &budget)
	if err != nil {
		return resultAndError(nil, newError("der_parse: %s", err.Error()))
	}
	return resultAndError(&object.Array{Elements: nodes}, nil)
}

func walkDER(data []byte, base, depth int, budget *int) ([]object.Object, int, error) {
	if depth > maxDERDepth {
		return nil, 0, fmt.Errorf("structure nests deeper than %d levels", maxDERDepth)
	}
	nodes := make([]object.Object, 0, 4)
	offset := 0

	for offset < len(data) {
		*budget--
		if *budget < 0 {
			return nil, 0, fmt.Errorf("structure has more than %d elements", maxDERNodes)
		}

		start := offset
		tagByte := data[offset]
		class := tagByte >> 6
		constructed := tagByte&0x20 != 0
		tagNumber := int(tagByte & 0x1f)
		offset++

		// A high tag number spills into continuation bytes, seven bits each.
		if tagNumber == 0x1f {
			tagNumber = 0
			for {
				if offset >= len(data) {
					return nil, 0, fmt.Errorf("at offset %d: tag number is truncated", base+start)
				}
				b := data[offset]
				offset++
				if tagNumber > (math.MaxInt32-int(b&0x7f))/128 {
					return nil, 0, fmt.Errorf("at offset %d: tag number is too large", base+start)
				}
				tagNumber = tagNumber*128 + int(b&0x7f)
				if b&0x80 == 0 {
					break
				}
			}
		}

		length, headerEnd, err := readDERLength(data, offset, base+start)
		if err != nil {
			return nil, 0, err
		}
		offset = headerEnd
		if length > len(data)-offset {
			return nil, 0, fmt.Errorf("at offset %d: element declares %d bytes but only %d remain", base+start, length, len(data)-offset)
		}
		content := data[offset : offset+length]
		offset += length

		node := map[string]object.Object{
			"offset":      intObj(int64(base + start)),
			"header_len":  intObj(int64(headerEnd - start)),
			"length":      intObj(int64(length)),
			"class":       stringObj(derClassName(class)),
			"tag":         intObj(int64(tagNumber)),
			"constructed": boolObj(constructed),
			"tag_name":    stringObj(derTagName(class, tagNumber, constructed)),
		}

		if constructed {
			children, _, err := walkDER(content, base+headerEnd, depth+1, budget)
			if err != nil {
				return nil, 0, err
			}
			node["children"] = &object.Array{Elements: children}
		} else {
			node["value"] = &object.Bytes{Value: content}
			if class == 0 {
				if decoded, ok := decodeDERUniversal(tagNumber, content); ok {
					node["decoded"] = decoded
				}
			}
		}
		nodes = append(nodes, makeHashObject(node))
	}
	return nodes, offset, nil
}

// readDERLength reads a definite length and returns it with the offset just
// past the header.
//
// Indefinite length is BER, not DER, and it is refused by name rather than
// supported: the encodings this reaches for -- certificates, CMS, tickets --
// all require definite length, and a document using it is either not DER or is
// deliberately shaped to confuse a parser.
func readDERLength(data []byte, offset, absolute int) (int, int, error) {
	if offset >= len(data) {
		return 0, 0, fmt.Errorf("at offset %d: length byte is missing", absolute)
	}
	first := data[offset]
	offset++
	if first&0x80 == 0 {
		return int(first), offset, nil
	}
	count := int(first & 0x7f)
	if count == 0 {
		return 0, 0, fmt.Errorf("at offset %d: indefinite length is BER, not DER", absolute)
	}
	if count > 8 {
		return 0, 0, fmt.Errorf("at offset %d: length spans %d bytes, which no real element needs", absolute, count)
	}
	if offset+count > len(data) {
		return 0, 0, fmt.Errorf("at offset %d: length is truncated", absolute)
	}
	value := 0
	for i := 0; i < count; i++ {
		if value > (math.MaxInt32-int(data[offset+i]))/256 {
			return 0, 0, fmt.Errorf("at offset %d: length does not fit", absolute)
		}
		value = value*256 + int(data[offset+i])
	}
	return value, offset + count, nil
}

func derClassName(class byte) string {
	switch class {
	case 0:
		return "universal"
	case 1:
		return "application"
	case 2:
		return "context"
	case 3:
		return "private"
	default:
		return "class-" + strconv.Itoa(int(class))
	}
}

var derUniversalTags = map[int]string{
	1: "BOOLEAN", 2: "INTEGER", 3: "BIT STRING", 4: "OCTET STRING", 5: "NULL",
	6: "OBJECT IDENTIFIER", 7: "ObjectDescriptor", 9: "REAL", 10: "ENUMERATED",
	11: "EMBEDDED PDV", 12: "UTF8String", 13: "RELATIVE-OID", 16: "SEQUENCE",
	17: "SET", 18: "NumericString", 19: "PrintableString", 20: "T61String",
	21: "VideotexString", 22: "IA5String", 23: "UTCTime", 24: "GeneralizedTime",
	25: "GraphicString", 26: "VisibleString", 27: "GeneralString",
	28: "UniversalString", 29: "CHARACTER STRING", 30: "BMPString",
}

func derTagName(class byte, tag int, constructed bool) string {
	if class != 0 {
		if constructed {
			return "[" + strconv.Itoa(tag) + "] constructed"
		}
		return "[" + strconv.Itoa(tag) + "]"
	}
	if name, ok := derUniversalTags[tag]; ok {
		return name
	}
	return "universal-" + strconv.Itoa(tag)
}

// decodeDERUniversal renders a primitive universal-class element as the value
// it stands for, alongside the raw bytes rather than instead of them. It
// answers false rather than guessing: an element whose content does not match
// its tag is left as bytes, because a certificate that is malformed in exactly
// that way is the interesting case, not one to paper over.
func decodeDERUniversal(tag int, content []byte) (object.Object, bool) {
	switch tag {
	case 1: // BOOLEAN
		if len(content) != 1 {
			return nil, false
		}
		return boolObj(content[0] != 0), true
	case 2, 10: // INTEGER, ENUMERATED
		return derInteger(content)
	case 3: // BIT STRING
		if len(content) == 0 || content[0] > 7 {
			return nil, false
		}
		return makeHashObject(map[string]object.Object{
			"unused_bits": intObj(int64(content[0])),
			"bits":        &object.Bytes{Value: content[1:]},
		}), true
	case 5: // NULL
		if len(content) != 0 {
			return nil, false
		}
		return &object.Null{}, true
	case 6: // OBJECT IDENTIFIER
		text, ok := derOID(content)
		if !ok {
			return nil, false
		}
		return stringObj(text), true
	case 12, 18, 19, 20, 22, 26, 27: // UTF8String and the ASCII-shaped strings
		if !utf8.Valid(content) {
			return nil, false
		}
		return stringObj(string(content)), true
	case 30: // BMPString is UTF-16BE
		text, ok := derBMPString(content)
		if !ok {
			return nil, false
		}
		return stringObj(text), true
	case 23: // UTCTime
		return derTime(content, []string{"060102150405Z0700", "0601021504Z0700"})
	case 24: // GeneralizedTime
		return derTime(content, []string{
			"20060102150405Z0700", "20060102150405.999999999Z0700",
			"200601021504Z0700", "2006010215Z0700",
		})
	default:
		return nil, false
	}
}

// derInteger reads a two's-complement integer of any width. A certificate
// serial is routinely 20 bytes, so anything that does not fit an int64 becomes
// decimal text rather than a truncation -- a serial reduced to its low 64 bits
// is a different serial, and reporting it as this one would be a lie the whole
// language is built to avoid.
func derInteger(content []byte) (object.Object, bool) {
	if len(content) == 0 {
		return nil, false
	}
	value := new(big.Int).SetBytes(content)
	if content[0]&0x80 != 0 {
		value.Sub(value, new(big.Int).Lsh(big.NewInt(1), uint(8*len(content))))
	}
	if value.IsInt64() {
		return intObj(value.Int64()), true
	}
	return stringObj(value.String()), true
}

// derOID renders an OID as its dotted form. The first byte packs two arcs, but
// only when it is a single-byte subidentifier -- the general decode below gets
// that right for the long-form first arc too.
func derOID(content []byte) (string, bool) {
	if len(content) == 0 {
		return "", false
	}
	var (
		subs    []uint64
		current uint64
		started bool
	)
	for _, b := range content {
		if !started && b == 0x80 {
			return "", false // non-minimal: a leading continuation of zero
		}
		started = true
		if current > (math.MaxUint64-uint64(b&0x7f))/128 {
			return "", false
		}
		current = current*128 + uint64(b&0x7f)
		if b&0x80 == 0 {
			subs = append(subs, current)
			current = 0
			started = false
		}
	}
	if started || len(subs) == 0 {
		return "", false // trailing continuation byte with nothing after it
	}
	var parts []string
	switch first := subs[0]; {
	case first < 40:
		parts = append(parts, "0", strconv.FormatUint(first, 10))
	case first < 80:
		parts = append(parts, "1", strconv.FormatUint(first-40, 10))
	default:
		parts = append(parts, "2", strconv.FormatUint(first-80, 10))
	}
	for _, sub := range subs[1:] {
		parts = append(parts, strconv.FormatUint(sub, 10))
	}
	return strings.Join(parts, "."), true
}

func derBMPString(content []byte) (string, bool) {
	if len(content)%2 != 0 {
		return "", false
	}
	units := make([]uint16, 0, len(content)/2)
	for i := 0; i < len(content); i += 2 {
		units = append(units, uint16(content[i])<<8|uint16(content[i+1]))
	}
	decoded := string(utf16.Decode(units))
	if !utf8.ValidString(decoded) {
		return "", false
	}
	return decoded, true
}

// derTime renders a certificate time as RFC 3339 in UTC, so it sorts and
// compares against every other timestamp the language produces.
func derTime(content []byte, layouts []string) (object.Object, bool) {
	text := string(content)
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, text); err == nil {
			return stringObj(parsed.UTC().Format(time.RFC3339Nano)), true
		}
	}
	return nil, false
}
