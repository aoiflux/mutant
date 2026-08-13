package builtin

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"mutant/object"
)

// Cocoa/Core Foundation epoch (2001-01-01 UTC) in Unix seconds.
const cocoaEpochUnix = 978307200

// PlistParse parses an Apple property list (binary bplist00 or XML) into a Mutant
// value (dict->hash, array->array, plus string/integer/real/bool; dates and data
// become strings). Pure-Go, no dependencies. Returns (value, err).
func PlistParse(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("plist_parse: panic during parse: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("plist_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return resultAndError(nil, newError("plist_parse: %s", err.Error()))
	}

	var obj object.Object
	if len(data) >= 8 && string(data[:8]) == "bplist00" {
		obj, err = parseBinaryPlist(data)
	} else {
		obj, err = parseXMLPlist(data)
	}
	if err != nil {
		return resultAndError(nil, newError("plist_parse: %s", err.Error()))
	}
	return resultAndError(obj, nil)
}

// --- XML plist ---

func parseXMLPlist(data []byte) (object.Object, error) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("no plist root element found")
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local == "plist" {
				return parseXMLPlistInner(dec)
			}
			// Some plists omit the <plist> wrapper.
			return parseXMLPlistValue(dec, se)
		}
	}
}

func parseXMLPlistInner(dec *xml.Decoder) (object.Object, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return globalNullObject(), nil
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return parseXMLPlistValue(dec, t)
		case xml.EndElement:
			return globalNullObject(), nil
		}
	}
}

func parseXMLPlistValue(dec *xml.Decoder, start xml.StartElement) (object.Object, error) {
	switch start.Name.Local {
	case "dict":
		return parseXMLPlistDict(dec)
	case "array":
		return parseXMLPlistArray(dec)
	case "string":
		return stringObj(readXMLText(dec, start)), nil
	case "integer":
		n, _ := strconv.ParseInt(strings.TrimSpace(readXMLText(dec, start)), 10, 64)
		return intObj(n), nil
	case "real":
		f, _ := strconv.ParseFloat(strings.TrimSpace(readXMLText(dec, start)), 64)
		return floatObj(f), nil
	case "true":
		dec.Skip()
		return boolObj(true), nil
	case "false":
		dec.Skip()
		return boolObj(false), nil
	case "date":
		return stringObj(strings.TrimSpace(readXMLText(dec, start))), nil
	case "data":
		raw := strings.Join(strings.Fields(readXMLText(dec, start)), "")
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return stringObj(raw), nil
		}
		return stringObj(string(decoded)), nil
	default:
		dec.Skip()
		return globalNullObject(), nil
	}
}

func parseXMLPlistDict(dec *xml.Decoder) (object.Object, error) {
	pairs := map[string]object.Object{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return makeHashObject(pairs), nil
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local != "key" {
				dec.Skip()
				continue
			}
			key := readXMLText(dec, t)
			// next start element is the value
			val, verr := nextXMLValue(dec)
			if verr != nil {
				return makeHashObject(pairs), nil
			}
			pairs[key] = val
		case xml.EndElement:
			return makeHashObject(pairs), nil
		}
	}
}

func parseXMLPlistArray(dec *xml.Decoder) (object.Object, error) {
	elems := []object.Object{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return &object.Array{Elements: elems}, nil
		}
		switch t := tok.(type) {
		case xml.StartElement:
			v, verr := parseXMLPlistValue(dec, t)
			if verr != nil {
				return &object.Array{Elements: elems}, nil
			}
			elems = append(elems, v)
		case xml.EndElement:
			return &object.Array{Elements: elems}, nil
		}
	}
}

func nextXMLValue(dec *xml.Decoder) (object.Object, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok {
			return parseXMLPlistValue(dec, se)
		}
	}
}

func readXMLText(dec *xml.Decoder, start xml.StartElement) string {
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return sb.String()
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			if t.Name.Local == start.Name.Local {
				return sb.String()
			}
		}
	}
}

// --- binary plist (bplist00) ---

func parseBinaryPlist(data []byte) (object.Object, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("binary plist too short")
	}
	trailer := data[len(data)-32:]
	offsetIntSize := int(trailer[6])
	objectRefSize := int(trailer[7])
	numObjects := int(binary.BigEndian.Uint64(trailer[8:16]))
	topObject := int(binary.BigEndian.Uint64(trailer[16:24]))
	offsetTableOffset := int(binary.BigEndian.Uint64(trailer[24:32]))

	if offsetIntSize < 1 || objectRefSize < 1 || numObjects < 1 {
		return nil, fmt.Errorf("invalid binary plist trailer")
	}
	offsets := make([]int, numObjects)
	for i := 0; i < numObjects; i++ {
		start := offsetTableOffset + i*offsetIntSize
		if start+offsetIntSize > len(data) {
			return nil, fmt.Errorf("offset table out of bounds")
		}
		offsets[i] = int(beUint(data[start : start+offsetIntSize]))
	}

	p := &bplistParser{data: data, offsets: offsets, numObjects: numObjects, refSize: objectRefSize}
	return p.parseObject(topObject, 0)
}

type bplistParser struct {
	data       []byte
	offsets    []int
	numObjects int
	refSize    int
}

func (p *bplistParser) parseObject(idx, depth int) (object.Object, error) {
	if depth > 100 {
		return nil, fmt.Errorf("binary plist nesting too deep")
	}
	if idx < 0 || idx >= p.numObjects {
		return nil, fmt.Errorf("object index %d out of range", idx)
	}
	off := p.offsets[idx]
	if off >= len(p.data) {
		return nil, fmt.Errorf("object offset out of bounds")
	}
	marker := p.data[off]
	objType := marker >> 4
	info := marker & 0x0F

	switch objType {
	case 0x0:
		switch info {
		case 0x8:
			return boolObj(false), nil
		case 0x9:
			return boolObj(true), nil
		default:
			return globalNullObject(), nil
		}
	case 0x1: // int
		n := 1 << info
		return intObj(int64(beUint(p.slice(off+1, n)))), nil
	case 0x2: // real
		n := 1 << info
		b := p.slice(off+1, n)
		if n == 4 {
			return floatObj(float64(math.Float32frombits(uint32(beUint(b))))), nil
		}
		return floatObj(math.Float64frombits(beUint(b))), nil
	case 0x3: // date (8-byte BE double, seconds since 2001)
		sec := math.Float64frombits(beUint(p.slice(off+1, 8)))
		unix := int64(sec) + cocoaEpochUnix
		return stringObj(time.Unix(unix, 0).UTC().Format(time.RFC3339)), nil
	case 0x4: // data
		count, dataStart := p.readCount(off, int(info))
		return stringObj(string(p.slice(dataStart, count))), nil
	case 0x5: // ASCII string
		count, dataStart := p.readCount(off, int(info))
		return stringObj(string(p.slice(dataStart, count))), nil
	case 0x6: // UTF-16BE string
		count, dataStart := p.readCount(off, int(info))
		return stringObj(decodeUTF16BE(p.slice(dataStart, count*2))), nil
	case 0x8: // UID
		n := int(info) + 1
		return intObj(int64(beUint(p.slice(off+1, n)))), nil
	case 0xA: // array
		count, dataStart := p.readCount(off, int(info))
		elems := make([]object.Object, 0, count)
		for i := 0; i < count; i++ {
			ref := int(beUint(p.slice(dataStart+i*p.refSize, p.refSize)))
			v, err := p.parseObject(ref, depth+1)
			if err != nil {
				return nil, err
			}
			elems = append(elems, v)
		}
		return &object.Array{Elements: elems}, nil
	case 0xD: // dict
		count, dataStart := p.readCount(off, int(info))
		keyBase := dataStart
		valBase := dataStart + count*p.refSize
		pairs := map[string]object.Object{}
		for i := 0; i < count; i++ {
			keyRef := int(beUint(p.slice(keyBase+i*p.refSize, p.refSize)))
			valRef := int(beUint(p.slice(valBase+i*p.refSize, p.refSize)))
			keyObj, err := p.parseObject(keyRef, depth+1)
			if err != nil {
				return nil, err
			}
			valObj, err := p.parseObject(valRef, depth+1)
			if err != nil {
				return nil, err
			}
			keyStr := keyObj.Inspect()
			if s, ok := keyObj.(*object.String); ok {
				keyStr = s.Value
			}
			pairs[keyStr] = valObj
		}
		return makeHashObject(pairs), nil
	default:
		return globalNullObject(), nil
	}
}

// readCount returns the element/byte count and the offset where the payload
// begins. When info==0xF the count is stored as a following int object.
func (p *bplistParser) readCount(off, info int) (int, int) {
	if info != 0xF {
		return info, off + 1
	}
	intMarker := p.data[off+1]
	intBytes := 1 << (intMarker & 0x0F)
	count := int(beUint(p.slice(off+2, intBytes)))
	return count, off + 2 + intBytes
}

func (p *bplistParser) slice(start, length int) []byte {
	if start < 0 || length < 0 || start+length > len(p.data) {
		panic(fmt.Sprintf("binary plist read out of bounds (start=%d len=%d)", start, length))
	}
	return p.data[start : start+length]
}

func beUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

func decodeUTF16BE(b []byte) string {
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.BigEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16))
}
