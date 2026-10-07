package builtin

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// The shape of a document, measured from its bytes before a library decodes it.
//
// Two decoders here recurse without a bound of their own: BurntSushi/toml
// parses an array or an inline table by calling itself, and msgpack's
// DecodeInterface does the same for arrays and maps. convertNative checks
// maxNativeDepth again, but only on the tree a decoder returns -- after the
// recursion it was meant to bound has already happened, and on a few megabytes
// of '[' that is a fatal stack overflow no recover can catch (M26-DAT-004).
//
// So a document is measured first and refused before the decoder sees it when
// it nests past maxNativeDepth. That refuses nothing that would have converted:
// a document that nests past maxNativeDepth has a value past it, and
// convertNative refuses that value anyway.

// tomlShapeCheck reads a TOML document the way BurntSushi/toml's lexer reads
// it -- the same four kinds of string and the same comments are skipped, so a
// bracket or a dot inside either does not count -- and measures two things.
//
// The depth of arrays and inline tables, because the parser recurses once per
// level. And the number of parts in one dotted key or table name, because the
// parser re-walks the key so far for every part it adds: a 32 KB key of 16,000
// parts took 7.9 s, and twice the parts four times as long. A key with more
// parts than maxNativeDepth names a table that deep, so refusing it is again
// refusing nothing that would have converted.
func tomlShapeCheck(doc string) error {
	var open []byte // '[' for an array, '{' for an inline table, innermost last
	key := true     // reading a key: from the start of a top-level line, or after '{' or ','
	header := false // reading a [table] or [[array of tables]] name
	parts := 1      // parts in the key or name being read
	for i := 0; i < len(doc); {
		switch c := doc[i]; c {
		case '\n', '\r':
			// The lexer refuses a carriage return that no line feed follows, so
			// counting either as the end of a line changes nothing it accepts.
			if len(open) == 0 {
				key, header, parts = true, false, 1
			}
			i++
		case '#':
			for i < len(doc) && doc[i] != '\n' && doc[i] != '\r' {
				i++
			}
		case '"', '\'':
			// A quoted key or table name is a one-line string to the lexer;
			// only a value can open a multi-line one.
			i = tomlSkipString(doc, i, !key && !header)
		case '.':
			if key || header {
				parts++
				if parts > maxNativeDepth {
					return fmt.Errorf("the key at line %d has more than %d dotted parts", tomlLine(doc, i), maxNativeDepth)
				}
			}
			i++
		case '=':
			key = false
			i++
		case '[':
			if key && !header && len(open) == 0 {
				// A table name, [name] or [[name]], at the start of a line.
				header, key, parts = true, false, 1
				i++
				if i < len(doc) && doc[i] == '[' {
					i++
				}
				continue
			}
			open = append(open, '[')
			if len(open) > maxNativeDepth {
				return fmt.Errorf("arrays and inline tables nest more than %d deep at line %d", maxNativeDepth, tomlLine(doc, i))
			}
			key = false
			i++
		case '{':
			open = append(open, '{')
			if len(open) > maxNativeDepth {
				return fmt.Errorf("arrays and inline tables nest more than %d deep at line %d", maxNativeDepth, tomlLine(doc, i))
			}
			key, parts = true, 1
			i++
		case ']', '}':
			if c == ']' && header {
				header = false
				i++
				continue
			}
			if len(open) > 0 {
				open = open[:len(open)-1]
			}
			key = false
			i++
		case ',':
			if len(open) > 0 && open[len(open)-1] == '{' {
				key, parts = true, 1
			}
			i++
		default:
			i++
		}
	}
	return nil
}

// tomlSkipString returns the index just past the string that opens at doc[i],
// closing it where BurntSushi/toml's lexer closes it: a basic string honours a
// backslash escape and a literal one does not, and a multi-line string ends at
// the last three quotes of the first run of three or more. A one-line string
// that reaches a line end is left there, since the lexer refuses it.
func tomlSkipString(doc string, i int, multiLineAllowed bool) int {
	q := doc[i]
	if multiLineAllowed && i+2 < len(doc) && doc[i+1] == q && doc[i+2] == q {
		for j := i + 3; j < len(doc); {
			switch {
			case q == '"' && doc[j] == '\\':
				j += 2
			case doc[j] == q:
				run := 0
				for j < len(doc) && doc[j] == q {
					run++
					j++
				}
				if run >= 3 {
					return j
				}
			default:
				j++
			}
		}
		return len(doc)
	}
	for j := i + 1; j < len(doc); j++ {
		switch doc[j] {
		case '\\':
			if q == '"' {
				j++
			}
		case q:
			return j + 1
		case '\n', '\r':
			return j
		}
	}
	return len(doc)
}

func tomlLine(doc string, i int) int {
	return 1 + strings.Count(doc[:i], "\n")
}

// msgpackShapeCheck walks the first value of a MessagePack document the way
// DecodeInterface will, building nothing, and refuses one that the decoder
// would recurse or allocate its way through before anything could stop it.
//
// Depth, for the reason above. And declared counts: DecodeInterface sizes the
// slice or map for a container from the count in its header before it reads
// a single element, so five bytes declaring an array of 2^32-1 values ask for
// 64 GiB at once. A count larger than the bytes left could hold, or larger
// than the values convertNative would ever convert, is refused here instead.
// Every value takes at least one byte, so a document that passes has its every
// allocation bounded by its own length.
func msgpackShapeCheck(data []byte) error {
	// pending[d] counts the values still to come in the container at depth d;
	// the document itself is the one value at depth 0. budget counts what
	// convertNative counts -- the document, every array element and every map
	// value, but not map keys -- so a document refused for its size here is one
	// convertNative would refuse too.
	pending := []uint64{1}
	budget := uint64(maxNativeNodes) - 1
	pos := 0
	for len(pending) > 0 {
		top := len(pending) - 1
		if pending[top] == 0 {
			pending = pending[:top]
			continue
		}
		pending[top]--
		if top > maxNativeDepth {
			return fmt.Errorf("document nests deeper than %d levels", maxNativeDepth)
		}
		if pos >= len(data) {
			return nil // truncated: the decoder says so
		}
		start := pos
		code := data[pos]
		pos++

		var payload uint64 // bytes after the header that are not values of their own
		var count uint64   // values that follow: two per map entry
		isMap, container := false, false
		switch {
		case code <= 0x7f || code >= 0xe0 || code == 0xc0 || code == 0xc2 || code == 0xc3:
		case code <= 0x8f: // fixmap
			count, isMap, container = 2*uint64(code&0x0f), true, true
		case code <= 0x9f: // fixarray
			count, container = uint64(code&0x0f), true
		case code <= 0xbf: // fixstr
			payload = uint64(code & 0x1f)
		default:
			var ok bool
			switch code {
			case 0xc4, 0xd9: // bin8, str8
				payload, ok = msgpackUint(data, &pos, 1)
			case 0xc5, 0xda: // bin16, str16
				payload, ok = msgpackUint(data, &pos, 2)
			case 0xc6, 0xdb: // bin32, str32
				payload, ok = msgpackUint(data, &pos, 4)
			case 0xc7: // ext8: length, then the type byte
				payload, ok = msgpackUint(data, &pos, 1)
				payload++
			case 0xc8: // ext16
				payload, ok = msgpackUint(data, &pos, 2)
				payload++
			case 0xc9: // ext32
				payload, ok = msgpackUint(data, &pos, 4)
				payload++
			case 0xcc, 0xd0: // uint8, int8
				payload, ok = 1, true
			case 0xcd, 0xd1: // uint16, int16
				payload, ok = 2, true
			case 0xca, 0xce, 0xd2: // float32, uint32, int32
				payload, ok = 4, true
			case 0xcb, 0xcf, 0xd3: // float64, uint64, int64
				payload, ok = 8, true
			case 0xd4, 0xd5, 0xd6, 0xd7, 0xd8: // fixext 1, 2, 4, 8, 16, plus the type byte
				payload, ok = 1+(uint64(1)<<(code-0xd4)), true
			case 0xdc: // array16
				count, ok = msgpackUint(data, &pos, 2)
				container = true
			case 0xdd: // array32
				count, ok = msgpackUint(data, &pos, 4)
				container = true
			case 0xde: // map16
				count, ok = msgpackUint(data, &pos, 2)
				count, isMap, container = 2*count, true, true
			case 0xdf: // map32
				count, ok = msgpackUint(data, &pos, 4)
				count, isMap, container = 2*count, true, true
			default: // 0xc1 is never used; the decoder names it
				return nil
			}
			if !ok {
				return nil // truncated header: the decoder says so
			}
		}

		if container {
			if count > uint64(len(data)-pos) {
				return fmt.Errorf("a container at offset %d declares %d values, but only %d bytes follow it", start, count, len(data)-pos)
			}
			converted := count
			if isMap {
				converted = count / 2
			}
			if converted > budget {
				return fmt.Errorf("document expands past %d values", maxNativeNodes)
			}
			budget -= converted
			pending = append(pending, count)
			continue
		}
		if payload > uint64(len(data)-pos) {
			return nil // truncated payload: the decoder says so
		}
		pos += int(payload)
	}
	return nil
}

// msgpackUint reads an n-byte big-endian length at *pos and moves past it.
func msgpackUint(data []byte, pos *int, n int) (uint64, bool) {
	if len(data)-*pos < n {
		return 0, false
	}
	b := data[*pos : *pos+n]
	*pos += n
	switch n {
	case 1:
		return uint64(b[0]), true
	case 2:
		return uint64(binary.BigEndian.Uint16(b)), true
	default:
		return uint64(binary.BigEndian.Uint32(b)), true
	}
}
