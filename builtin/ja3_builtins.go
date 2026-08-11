package builtin

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"mutant/object"
)

// JA3 computes the JA3 TLS-client fingerprint from a ClientHello. JA3 hashes a
// comma-joined string of five ClientHello fields — TLS version, cipher suites,
// extensions, supported groups (elliptic curves), and EC point formats — with
// GREASE values (RFC 8701) removed from the cipher/extension/curve lists. The
// input is the raw bytes of a ClientHello, optionally still wrapped in its TLS
// record layer (a leading 0x16 handshake record is unwrapped automatically).
//
// Returns {ja3, ja3_hash, tls_version, ciphers[], extensions[], curves[],
// point_formats[]} paired with an error. Pure-Go, no dependency.
func JA3(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("ja3: panic during parse: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	raw, errObj := requireStringArg("ja3", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	f, err := parseClientHello([]byte(raw))
	if err != nil {
		return resultAndError(nil, newError("ja3: %s", err.Error()))
	}

	ja3Str := fmt.Sprintf("%d,%s,%s,%s,%s",
		f.version,
		joinTLSValues(f.ciphers, true),
		joinTLSValues(f.extensions, true),
		joinTLSValues(f.curves, true),
		joinTLSValues(f.pointFormats, false), // point formats have no GREASE
	)
	sum := md5.Sum([]byte(ja3Str))

	return resultAndError(makeHashObject(map[string]object.Object{
		"ja3":           stringObj(ja3Str),
		"ja3_hash":      stringObj(hex.EncodeToString(sum[:])),
		"tls_version":   intObj(int64(f.version)),
		"ciphers":       tlsValueArray(f.ciphers),
		"extensions":    tlsValueArray(f.extensions),
		"curves":        tlsValueArray(f.curves),
		"point_formats": tlsValueArray(f.pointFormats),
	}), nil)
}

type ja3Fields struct {
	version      uint16
	ciphers      []uint16
	extensions   []uint16
	curves       []uint16
	pointFormats []uint16
}

// isGREASE reports whether a value is a GREASE placeholder (RFC 8701): both bytes
// equal with a low nibble of 0xA (0x0A0A, 0x1A1A, … 0xFAFA).
func isGREASE(v uint16) bool {
	hi, lo := byte(v>>8), byte(v)
	return hi == lo && lo&0x0f == 0x0a
}

func joinTLSValues(vals []uint16, dropGREASE bool) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		if dropGREASE && isGREASE(v) {
			continue
		}
		parts = append(parts, strconv.Itoa(int(v)))
	}
	return strings.Join(parts, "-")
}

func tlsValueArray(vals []uint16) object.Object {
	out := make([]object.Object, len(vals))
	for i, v := range vals {
		out[i] = intObj(int64(v))
	}
	return &object.Array{Elements: out}
}

// parseClientHello decodes the fields JA3 needs from a TLS ClientHello, with
// bounds checks at every step so a truncated/hostile buffer errors rather than
// panics.
func parseClientHello(data []byte) (*ja3Fields, error) {
	p := 0
	// Unwrap a TLS record layer if present: content_type(1)=0x16, version(2), len(2).
	if len(data) >= 5 && data[0] == 0x16 {
		p = 5
	}
	if p+4 > len(data) {
		return nil, fmt.Errorf("truncated handshake header")
	}
	if data[p] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello (handshake type %d)", data[p])
	}
	p += 4 // handshake type (1) + length (3)

	f := &ja3Fields{}
	if p+2 > len(data) {
		return nil, fmt.Errorf("truncated client version")
	}
	f.version = binary.BigEndian.Uint16(data[p:])
	p += 2

	p += 32 // random
	if p > len(data) {
		return nil, fmt.Errorf("truncated random")
	}

	// session_id (1-byte length prefix)
	if p+1 > len(data) {
		return nil, fmt.Errorf("truncated session id")
	}
	p += 1 + int(data[p])
	if p > len(data) {
		return nil, fmt.Errorf("session id overruns buffer")
	}

	// cipher_suites (2-byte length prefix)
	if p+2 > len(data) {
		return nil, fmt.Errorf("truncated cipher suites")
	}
	csLen := int(binary.BigEndian.Uint16(data[p:]))
	p += 2
	if p+csLen > len(data) {
		return nil, fmt.Errorf("cipher suites overrun buffer")
	}
	for i := 0; i+1 < csLen; i += 2 {
		f.ciphers = append(f.ciphers, binary.BigEndian.Uint16(data[p+i:]))
	}
	p += csLen

	// compression_methods (1-byte length prefix)
	if p+1 > len(data) {
		return nil, fmt.Errorf("truncated compression methods")
	}
	p += 1 + int(data[p])
	if p > len(data) {
		return nil, fmt.Errorf("compression methods overrun buffer")
	}

	// extensions are optional (SSLv3/very old clients omit them).
	if p+2 <= len(data) {
		extLen := int(binary.BigEndian.Uint16(data[p:]))
		p += 2
		end := p + extLen
		if end > len(data) {
			end = len(data)
		}
		for p+4 <= end {
			etype := binary.BigEndian.Uint16(data[p:])
			elen := int(binary.BigEndian.Uint16(data[p+2:]))
			p += 4
			if p+elen > end {
				break
			}
			ext := data[p : p+elen]
			f.extensions = append(f.extensions, etype)
			switch etype {
			case 10: // supported_groups (elliptic curves)
				f.curves = append(f.curves, readTLSList16(ext)...)
			case 11: // ec_point_formats
				f.pointFormats = append(f.pointFormats, readTLSList8(ext)...)
			}
			p += elen
		}
	}
	return f, nil
}

// readTLSList16 reads a 2-byte-length-prefixed list of 16-bit values.
func readTLSList16(ext []byte) []uint16 {
	if len(ext) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(ext))
	out := make([]uint16, 0, n/2)
	for i := 2; i+1 < 2+n && i+1 < len(ext); i += 2 {
		out = append(out, binary.BigEndian.Uint16(ext[i:]))
	}
	return out
}

// readTLSList8 reads a 1-byte-length-prefixed list of 8-bit values.
func readTLSList8(ext []byte) []uint16 {
	if len(ext) < 1 {
		return nil
	}
	n := int(ext[0])
	out := make([]uint16, 0, n)
	for i := 1; i < 1+n && i < len(ext); i++ {
		out = append(out, uint16(ext[i]))
	}
	return out
}
