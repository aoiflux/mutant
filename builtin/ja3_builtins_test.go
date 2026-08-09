package builtin

import (
	"crypto/md5"
	"encoding/hex"
	"testing"

	"mutant/object"
)

// buildClientHello assembles a ClientHello with a GREASE value in the cipher,
// extension, and curve lists so the JA3 string's GREASE filtering is exercised.
func buildClientHello() []byte {
	var body []byte
	body = append(body, 0x03, 0x03)          // client_version = 771 (TLS 1.2)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id length 0

	ciphers := []byte{0x0a, 0x0a, 0x13, 0x01, 0xc0, 0x2b} // GREASE, 4865, 49195
	body = append(body, byte(len(ciphers)>>8), byte(len(ciphers)))
	body = append(body, ciphers...)

	body = append(body, 0x01, 0x00) // compression_methods: [null]

	var exts []byte
	exts = append(exts, 0x0a, 0x0a, 0x00, 0x00)                           // GREASE extension
	groups := []byte{0x00, 0x06, 0x0a, 0x0a, 0x00, 0x1d, 0x00, 0x17}      // GREASE, 29, 23
	exts = append(exts, 0x00, 0x0a, byte(len(groups)>>8), byte(len(groups)))
	exts = append(exts, groups...)
	formats := []byte{0x01, 0x00} // one point format: uncompressed (0)
	exts = append(exts, 0x00, 0x0b, byte(len(formats)>>8), byte(len(formats)))
	exts = append(exts, formats...)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

func TestJA3(t *testing.T) {
	const wantStr = "771,4865-49195,10-11,29-23,0"
	wantHash := md5.Sum([]byte(wantStr))

	payload, errObj := unwrapPair(t, JA3(stringObj(string(buildClientHello()))))
	if errObj != nil {
		t.Fatalf("ja3 error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)
	if got := hStr(t, h, "ja3"); got != wantStr {
		t.Fatalf("ja3 = %q, want %q", got, wantStr)
	}
	if got := hStr(t, h, "ja3_hash"); got != hex.EncodeToString(wantHash[:]) {
		t.Errorf("ja3_hash = %q, want %q", got, hex.EncodeToString(wantHash[:]))
	}
	if got := hInt(t, h, "tls_version"); got != 771 {
		t.Errorf("tls_version = %d, want 771", got)
	}
	// The decoded arrays are raw (GREASE included) for full visibility.
	if got := len(hashValueByKey(h, "ciphers").(*object.Array).Elements); got != 3 {
		t.Errorf("ciphers len = %d, want 3 (raw, incl GREASE)", got)
	}
	curves := hashValueByKey(h, "curves").(*object.Array)
	if len(curves.Elements) != 3 || curves.Elements[1].(*object.Integer).Value != 29 {
		t.Errorf("curves = %s", curves.Inspect())
	}
}

func TestJA3WithRecordLayer(t *testing.T) {
	hello := buildClientHello()
	// Wrap in a TLS record: content_type=0x16, version, length.
	rec := []byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}
	rec = append(rec, hello...)

	payload, errObj := unwrapPair(t, JA3(stringObj(string(rec))))
	if errObj != nil {
		t.Fatalf("ja3 (record-wrapped) error: %s", errObj.Inspect())
	}
	if got := hStr(t, payload.(*object.Hash), "ja3"); got != "771,4865-49195,10-11,29-23,0" {
		t.Errorf("record-wrapped ja3 = %q", got)
	}
}

func TestJA3Errors(t *testing.T) {
	// Not a ClientHello (handshake type 2 = ServerHello).
	if _, e := unwrapPair(t, JA3(stringObj("\x02\x00\x00\x00"))); e == nil {
		t.Error("expected error for a non-ClientHello handshake")
	}
	// Truncated.
	if _, e := unwrapPair(t, JA3(stringObj("\x01\x00"))); e == nil {
		t.Error("expected error for a truncated ClientHello")
	}
	// Wrong arg count.
	if _, e := unwrapPair(t, JA3()); e == nil {
		t.Error("expected arg-count error")
	}
}
