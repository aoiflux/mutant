package object

import (
	"strings"
	"testing"
)

// Inspect is lossless on purpose. It doubles as the identity function for
// equality in both engines, for unique's dedup key, for contains and index_of,
// and for hash-key ordering, so a preview would silently make two distinct
// buffers compare equal in six places at once.
func TestBytesInspectIsCompleteHex(t *testing.T) {
	buf := &Bytes{Value: []byte{0x4d, 0x5a, 0x90, 0x00, 0xff}}

	if got := buf.Inspect(); got != "4d5a9000ff" {
		t.Errorf("Inspect() = %q, want %q", got, "4d5a9000ff")
	}
	if got := (&Bytes{}).Inspect(); got != "" {
		t.Errorf("empty buffer rendered as %q, want empty", got)
	}

	// Every byte survives the rendering; nothing is elided at any length.
	long := &Bytes{Value: make([]byte, 4096)}
	if got := len(long.Inspect()); got != 8192 {
		t.Errorf("a 4096-byte buffer rendered %d hex characters, want 8192", got)
	}
}

// Two buffers with the same prefix must not collide, which is exactly what a
// truncated render would have caused.
func TestBytesSharingAPrefixRenderDifferently(t *testing.T) {
	head := strings.Repeat("\x00", 64)
	a := &Bytes{Value: []byte(head + "a")}
	b := &Bytes{Value: []byte(head + "b")}

	if a.Inspect() == b.Inspect() {
		t.Error("two buffers differing only past a long common prefix rendered alike")
	}
}

// A buffer and the string spelling its hex must not share a hash slot: the key
// carries the type, so the two keyspaces are disjoint without any extra work.
func TestBytesHashKeyIsDisjointFromString(t *testing.T) {
	buf := &Bytes{Value: []byte{0x4d, 0x5a}}
	text := &String{Value: "4d5a"}

	if buf.HashKey() == text.HashKey() {
		t.Error("a buffer and the string of its hex collide as hash keys")
	}
	if buf.HashKey() != (&Bytes{Value: []byte{0x4d, 0x5a}}).HashKey() {
		t.Error("two equal buffers produced different hash keys")
	}
	if buf.HashKey().Type != BYTES_OBJ {
		t.Errorf("hash key type = %q, want %q", buf.HashKey().Type, BYTES_OBJ)
	}
}

// Preview is what the traceback uses: it must never materialise the whole
// buffer, and it must say how much it is not showing.
func TestBytesPreviewIsBoundedAndReportsLength(t *testing.T) {
	buf := &Bytes{Value: make([]byte, 4096)}

	preview := buf.Preview(8)
	if !strings.HasPrefix(preview, "bytes(4096)") {
		t.Errorf("preview does not report the length: %q", preview)
	}
	if !strings.HasSuffix(preview, "...") {
		t.Errorf("preview does not mark the elision: %q", preview)
	}
	if len(preview) > 40 {
		t.Errorf("preview of a 4096-byte buffer is %d characters: %q", len(preview), preview)
	}

	short := &Bytes{Value: []byte{0x4d, 0x5a}}
	if got := short.Preview(8); got != "bytes(2) 4d5a" {
		t.Errorf("Preview of a short buffer = %q, want %q", got, "bytes(2) 4d5a")
	}
}

// This is the difference the type makes to key material. The String path
// zeroes a copy Go makes at the conversion and has always been a no-op; a
// []byte can actually be cleared.
func TestBytesZeroWipesTheBackingArray(t *testing.T) {
	payload := []byte("super-secret-key")
	buf := &Bytes{Value: payload}

	buf.Zero()

	if buf.Value != nil {
		t.Errorf("Zero left the slice in place: %v", buf.Value)
	}
	for i, b := range payload {
		if b != 0 {
			t.Fatalf("byte %d of the backing array survived Zero: %q", i, payload)
		}
	}

	// A nil receiver and an empty buffer must both be survivable.
	(*Bytes)(nil).Zero()
	(&Bytes{}).Zero()
}

func TestBytesOrdersBeforeItsHashIsPrinted(t *testing.T) {
	a := &Bytes{Value: []byte{0x01}}
	b := &Bytes{Value: []byte{0x02}}

	if !hashKeyLess(a, b) || hashKeyLess(b, a) {
		t.Error("buffers do not order by content")
	}
}
