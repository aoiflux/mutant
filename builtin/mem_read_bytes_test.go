package builtin

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"mutant/object"
)

// memReadBytesOf calls mem_read_bytes and asserts it produced a buffer.
func memReadBytesOf(t *testing.T, path string, offset, size int64) []byte {
	t.Helper()

	payload, errObj := unwrapPair(t, MemReadBytes(stringObj(path), intObj(offset), intObj(size)))
	if errObj != nil {
		t.Fatalf("mem_read_bytes error: %s", errObj.Inspect())
	}
	buf, ok := payload.(*object.Bytes)
	if !ok {
		t.Fatalf("mem_read_bytes returned %T, want *object.Bytes", payload)
	}
	return buf.Value
}

// The pair shares one implementation, and this is what says so: the buffer and
// the hex describe the same range, so the two cannot drift apart without a test
// failing. The size field and len() must agree for the same reason -- a caller
// switching to mem_read_bytes loses the field and gets len() instead.
func TestMemReadBytesAgreesWithMemReadHex(t *testing.T) {
	fixture := writeMemFixture(t)

	buf := memReadBytesOf(t, fixture, 0, 8)

	payload, errObj := unwrapPair(t, MemRead(stringObj(fixture), intObj(0), intObj(8)))
	if errObj != nil {
		t.Fatalf("mem_read error: %s", errObj.Inspect())
	}
	h := mfMustHash(t, payload)

	if got, want := hex.EncodeToString(buf), mfMustHashString(t, h, "hex"); got != want {
		t.Errorf("mem_read_bytes = %s, mem_read hex = %s", got, want)
	}
	if got, want := int64(len(buf)), mfMustHashInt(t, h, "size"); got != want {
		t.Errorf("len(buffer) = %d, mem_read size = %d", got, want)
	}
}

// The whole point of the type: the range arrives byte for byte, including bytes
// that are not text. The fixture is checked for that too -- a test that read
// only valid UTF-8 would pass just as well against the old string return, and
// would prove nothing.
func TestMemReadBytesCarriesRawBinary(t *testing.T) {
	fixture := writeMemFixture(t)

	onDisk, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if utf8.Valid(onDisk) {
		t.Fatal("the fixture is valid UTF-8; it cannot exercise the binary case")
	}

	if buf := memReadBytesOf(t, fixture, 0, int64(len(onDisk))); !bytes.Equal(buf, onDisk) {
		t.Errorf("mem_read_bytes returned %x, want %x", buf, onDisk)
	}
}

// A read that runs past the end of the image is not an error; it comes back
// short. mem_read reports that in its size field, mem_read_bytes in its length.
func TestMemReadBytesShortReadAtEndOfImage(t *testing.T) {
	fixture := writeMemFixture(t)

	onDisk, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	start := int64(len(onDisk) - 4)
	buf := memReadBytesOf(t, fixture, start, 4096)

	if len(buf) != 4 {
		t.Errorf("short read returned %d bytes, want 4", len(buf))
	}
	if !bytes.Equal(buf, onDisk[start:]) {
		t.Errorf("short read = %x, want %x", buf, onDisk[start:])
	}
}

// The returned buffer is a copy, not a window onto the image.
//
// This is about retention, not correctness: memRead reads the whole file, so a
// slice of it holds the entire image alive for as long as the script keeps the
// buffer. Reading 16 bytes out of a memory dump is the ordinary case, and dumps
// are measured in gigabytes -- an aliased return would make a small read cost
// the whole file, indefinitely and invisibly.
//
// Capacity is what observes that, because it is the only difference an aliased
// and a copied slice have: the contents are identical either way. The threshold
// is deliberately loose, since append may round a clone's capacity up.
func TestMemReadBytesDoesNotRetainTheImage(t *testing.T) {
	image := make([]byte, 1<<20)
	for i := range image {
		image[i] = byte(i)
	}
	path := filepath.Join(t.TempDir(), "large.bin")
	if err := os.WriteFile(path, image, 0644); err != nil {
		t.Fatalf("write image: %v", err)
	}

	buf := memReadBytesOf(t, path, 0, 16)
	if !bytes.Equal(buf, image[:16]) {
		t.Fatalf("read returned %x, want %x", buf, image[:16])
	}

	if cap(buf) >= len(image) {
		t.Errorf("a %d-byte read has capacity %d, so it still holds the whole %d-byte image",
			len(buf), cap(buf), len(image))
	}
}

// Both builtins run through one function, so the operation name has to be
// threaded rather than baked in -- otherwise mem_read_bytes reports failures
// under the wrong name and the caller goes looking at the wrong call.
func TestMemReadBytesErrorsNameThemselves(t *testing.T) {
	fixture := writeMemFixture(t)

	cases := []struct {
		name string
		args []object.Object
	}{
		{"offset past the end", []object.Object{stringObj(fixture), intObj(1 << 20), intObj(4)}},
		{"negative offset", []object.Object{stringObj(fixture), intObj(-1), intObj(4)}},
		{"missing file", []object.Object{stringObj(fixture + ".absent"), intObj(0), intObj(4)}},
		{"non-integer offset", []object.Object{stringObj(fixture), stringObj("0"), intObj(4)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, errObj := unwrapPair(t, MemReadBytes(tc.args...))
			if errObj == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(errObj.Message, "mem_read_bytes") {
				t.Errorf("error names the wrong builtin: %s", errObj.Message)
			}
		})
	}
}
