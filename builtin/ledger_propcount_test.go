package builtin

// M26-CUS-030. ledgerDecodeProperties pre-sized its map from the entry count
// the blob declares. A msgpack map32 header is five bytes and can claim
// 2^32-1 entries, so a stored property blob with no body at all made Go
// allocate buckets for four billion of them -- measured at about 96 bytes per
// declared entry, so somewhere near 400 GB -- and the process died on a fatal
// runtime out-of-memory rather than returning an error a script could catch.
//
// The old code did reach an error. It reached it after allocating, which is
// why the test that matters here is the one that measures the refusal rather
// than the one that checks it happened.
//
// Forensic input is hostile by definition, and a ledger is opened from a store
// the examiner may have been handed.

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// ledgerMap32Header is the five bytes a hostile property blob needs: the
// msgpack map32 tag, then a big-endian entry count and no body at all.
func ledgerMap32Header(count uint32) []byte {
	b := make([]byte, 5)
	b[0] = 0xdf
	binary.BigEndian.PutUint32(b[1:], count)
	return b
}

// TestAPropertyBlobCannotDeclareMoreEntriesThanItHolds is the fix: the blob
// bounds its own header, so a declared count is checked against the bytes
// behind it before anything is sized from it.
func TestAPropertyBlobCannotDeclareMoreEntriesThanItHolds(t *testing.T) {
	for _, declared := range []uint32{1 << 10, 1 << 16, 1 << 20} {
		blob := ledgerMap32Header(declared)

		props, err := ledgerDecodeProperties(blob)
		if err == nil {
			t.Fatalf("a %d-byte blob declaring %d entries was accepted, giving %d properties",
				len(blob), declared, len(props))
		}
		for _, want := range []string{"declares", "cannot hold"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not say %q, so it does not say what is wrong:\n%s",
					want, err.Error())
			}
		}
	}
}

// TestRefusingAPropertyBlobCostsNothing is the half that carries the fix. A
// refusal that allocates first is not one: before this change, a blob
// declaring 1<<20 entries grew the heap by 100,757,760 bytes and *then*
// returned an error.
//
// The measurement is against the same five bytes declaring one entry instead of
// 2^20. One is refused for the same reason 2^20 is -- there is no body at all --
// so both measurements are of the same refusal and the difference between them
// is the cost of the number and nothing else. See allocation_gap_test.go for
// why the absolute figure this asserted until 2026-10-06 could not survive a
// full run of this package.
func TestRefusingAPropertyBlobCostsNothing(t *testing.T) {
	const declared = 1 << 20

	honest, claimed := ledgerMap32Header(1), ledgerMap32Header(declared)

	var honestErr, err error
	requireNoAllocationGap(t, "refusing a five-byte blob that declares 2^20 entries",
		func() { _, honestErr = ledgerDecodeProperties(honest) },
		func() { _, err = ledgerDecodeProperties(claimed) })
	if honestErr == nil {
		t.Fatal("the twin declaring one entry was accepted, so the two measurements are not " +
			"of the same refusal and the difference between them says nothing")
	}
	if err == nil {
		t.Fatalf("a five-byte blob declaring %d entries was accepted", declared)
	}
}

// TestAFiveByteBlobDeclaringFourBillionEntriesIsRefused is the row's own case,
// at full size.
//
// Do not run this against the unfixed code. There, make(map, count) asks for
// something near 400 GB, and a fatal runtime out-of-memory does not fail a
// test binary -- it takes the machine with it.
func TestAFiveByteBlobDeclaringFourBillionEntriesIsRefused(t *testing.T) {
	blob := ledgerMap32Header(0xFFFFFFFF)

	props, err := ledgerDecodeProperties(blob)
	if err == nil {
		t.Fatalf("five bytes declaring 4294967295 entries was accepted, giving %d properties",
			len(props))
	}
	if !strings.Contains(err.Error(), "4294967295") {
		t.Errorf("the refusal does not name the count it refused:\n%s", err.Error())
	}
}

// TestAnHonestPropertyBlobStillDecodes keeps this a bug fix rather than a new
// refusal. The bound has to pass every blob the encoder can actually write,
// including the densest one: a short key and an empty value is three bytes an
// entry against the two the bound allows, so a real blob has room to spare.
func TestAnHonestPropertyBlobStillDecodes(t *testing.T) {
	cases := []struct {
		name  string
		props map[string][]byte
	}{
		{"one ordinary property", map[string][]byte{"actor": []byte("examiner-1")}},
		{"an empty value", map[string][]byte{"k": {}}},
		{"a value that is valid UTF-8 beside one that is not",
			map[string][]byte{"text": []byte("hello"), "raw": {0xff, 0xfe, 0x00}}},
	}

	// The densest blob the encoder writes: many one-character keys, all empty.
	dense := map[string][]byte{}
	for c := byte('a'); c <= 'z'; c++ {
		dense[string([]byte{c})] = []byte{}
	}
	cases = append(cases, struct {
		name  string
		props map[string][]byte
	}{"the densest blob the encoder can write", dense})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blob, err := ledgerPropertyBlob(c.props)
			if err != nil {
				t.Fatalf("encoding: %v", err)
			}

			back, err := ledgerDecodeProperties(blob)
			if err != nil {
				t.Fatalf("a blob this encoder wrote was refused: %v (%d entries in %d bytes)",
					err, len(c.props), len(blob))
			}
			if len(back) != len(c.props) {
				t.Fatalf("decoded %d properties, want %d", len(back), len(c.props))
			}
			for key, want := range c.props {
				got, ok := back[key]
				if !ok {
					t.Errorf("%q did not come back", key)
					continue
				}
				if !bytes.Equal(got, want) {
					t.Errorf("%q came back as %v, want %v", key, got, want)
				}
			}
		})
	}
}
