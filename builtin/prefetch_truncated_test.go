package builtin

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// mamVector returns the embedded MAM-compressed prefetch vector's payload and
// the uncompressed size its header declares, which is what PrefetchParse passes
// to the decompressor.
func mamVector(t *testing.T) (payload []byte, outSize int) {
	t.Helper()
	mam, err := base64.StdEncoding.DecodeString(pfMAMVectorBase64)
	if err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	if len(mam) < 8 || string(mam[0:3]) != "MAM" {
		t.Fatalf("vector is not a MAM container")
	}
	return mam[8:], int(binary.LittleEndian.Uint32(mam[4:8]))
}

// TestATruncatedXpressStreamIsRefusedRatherThanInvented is M26-ART-028.
//
// xhU16 answers zero past the end of the input rather than refusing, and the
// decode loop ran until it had produced the number of bytes the header declared,
// so a stream cut mid-block refilled its lookahead with zeros and went on
// decoding symbols out of them. The row measured this vector -- 382 bytes
// compressed to 768 -- cut to 366, 319 and 264 bytes: each returned a full 768
// bytes and no error, with 626, 296 and 16 of them right. A carved or partly
// recovered prefetch file produced file names and volume paths that were not in
// it, under a parse that reported success.
//
// Every cut is tried, not the row's three, because the property is what matters
// and it is cheap to state exhaustively: a truncated stream may be refused, and
// it may decode correctly if the cut happens to fall after everything needed,
// but it may never answer with bytes the input does not contain. The three
// figures are checked by name as well, so the row's own measurement is in here.
func TestATruncatedXpressStreamIsRefusedRatherThanInvented(t *testing.T) {
	payload, outSize := mamVector(t)

	whole, err := xpressHuffmanDecompress(payload, outSize)
	if err != nil {
		t.Fatalf("the whole vector must still decode: %v", err)
	}
	if len(whole) != outSize {
		t.Fatalf("the whole vector decoded to %d bytes, want %d", len(whole), outSize)
	}

	invented := 0
	for cut := 1; cut < len(payload); cut++ {
		got, err := xpressHuffmanDecompress(payload[:cut], outSize)
		if err != nil {
			continue
		}
		// Decoding without error is only honest if what came out is what the
		// whole stream says.
		if !bytes.Equal(got, whole) {
			invented++
			if invented <= 3 {
				matching := 0
				for matching < len(got) && matching < len(whole) && got[matching] == whole[matching] {
					matching++
				}
				t.Errorf("cut to %d of %d bytes: no error, %d bytes out, only %d of them right",
					cut, len(payload), len(got), matching)
			}
		}
	}
	if invented > 3 {
		t.Errorf("... and %d further cuts answered with bytes the input does not hold", invented-3)
	}
}

// TestTheRowsOwnThreeCutsAreRefusedByName keeps the measured figures in the
// tree. Each returned a full 768 bytes with no error, with 626, 296 and 16 of
// them correct.
func TestTheRowsOwnThreeCutsAreRefusedByName(t *testing.T) {
	payload, outSize := mamVector(t)
	if len(payload) != 382 {
		t.Skipf("the row's figures are for a 382-byte payload, this vector has %d", len(payload))
	}

	for _, cut := range []int{366, 319, 264} {
		_, err := xpressHuffmanDecompress(payload[:cut], outSize)
		if err == nil {
			t.Errorf("cut to %d bytes was accepted", cut)
			continue
		}
		if !strings.Contains(err.Error(), "truncated") {
			t.Errorf("cut to %d bytes: err = %q, want it to say the stream was truncated", cut, err)
		}
	}
}

// TestAnEmptyStreamIsRefusedBeforeTheTable keeps the first check honest: a
// stream with nothing in it has no 256-byte Huffman table, which is the one
// truncation the decoder always detected.
func TestAnEmptyStreamIsRefusedBeforeTheTable(t *testing.T) {
	_, outSize := mamVector(t)
	if _, err := xpressHuffmanDecompress(nil, outSize); err == nil {
		t.Error("an empty stream was accepted")
	}
}
