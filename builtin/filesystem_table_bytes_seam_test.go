package builtin

import (
	"math"
	"testing"
)

// The checked arithmetic M26-FS1-002 replaced libtable's with, at the edges.
func TestATableNumberThatDoesNotFitReadsMinusOne(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		offset                uint64
		block                 uint32
		startLBA, lengthLBA   uint64
		wantStart, wantLength int64
	}{
		{"an ordinary entry", 0, 512, 2048, 4096, 2048 * 512, 4096 * 512},
		{"a table at an offset", 1 << 20, 512, 2048, 4096, 1<<20 + 2048*512, 4096 * 512},
		{"a start that wraps 2^64", 0, 512, 1<<55 + 2048, 4096, -1, 4096 * 512},
		{"a start past 2^63", 0, 512, 1 << 54, 1, -1, 512},
		{"an offset that carries the start over", math.MaxUint64 - 100, 512, 1, 1, -1, 512},
		{"a length that wraps", 0, 512, 2048, 1 << 56, 2048 * 512, -1},
		{"a length past 2^63", 0, 4096, 2048, 1 << 52, 2048 * 4096, -1},
	} {
		start, length := tableByteRange(tc.offset, tc.block, tc.startLBA, tc.lengthLBA)
		if start != tc.wantStart || length != tc.wantLength {
			t.Errorf("%s: (%d, %d), want (%d, %d)", tc.name, start, length, tc.wantStart, tc.wantLength)
		}
	}

	for _, tc := range []struct {
		start, length uint64
		want          int64
	}{
		{2048, 4096, 6143},
		{2048, 0, 2048},
		{math.MaxUint64, 2, -1},
		{1 << 63, 1, -1},
		{math.MaxInt64, 1, math.MaxInt64},
	} {
		if got := endLBA(tc.start, tc.length); got != tc.want {
			t.Errorf("endLBA(%d, %d) = %d, want %d", tc.start, tc.length, got, tc.want)
		}
	}
}

// validateFSRegion refuses a region whose end is not an offset (M26-FS1-014).
func TestARegionsEndMustBeAnOffset(t *testing.T) {
	if errObj := validateFSRegion("t", fsRegion{Offset: 4096, Length: math.MaxInt64}); errObj == nil {
		t.Fatal("a region ending past 2^63-1 was accepted")
	}
	if errObj := validateFSRegion("t", fsRegion{Offset: 4096, Length: math.MaxInt64 - 4096}); errObj != nil {
		t.Fatalf("a region ending exactly at 2^63-1 was refused: %s", errObj.Message)
	}
}
