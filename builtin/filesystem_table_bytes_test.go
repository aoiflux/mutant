package builtin

import (
	"math"
	"strings"
	"testing"

	"mutant/object"
)

// TestACraftedGPTEntryNamesNoOtherPartitionsBytes is M26-FS1-002's regression
// test. libtable computes an entry's byte offset as table offset + LBA * block
// size with no overflow check, so an entry at LBA 2^55+2048 -- 2^55 * 512 is
// 2^64 -- came back at byte 1048576, the real partition's start. Its hash then
// opened the real volume under the crafted entry's identity, and a gap row the
// listing derived from it reported a negative length.
func TestACraftedGPTEntryNamesNoOtherPartitionsBytes(t *testing.T) {
	const basicData = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
	const wrap = uint64(1) << 55
	disk := buildTestGPTImage(t, testGPTOpts{
		Sectors: 16384,
		Entries: []testGPTEntry{
			{TypeGUID: basicData, Name: "real", StartLBA: 2048, EndLBA: 2048 + 5119},
			{TypeGUID: basicData, Name: "crafted", StartLBA: wrap + 2048, EndLBA: wrap + 2048 + 5119},
		},
	})
	copy(disk[2048*512:], buildFAT16Image(t, 2, 0))
	path := writeTableImage(t, "wrap.img", disk)

	info := tableOpenImage(t, TableOpen, stringObj(path))
	var crafted *object.Hash
	for _, row := range tablePartitionsOf(t, mustHashStringValue(t, info, "handle")) {
		for _, field := range []string{"start_byte", "length_byte", "start_lba", "length_lba", "end_lba"} {
			if v := mustHashIntValue(t, row, field); v < -1 {
				t.Errorf("row %s reports %s = %d, a number that wrapped", row.Inspect(), field, v)
			}
		}
		if mustHashStringValue(t, row, "name") == "crafted" {
			crafted = row
		}
	}
	if crafted == nil {
		t.Fatal("the listing has no crafted row")
	}
	if got := mustHashIntValue(t, crafted, "start_byte"); got == 2048*512 {
		t.Errorf("the crafted entry reports start_byte %d, the real partition's", got)
	}

	if payload, errObj := unwrapPairNoFatal(FatOpen(stringObj(path), crafted)); errObj == nil {
		handle := mustHashValue(t, payload.(*object.Hash), "handle")
		FatClose(handle)
		t.Fatalf("fat_open on the crafted entry opened a volume: %s", payload.Inspect())
	} else if !strings.Contains(errObj.Message, "does not fit a byte offset") {
		t.Errorf("the refusal does not say why: %s", errObj.Message)
	}
}

// TestARegionThatWouldEndPastAnyOffsetIsRefused is M26-FS1-014's regression
// test. offset + length wrapped to a negative end, which the "runs past the
// image" check then passed, and the section reader built from it saturated to
// unbounded: the open succeeded and said bounded:true over a length of 2^63-1.
func TestARegionThatWouldEndPastAnyOffsetIsRefused(t *testing.T) {
	path := embedVolume(t, buildFAT16Image(t, 2, 0), 4096, 4096)

	payload, errObj := unwrapPairNoFatal(FatOpen(stringObj(path), intObj(4096), intObj(math.MaxInt64)))
	if errObj == nil {
		FatClose(mustHashValue(t, payload.(*object.Hash), "handle"))
		t.Fatalf("fat_open(4096, MaxInt64) opened: %s", payload.Inspect())
	}
	// The same length from offset zero was always refused; the two now agree.
	if _, errObj := unwrapPairNoFatal(FatOpen(stringObj(path), intObj(0), intObj(math.MaxInt64))); errObj == nil {
		t.Fatalf("fat_open(0, MaxInt64) opened")
	}
}
