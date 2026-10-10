package builtin

// The arithmetic behind the exFAT report's partition_offset field.
//
// xfatPartitionOffset is where the number that used to refuse an open now gets
// reported instead (M26-FS1-020), and both of its guards are unreachable from
// any image in the corpus: a volume would have to record a partition offset of
// more than 2^63 sectors, or one whose product with the sector size does not
// fit. That is exactly why they are tested here rather than left to a corpus
// run. Skipping libxfat's cross-check for a bare volume image also skips the
// representability check that lived inside it, so this is the only thing
// standing between a hostile boot record and a negative sector count in a
// report an examiner reads.

import (
	"math"
	"testing"
)

func TestXfatPartitionOffsetReportsAgreementAndGuardsItsArithmetic(t *testing.T) {
	for _, tc := range []struct {
		name        string
		recorded    uint64
		sectorSize  int
		base        int64
		wantSectors int64
		wantAgrees  bool
		why         string
	}{
		{
			name:     "a volume that records nothing and was opened at zero agrees",
			recorded: 0, sectorSize: 512, base: 0,
			wantSectors: 0, wantAgrees: true,
			why: "the commonest whole-image case, and the one where no warning should fire",
		},
		{
			name:     "a volume opened at the byte it names agrees",
			recorded: 2048, sectorSize: 512, base: 1048576,
			wantSectors: 2048, wantAgrees: true,
			why: "a partition hash from table_list_partitions puts the volume where it says it is",
		},
		{
			name:     "the corpus case: records sector 2048, opened at byte 0",
			recorded: 2048, sectorSize: 512, base: 0,
			wantSectors: 2048, wantAgrees: false,
			why: "img1_exfat.dd, and the reason this function exists at all",
		},
		{
			name:     "a 4 KiB-sector volume is compared in bytes and not in sectors",
			recorded: 2048, sectorSize: 4096, base: 8388608,
			wantSectors: 2048, wantAgrees: true,
			why: "2048 sectors of 4096 is 8388608, so comparing sector counts would be wrong here",
		},
		{
			name:     "a recorded offset wider than an int64 is not reported as a number",
			recorded: math.MaxUint64, sectorSize: 512, base: 0,
			wantSectors: -1, wantAgrees: false,
			why: "int64(math.MaxUint64) is -1, and a negative sector count in a report is a lie",
		},
		{
			name:     "a product that overflows int64 but not uint64 does not agree",
			recorded: 1 << 54, sectorSize: 512, base: 0,
			wantSectors: 1 << 54, wantAgrees: false,
			why: "2^54 sectors of 512 is 2^63, which fits in a uint64 and not in an int64",
		},
		{
			name:     "a product that overflows uint64 does not agree",
			recorded: 1 << 60, sectorSize: 4096, base: 0,
			wantSectors: 1 << 60, wantAgrees: false,
			why: "2^60 times 2^12 is 2^72, so bits.Mul64's high word is what catches it",
		},
		{
			name:     "a volume reporting no sector size cannot be compared",
			recorded: 2048, sectorSize: 0, base: 0,
			wantSectors: 2048, wantAgrees: false,
			why: "the recorded value still travels; what cannot be done is the multiplication",
		},
		{
			name:     "a negative base cannot be agreed with",
			recorded: 0, sectorSize: 512, base: -1,
			wantSectors: 0, wantAgrees: false,
			why: "nothing should produce this, and agreeing with it would hide whatever did",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sectors, agrees := xfatPartitionOffset(tc.recorded, tc.sectorSize, tc.base)
			if sectors != tc.wantSectors {
				t.Errorf("sectors = %d, want %d (%s)", sectors, tc.wantSectors, tc.why)
			}
			if agrees != tc.wantAgrees {
				t.Errorf("agrees = %v, want %v (%s)", agrees, tc.wantAgrees, tc.why)
			}
			if sectors < 0 && sectors != -1 {
				t.Errorf("sectors = %d: the only negative this may return is -1, following fsVolumeEnd", sectors)
			}
		})
	}
}
