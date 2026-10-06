package builtin

import (
	"runtime"
	"testing"
)

// Several parsers here are bounded by what a file holds rather than by what its
// header claims, and the tests that hold them to it measure allocation. Those
// measurements have to be about the parser and not about everything else
// running in the process, and an absolute figure is not.
//
// runtime.MemStats.TotalAlloc is process-wide and cumulative: everything
// allocated between the two readings lands in the difference, by any goroutine
// and by the runtime itself. Against bounds as small as 1 MiB that was 0.6 to
// 2 MB of other people's memory, so six of these tests passed when run alone
// and failed in a full `go test ./builtin`. That is the worst way for a test to
// fail, because a gate that is red on a correct tree teaches people to ignore
// red, and three staged fixes could not be gated at all while it was.
//
// allocationGap is the measurement that survives it. It runs the same parse
// twice -- once over a fixture whose header declares a small count, once over
// one declaring an enormous count, with the same bytes behind both -- and
// reports the difference. Two things make that honest where the absolute figure
// was not:
//
//   - The difference cancels the parse's own cost. The question these tests ask
//     is not how much a parse allocates, but whether the declared count decides
//     it, and the difference is that question with nothing else left in it.
//   - Contamination can only ever add, so the lowest of several readings carries
//     the least of it. The answer is a floor and not an average, because the
//     average of a contaminated sample is contaminated.
//
// What remains in the figure is the fixtures' own difference in size, which for
// these is a few bytes of header, and whatever noise survived being minimised.

// allowedGap is what an enormous declared count may cost over a small one.
//
// It is far above the noise the differential leaves and far below what sizing
// by the header takes: these parsers asked for 128 MiB, 256 MiB and 900 MiB on
// the fixtures below, so the bound separates a correct parser from a header-led
// one by more than an order of magnitude in both directions. A parser that
// allocates per declared entry cannot slip under it, and a correct one cannot
// be pushed over it by whatever else the package is doing.
const allowedGap = 4 << 20

// allocationAttempts is how many gaps are measured before the lowest is taken.
// Each attempt is two parses of fixtures built once beforehand, and these
// fixtures are tens of bytes, so the whole measurement is microseconds.
const allocationAttempts = 5

// allocatedBy reports how many bytes fn allocated.
//
// This is the raw reading, with every other goroutine's allocation still in it.
// It is exported from this file only because allocationGap is built on it;
// anything asserting a bound should use allocationGap or requireNoAllocationGap
// instead, and should read the note above first.
func allocatedBy(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// allocationGap reports the least that huge allocated over small across several
// attempts, and zero when huge never once allocated more.
func allocationGap(small, huge func()) uint64 {
	gap := ^uint64(0)
	for i := 0; i < allocationAttempts; i++ {
		taken := allocatedBy(small)
		claimed := allocatedBy(huge)
		if claimed <= taken {
			return 0
		}
		if difference := claimed - taken; difference < gap {
			gap = difference
		}
	}
	return gap
}

// requireNoAllocationGap fails the test when a header's enormous count bought
// memory, and names what was measured. The failure carries the gap itself,
// because a bound that only says it was exceeded leaves the next reader to
// rerun the test to find out by how much -- and the difference between a few
// megabytes of surviving noise and a hundred megabytes of header-sized
// allocation is the whole diagnosis.
func requireNoAllocationGap(t *testing.T, what string, small, huge func()) {
	t.Helper()
	if gap := allocationGap(small, huge); gap > allowedGap {
		t.Errorf("%s allocated %d bytes more for an enormous declared count than for a small "+
			"one, over the %d-byte allowance: the count is still deciding the size",
			what, gap, allowedGap)
	}
}
