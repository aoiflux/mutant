package builtin

// The $MFT says how many records it holds, and nothing else does.
//
// libntfs's MFTEntryCount is the total of the $MFT's own data runs divided by
// the record size: read from record 0 and bounded by nothing, so a 64 KiB image
// can declare four billion records. Every walk over the MFT used that count as
// its loop bound -- ntfs_verify's, ntfs_deleted's, and the report's inside
// libntfs -- so how long a call took, and how much memory ntfs_deleted asked
// for before reading anything, was a number the evidence chose rather than a
// property of the evidence.
//
// ntfsPlanMFT works the walk out from where the records are. It takes record
// 0's primary $DATA run list -- the list libntfs maps entry numbers through --
// and replays libntfs's own arithmetic over it, so that entry n here is the
// record libntfs reads for entry n. The declared entry numbers then split three
// ways: records lying wholly inside the image, which are read; records lying
// past its end, or before its start, which are counted and never visited one
// at a time; and records no run places (a sparse run, or past the last run),
// which are counted the same way. A walk therefore costs what reading the
// image's own records costs, however large the declaration.
//
// Record 0 is read through that same mapping, so the mapping is only trusted
// when it puts record 0 where the boot sector does. When it does not -- or the
// run list cannot be read, or its arithmetic overflows -- there is no telling
// which entry numbers the image holds, and the walk is bounded instead by how
// many records the image could hold at all, starting from entry 0, with the
// reason carried on the plan.

import (
	"fmt"
	"io"
	"math"
	"math/bits"

	libntfs "github.com/aoiflux/libntfs"
)

// ntfsMFTRange is a run of consecutive MFT entry numbers.
type ntfsMFTRange struct {
	First uint64
	Count uint64
}

// ntfsMFTPlan is an MFT walk bounded by the image.
type ntfsMFTPlan struct {
	// Declared is MFTEntryCount: what the $MFT's run list claims.
	Declared   uint64
	RecordSize uint64
	ImageEnd   int64

	// Walk holds the entry numbers whose records lie wholly inside the
	// image, in entry order. Walkable is their total.
	Walk     []ntfsMFTRange
	Walkable uint64

	// Outside counts the records the run list places outside the image --
	// past its end, almost always: a truncated acquisition, or a run length
	// nobody wrote. FirstOutside is the lowest such entry number.
	Outside      uint64
	FirstOutside uint64

	// Unplaced counts the records no run places: a sparse run, or entry
	// numbers past the last run.
	Unplaced uint64

	// LayoutKnown is false when the run list could not be trusted, and
	// Reason says why. Walk is then [0, what the image could hold).
	LayoutKnown bool
	Reason      string
}

// unread is how many declared records the walk will not read.
func (p ntfsMFTPlan) unread() uint64 { return p.Outside + p.Unplaced }

// describe says, in one sentence, which declared records are not read. Empty
// when every one of them is.
func (p ntfsMFTPlan) describe() string {
	switch {
	case !p.LayoutKnown:
		return fmt.Sprintf("the $MFT declares %d records, but its layout could not be established (%s), "+
			"so only the first %d -- as many as the image's %d bytes could hold -- were walked",
			p.Declared, p.Reason, p.Walkable, p.ImageEnd)
	case p.Outside > 0 && p.Unplaced > 0:
		return fmt.Sprintf("the $MFT declares %d records: %d of them, from entry %d, lie outside the image, "+
			"which ends at byte %d, and %d are placed by no run, so %d were walked",
			p.Declared, p.Outside, p.FirstOutside, p.ImageEnd, p.Unplaced, p.Walkable)
	case p.Outside > 0:
		return fmt.Sprintf("the $MFT declares %d records: %d of them, from entry %d, lie outside the image, "+
			"which ends at byte %d, so %d were walked",
			p.Declared, p.Outside, p.FirstOutside, p.ImageEnd, p.Walkable)
	case p.Unplaced > 0:
		return fmt.Sprintf("the $MFT declares %d records and %d of them are placed by no run "+
			"(a sparse run, or past the last one), so %d were walked",
			p.Declared, p.Unplaced, p.Walkable)
	}
	return ""
}

// ntfsPlanMFT plans an MFT walk over volume, which was opened over image.
func ntfsPlanMFT(volume *libntfs.Volume, image io.ReaderAt) (ntfsMFTPlan, error) {
	declared, err := volume.MFTEntryCount()
	if err != nil {
		return ntfsMFTPlan{}, err
	}
	extent, err := fsImageExtent(image)
	if err != nil {
		return ntfsMFTPlan{}, err
	}
	plan := ntfsMFTPlan{Declared: declared, RecordSize: uint64(volume.MFTRecordSize()), ImageEnd: extent}
	if plan.RecordSize == 0 {
		return ntfsMFTPlan{}, fmt.Errorf("the volume reports an MFT record size of zero")
	}

	runs, reason := ntfsMFTRuns(volume, declared, plan.RecordSize)
	if reason != "" {
		plan.Reason = reason
		walk := uint64(extent) / plan.RecordSize
		if walk > declared {
			walk = declared
		}
		if walk > 0 {
			plan.Walk = []ntfsMFTRange{{First: 0, Count: walk}}
		}
		plan.Walkable = walk
		plan.Unplaced = declared - walk
		return plan, nil
	}
	plan.LayoutKnown = true

	// libntfs finds entry n in the run holding byte n*recordSize of the
	// stream, and reads the record from there on. So a run owns the entries
	// whose first byte it holds.
	rs := plan.RecordSize
	clusterBytes := uint64(volume.BytesPerCluster())
	ceilDiv := func(a uint64) uint64 {
		if a%rs != 0 {
			return a/rs + 1
		}
		return a / rs
	}
	var runStart uint64
	for _, run := range runs {
		runEnd := runStart + run.LengthClusters*clusterBytes // cannot wrap: ntfsMFTRuns checked
		first, last := ceilDiv(runStart), ceilDiv(runEnd)
		if last > declared {
			last = declared
		}
		runFirstByte := runStart
		runStart = runEnd
		if first >= last {
			continue
		}
		skip := first*rs - runFirstByte // first < declared, so first*rs is inside the total
		n := last - first
		if run.IsSparse {
			plan.Unplaced += n
			continue
		}

		inside := ntfsRecordsInImage(volume.BaseOffset(), run.StartCluster, clusterBytes, skip, rs, n, extent)
		if inside > 0 {
			plan.Walk = append(plan.Walk, ntfsMFTRange{First: first, Count: inside})
			plan.Walkable += inside
		}
		if outside := n - inside; outside > 0 {
			if plan.Outside == 0 {
				plan.FirstOutside = first + inside
			}
			plan.Outside += outside
		}
	}
	if counted := plan.Walkable + plan.Outside + plan.Unplaced; counted < declared {
		plan.Unplaced += declared - counted
	}
	return plan, nil
}

// ntfsMFTRuns returns record 0's primary $DATA run list when it is the list
// libntfs maps entry numbers through, or the reason it cannot be taken to be.
func ntfsMFTRuns(volume *libntfs.Volume, declared, recordSize uint64) ([]libntfs.DataRun, string) {
	record, err := volume.GetMFTEntry(0)
	if err != nil {
		return nil, "record 0, the $MFT's own, could not be read: " + err.Error()
	}
	attr := record.FindPrimaryNonResidentDataAttribute()
	if attr == nil || attr.NonResident == nil || len(attr.NonResident.DataRuns) == 0 {
		return nil, "record 0 carries no non-resident $DATA run list"
	}
	runs := attr.NonResident.DataRuns

	// libntfs read record 0 at the boot sector's MFT cluster when it opened
	// the volume, and reads it through the run list ever after. The two are
	// the same record only if the list starts where the boot sector says.
	if boot := volume.GetBootSector(); boot == nil || runs[0].IsSparse ||
		runs[0].StartCluster < 0 || uint64(runs[0].StartCluster) != boot.MFTCluster {
		return nil, "the $MFT's run list does not start at the cluster the boot sector names"
	}

	clusterBytes := uint64(volume.BytesPerCluster())
	var total uint64
	for _, run := range runs {
		hi, length := bits.Mul64(run.LengthClusters, clusterBytes)
		sum, carry := bits.Add64(total, length, 0)
		if hi != 0 || carry != 0 {
			return nil, "the $MFT's run lengths add up past 2^64 bytes"
		}
		total = sum
	}
	if total/recordSize != declared {
		return nil, fmt.Sprintf("record 0's run list holds %d records and libntfs counts %d",
			total/recordSize, declared)
	}
	return runs, ""
}

// ntfsRecordsInImage is how many of n consecutive records lie wholly inside
// [0, extent), the first starting skip bytes into a run that begins at
// startCluster. Written so that no product or sum can wrap: the cluster
// number and the lengths are the evidence's.
func ntfsRecordsInImage(base, startCluster int64, clusterBytes, skip, recordSize, n uint64, extent int64) uint64 {
	if startCluster < 0 || base < 0 || clusterBytes == 0 {
		return 0
	}
	hi, runStart := bits.Mul64(uint64(startCluster), clusterBytes)
	if hi != 0 || runStart > math.MaxInt64 {
		return 0
	}
	first, carry := bits.Add64(runStart, uint64(base), 0)
	if carry != 0 {
		return 0
	}
	first, carry = bits.Add64(first, skip, 0)
	if carry != 0 || first >= uint64(extent) {
		return 0
	}
	fits := (uint64(extent) - first) / recordSize
	if fits > n {
		return n
	}
	return fits
}
