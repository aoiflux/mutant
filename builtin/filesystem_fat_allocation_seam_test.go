package builtin

import (
	"errors"
	"math"
	"testing"
)

// fsCheckClusterRuns at its edges (M26-FS2-004, M26-FS2-017).
func TestTheAllocationMapIsAskedAboutEveryClusterOfARun(t *testing.T) {
	inUse := map[uint64]bool{12: true}
	asked := []uint64{}
	query := func(c uint64) (bool, error) {
		asked = append(asked, c)
		if c == 99 {
			return false, errors.New("the bitmap could not be read")
		}
		return inUse[c], nil
	}

	if got := fsCheckClusterRuns([]fsClusterRun{{First: 3, Count: 4}}, query); !got.Checked || got.Reallocated {
		t.Errorf("a free run: %+v", got)
	}
	if len(asked) != 4 {
		t.Errorf("a four-cluster run asked about %d clusters", len(asked))
	}

	asked = asked[:0]
	got := fsCheckClusterRuns([]fsClusterRun{{First: 10, Count: 2}, {First: 11, Count: 5}}, query)
	if !got.Checked || !got.Reallocated || got.FirstAllocated != 12 {
		t.Errorf("a run reaching cluster 12: %+v", got)
	}
	if asked[len(asked)-1] != 12 {
		t.Errorf("the walk went on past the first cluster in use: %v", asked)
	}

	if got := fsCheckClusterRuns([]fsClusterRun{{First: 98, Count: 3}}, query); got.Checked || got.Reallocated {
		t.Errorf("a run the map could not answer for: %+v", got)
	}
	if got := fsCheckClusterRuns(nil, query); got.Checked {
		t.Errorf("no clusters at all were reported checked")
	}
	if got := fsCheckClusterRuns([]fsClusterRun{{First: 0, Count: 0}}, query); got.Checked {
		t.Errorf("a run of no clusters was reported checked")
	}
	if got := fsCheckClusterRuns([]fsClusterRun{{First: math.MaxUint64 - 1, Count: 3}}, func(uint64) (bool, error) {
		return false, nil
	}); got.Checked {
		t.Errorf("a run whose cluster numbers wrapped was reported checked")
	}
	// A FAT or exFAT run reaching past cluster 2^32-1 asks about a cluster the
	// volume cannot have: unanswered, not free.
	free32 := fsClusters32(func(uint32) (bool, error) { return false, nil })
	if got := fsCheckClusterRuns([]fsClusterRun{{First: math.MaxUint32, Count: 3}}, free32); got.Checked {
		t.Errorf("a 32-bit run past its last cluster was reported checked")
	}
}

// A second sighting folds into the row kept, the directory's winning.
func TestASecondSightingOfARecordFoldsIntoTheFirst(t *testing.T) {
	directory := fsDeletedEntry{Path: "/_LDDIR/_ONE2.TXT", Source: fsDeletedSourceDirectory, EntryOffset: 40032}
	orphan := fsDeletedEntry{Path: "/$OrphanFiles/_ONE2.TXT", Source: fsDeletedSourceOrphanScan, EntryOffset: 40032}

	for _, order := range [][2]fsDeletedEntry{{directory, orphan}, {orphan, directory}} {
		kept, swapped := fsMergeSighting(order[0], order[1])
		if kept.Path != directory.Path || swapped != (order[0].Source != fsDeletedSourceDirectory) {
			t.Errorf("merging %s then %s kept %q (swapped %v)", order[0].Source, order[1].Source, kept.Path, swapped)
		}
		if len(kept.Reasons) != 1 {
			t.Errorf("the merged row carries %d reasons", len(kept.Reasons))
		}
	}

	var s fsSightings
	if index, skip := s.place(fsDeletedEntry{EntryOffset: -1}); index != -1 || skip {
		t.Errorf("a record with no offset was treated as seen")
	}
	s.note(directory, 3)
	if index, skip := s.place(orphan); index != 3 || skip {
		t.Errorf("a second sighting placed at %d (skip %v), want row 3", index, skip)
	}
	s.note(fsDeletedEntry{EntryOffset: 7}, -1)
	if _, skip := s.place(fsDeletedEntry{EntryOffset: 7}); !skip {
		t.Errorf("a repeat of a record past the cap was not skipped")
	}
}
