package builtin

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"

	libntfs "github.com/aoiflux/libntfs"
)

// These run only on the fixed code: on the unfixed code the first would loop
// for hours and the third would abort the test binary with an out-of-memory
// error no recover() catches (M26-FS1-006, M26-FS2-003).

// A billion declared records over 128 KiB of image cost what reading the image
// costs, in verify, in the deleted scan and in the report's refusal.
func TestABillionDeclaredMFTRecordsCostWhatTheImageCosts(t *testing.T) {
	handle := openNTFSVolume(t, buildNTFSVolume(0x0FFFFFFF))

	for name, call := range map[string]func(){
		"ntfs_verify":  func() { NtfsVerify(handle) },
		"ntfs_deleted": func() { NtfsDeleted(handle) },
		"ntfs_report":  func() { NtfsReport(handle) },
	} {
		start := time.Now()
		call()
		// A walk of the declared count measured 1.6 s per 262,144 records;
		// a billion would be hours. What is left is milliseconds.
		if took := time.Since(start); took > 10*time.Second {
			t.Errorf("%s took %v over a billion declared records", name, took)
		}
	}
}

// The plan itself, on the same volume: 112 records walked, the rest named.
func TestThePlanWalksOnlyTheRecordsTheImageHolds(t *testing.T) {
	image := buildNTFSVolume(0x4000)
	volume, err := libntfs.OpenWithOptions(bytes.NewReader(image), libntfs.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ntfsPlanMFT(volume, bytes.NewReader(image))
	if err != nil {
		t.Fatal(err)
	}
	inImage := uint64((ntfsVolClusters - ntfsVolMFTCluster) * ntfsVolClusterSize / ntfsVolRecordSize)
	if !plan.LayoutKnown || plan.Declared != 65536 || plan.Walkable != inImage ||
		plan.Outside != 65536-inImage || plan.FirstOutside != inImage || plan.Unplaced != 0 {
		t.Fatalf("plan = %+v; want 65536 declared, %d walked, the rest outside from entry %d", plan, inImage, inImage)
	}
	if len(plan.Walk) != 1 || plan.Walk[0] != (ntfsMFTRange{First: 0, Count: inImage}) {
		t.Fatalf("walk = %+v", plan.Walk)
	}
}

// When record 0's run list does not start where the boot sector puts the
// $MFT, entry numbers cannot be mapped to the image, and the walk falls back to
// as many records as the image could hold -- saying so.
func TestAnMFTWhoseLayoutCannotBeTrustedIsBoundedByTheImage(t *testing.T) {
	image := buildNTFSVolume(2)
	// Point record 0's run one cluster on: libntfs opened the volume from the
	// boot sector's cluster and maps every later lookup through the run.
	record := image[ntfsVolMFTCluster*ntfsVolClusterSize : ntfsVolMFTCluster*ntfsVolClusterSize+ntfsVolRecordSize]
	replacement := ntfsVolRecord(libntfs.MFTFlagInUse, "$MFT", 5, 0,
		ntfsVolData(ntfsVolMFTCluster+1, 0x4000, 0x4000*ntfsVolClusterSize))
	copy(record, replacement)

	volume, err := libntfs.OpenWithOptions(bytes.NewReader(image), libntfs.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ntfsPlanMFT(volume, bytes.NewReader(image))
	if err != nil {
		t.Fatal(err)
	}
	if plan.LayoutKnown || plan.Reason == "" {
		t.Fatalf("a run list starting off the boot sector's cluster was trusted: %+v", plan)
	}
	if want := uint64(len(image) / ntfsVolRecordSize); plan.Walkable != want {
		t.Fatalf("walked %d records, want the %d the image could hold", plan.Walkable, want)
	}
	if !strings.Contains(plan.describe(), "could not be established") {
		t.Fatalf("describe() = %q", plan.describe())
	}
}

// The arithmetic with the evidence's numbers at their worst.
func TestRecordsInImageNeverWraps(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		base, cluster         int64
		clusterBytes, skip, n uint64
		extent                int64
		want                  uint64
	}{
		{"inside", 0, 4, 4096, 0, 8, 1 << 20, 8},
		{"straddling the end", 0, 4, 4096, 0, 8, 4*4096 + 3*1024 + 512, 3},
		{"past the end", 0, 400, 4096, 0, 8, 1 << 20, 0},
		{"at a base offset", 1 << 20, 4, 4096, 0, 8, 1<<20 + 4*4096 + 2*1024, 2},
		{"a negative cluster", 0, -1, 4096, 0, 8, 1 << 20, 0},
		{"a cluster whose offset wraps", 0, math.MaxInt64 / 2, 4096, 0, 8, 1 << 20, 0},
		{"a skip past the end", 0, 4, 4096, math.MaxUint64 - 10, 8, 1 << 20, 0},
		{"no image", 0, 0, 4096, 0, 8, 0, 0},
	} {
		got := ntfsRecordsInImage(tc.base, tc.cluster, tc.clusterBytes, tc.skip, 1024, tc.n, tc.extent)
		if got != tc.want {
			t.Errorf("%s: %d records in the image, want %d", tc.name, got, tc.want)
		}
	}
}
