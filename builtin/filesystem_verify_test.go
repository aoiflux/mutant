package builtin

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	libext "github.com/aoiflux/libext"
	libfat "github.com/aoiflux/libfat"

	"mutant/object"
)

// The verdict rule is the whole contract, so it is pinned on its own rather
// than only through the six builtins that apply it.
func TestVerifiedNeedsACheckToHaveRun(t *testing.T) {
	cases := []struct {
		name   string
		checks []fsVerifyCheck
		want   bool
	}{
		{
			// The case that motivates the rule. HFS+ has no checksums, so
			// every check is unavailable. Reporting that as verified would
			// assert something the format cannot support.
			"nothing could be checked",
			[]fsVerifyCheck{{Name: "metadata_checksums", Checked: false}},
			false,
		},
		{
			"no checks at all",
			nil,
			false,
		},
		{
			"one check ran and passed",
			[]fsVerifyCheck{{Name: "a", Checked: true, Passed: true}},
			true,
		},
		{
			"one check ran and failed",
			[]fsVerifyCheck{{Name: "a", Checked: true, Passed: false}},
			false,
		},
		{
			// A single failure is enough, however much else passed.
			"one of three failed",
			[]fsVerifyCheck{
				{Name: "a", Checked: true, Passed: true},
				{Name: "b", Checked: true, Passed: false},
				{Name: "c", Checked: true, Passed: true},
			},
			false,
		},
		{
			// An unavailable check must not drag down a real pass, or a v4
			// XFS volume whose other checks all held could never be verified.
			"one ran and passed beside one that could not run",
			[]fsVerifyCheck{
				{Name: "a", Checked: true, Passed: true},
				{Name: "b", Checked: false},
			},
			true,
		},
		{
			// Passed is meaningless without Checked, and must not be read.
			"an unavailable check claiming to have passed",
			[]fsVerifyCheck{{Name: "a", Checked: false, Passed: true}},
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := fsVerifyResult{Checks: tc.checks}
			if got := result.verified(); got != tc.want {
				t.Fatalf("verified() = %v, want %v", got, tc.want)
			}
		})
	}
}

// checks_run is what tells "nothing to check" apart from "checked and failed",
// since verified() reports false for both.
func TestTallySeparatesUnavailableFromFailed(t *testing.T) {
	result := fsVerifyResult{Checks: []fsVerifyCheck{
		{Name: "a", Checked: true, Passed: true},
		{Name: "b", Checked: true, Passed: false},
		{Name: "c", Checked: false},
		{Name: "d", Checked: false},
	}}

	run, passed, failed, unavailable := result.tally()
	if run != 2 || passed != 1 || failed != 1 || unavailable != 2 {
		t.Fatalf("tally() = run %d, passed %d, failed %d, unavailable %d; want 2, 1, 1, 2",
			run, passed, failed, unavailable)
	}
}

// The findings list is capped, but the number an examiner would quote is not.
func TestFindingCountSurvivesTruncation(t *testing.T) {
	var result fsVerifyResult
	for i := 0; i < fsVerifyMaxFindings+25; i++ {
		result.addFinding(fsVerifyFinding{Issue: "torn record"})
	}

	if len(result.Findings) != fsVerifyMaxFindings {
		t.Fatalf("kept %d findings, want the cap of %d", len(result.Findings), fsVerifyMaxFindings)
	}
	if result.FindingCount != int64(fsVerifyMaxFindings+25) {
		t.Fatalf("finding count %d, want %d", result.FindingCount, fsVerifyMaxFindings+25)
	}

	hash := result.toHash("h")
	if !mustHashBoolValue(t, hash, "findings_truncated") {
		t.Fatal("findings_truncated is false although the cap bit")
	}
	if got := mustHashIntValue(t, hash, "finding_count"); got != int64(fsVerifyMaxFindings+25) {
		t.Fatalf("finding_count %d, want %d", got, fsVerifyMaxFindings+25)
	}
	if got := len(mustHashArrayValue(t, hash, "findings")); got != fsVerifyMaxFindings {
		t.Fatalf("findings array holds %d, want %d", got, fsVerifyMaxFindings)
	}
}

func TestFindingsAreNotTruncatedBelowTheCap(t *testing.T) {
	var result fsVerifyResult
	result.addFinding(fsVerifyFinding{Issue: "one"})

	hash := result.toHash("h")
	if mustHashBoolValue(t, hash, "findings_truncated") {
		t.Fatal("findings_truncated is true for a single finding")
	}
}

// Every *_verify builtin returns exactly the keys its metadata declares. The
// return-fields conformance probe cannot reach these -- they need a live
// handle -- so the agreement is pinned here instead.
func TestVerifyBuiltinsReturnTheDeclaredFields(t *testing.T) {
	cases := []struct {
		name    string
		install func(*testing.T)
		open    func() object.Object
		verify  func(string) object.Object
	}{
		{
			BuiltinNameNtfsVerify,
			func(t *testing.T) {
				installFakeNTFSBackend(t, fakeNTFSBackend{session: &fakeNTFSSession{
					verify: fsVerifyResult{Filesystem: "ntfs"},
				}})
			},
			func() object.Object { return NtfsOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return NtfsVerify(stringObj(h)) },
		},
		{
			BuiltinNameFatVerify,
			func(t *testing.T) {
				installFakeFATBackend(t, fakeFATBackend{session: &fakeFATSession{
					verify: fsVerifyResult{Filesystem: "fat"},
				}})
			},
			func() object.Object { return FatOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return FatVerify(stringObj(h)) },
		},
		{
			BuiltinNameXfatVerify,
			func(t *testing.T) {
				installFakeXFATBackend(t, fakeXFATBackend{session: &fakeXFATSession{
					verify: fsVerifyResult{Filesystem: "xfat"},
				}})
			},
			func() object.Object { return XFATOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return XFATVerify(stringObj(h)) },
		},
		{
			BuiltinNameExtVerify,
			func(t *testing.T) {
				installFakeEXTBackend(t, fakeEXTBackend{session: &fakeEXTSession{
					verify: fsVerifyResult{Filesystem: "ext"},
				}})
			},
			func() object.Object { return ExtOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return ExtVerify(stringObj(h)) },
		},
		{
			BuiltinNameHfsVerify,
			func(t *testing.T) {
				installFakeHFSBackend(t, fakeHFSBackend{session: &fakeHFSSession{
					verify: fsVerifyResult{Filesystem: "hfs"},
				}})
			},
			func() object.Object { return HFSOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return HFSVerify(stringObj(h)) },
		},
		{
			BuiltinNameXfsVerify,
			func(t *testing.T) {
				installFakeXFSBackend(t, fakeXFSBackend{session: &fakeXFSSession{
					verify: fsVerifyResult{Filesystem: "xfs"},
				}})
			},
			func() object.Object { return XFSOpen(stringObj("synthetic.img")) },
			func(h string) object.Object { return XFSVerify(stringObj(h)) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.install(t)

			openPayload, openErr := unwrapPair(t, tc.open())
			if openErr != nil {
				t.Fatalf("open returned error: %s", openErr.Inspect())
			}
			handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

			payload, err := unwrapPair(t, tc.verify(handle))
			if err != nil {
				t.Fatalf("%s returned error: %s", tc.name, err.Inspect())
			}
			hash, ok := payload.(*object.Hash)
			if !ok {
				t.Fatalf("%s payload is not HASH. got=%T", tc.name, payload)
			}

			got := map[string]bool{}
			for _, pair := range hash.Pairs {
				key, ok := pair.Key.(*object.String)
				if !ok {
					t.Fatalf("%s returned a non-STRING key %s", tc.name, pair.Key.Inspect())
				}
				got[key.Value] = true
			}

			declared, ok := builtinDocs[tc.name]
			if !ok {
				t.Fatalf("%s has no metadata entry", tc.name)
			}
			for _, field := range declared.returns.fields {
				if !got[field] {
					t.Errorf("%s declares field %q but did not return it", tc.name, field)
				}
				delete(got, field)
			}
			for field := range got {
				t.Errorf("%s returned undeclared field %q", tc.name, field)
			}

			if mustHashStringValue(t, hash, "handle") != handle {
				t.Errorf("%s did not echo its handle", tc.name)
			}
		})
	}
}

// A verify that cannot run is an error, not a result claiming nothing was
// wrong: a session error means the checks did not happen.
func TestVerifyPropagatesTheSessionError(t *testing.T) {
	installFakeEXTBackend(t, fakeEXTBackend{session: &fakeEXTSession{
		verifyErr: errors.New("volume closed"),
	}})

	openPayload, openErr := unwrapPair(t, ExtOpen(stringObj("synthetic.img")))
	if openErr != nil {
		t.Fatalf("ext_open returned error: %s", openErr.Inspect())
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	_, err := unwrapPairNoFatal(ExtVerify(stringObj(handle)))
	if err == nil {
		t.Fatal("a failing session verify produced no error")
	}
	if !strings.Contains(err.Message, "volume closed") {
		t.Fatalf("error does not name the cause: %s", err.Message)
	}
	if !strings.Contains(err.Message, BuiltinNameExtVerify) {
		t.Fatalf("error does not name the builtin: %s", err.Message)
	}
}

func TestVerifyRejectsBadArguments(t *testing.T) {
	installFakeEXTBackend(t, fakeEXTBackend{session: &fakeEXTSession{}})

	if _, err := unwrapPairNoFatal(ExtVerify()); err == nil {
		t.Fatal("ext_verify accepted no arguments")
	}
	if _, err := unwrapPairNoFatal(ExtVerify(stringObj("a"), stringObj("b"))); err == nil {
		t.Fatal("ext_verify accepted two arguments")
	}
	if _, err := unwrapPairNoFatal(ExtVerify(intObj(7))); err == nil {
		t.Fatal("ext_verify accepted a non-STRING handle")
	}
	if _, err := unwrapPairNoFatal(ExtVerify(stringObj("ext-handle-999"))); err == nil {
		t.Fatal("ext_verify accepted an unknown handle")
	}
}

// The six builtins each resolve handles from their own store, so a handle from
// one filesystem must not verify against another.
func TestVerifyRejectsAHandleFromAnotherFilesystem(t *testing.T) {
	installFakeEXTBackend(t, fakeEXTBackend{session: &fakeEXTSession{}})
	installFakeXFSBackend(t, fakeXFSBackend{session: &fakeXFSSession{}})

	openPayload, openErr := unwrapPair(t, ExtOpen(stringObj("synthetic.img")))
	if openErr != nil {
		t.Fatalf("ext_open returned error: %s", openErr.Inspect())
	}
	handle := mustHashStringValue(t, openPayload.(*object.Hash), "handle")

	if _, err := unwrapPairNoFatal(XFSVerify(stringObj(handle))); err == nil {
		t.Fatalf("xfs_verify accepted an ext handle %q", handle)
	}
}

// Severity words from three libraries have to arrive as one vocabulary, or a
// script branching on severity has to know which filesystem it came from.
func TestSeverityNamesNormalise(t *testing.T) {
	extCases := map[libext.CorruptionSeverity]string{
		libext.SeverityCritical: "critical",
		libext.SeverityWarning:  "warning",
		libext.SeverityInfo:     "info",
	}
	for severity, want := range extCases {
		if got := extSeverityName(severity); got != want {
			t.Errorf("extSeverityName(%d) = %q, want %q", severity, got, want)
		}
	}
	if got := extSeverityName(libext.CorruptionSeverity(99)); got != "unknown" {
		t.Errorf("an unrecognised ext severity became %q, want \"unknown\"", got)
	}

	xfsCases := map[string]string{
		"high":     "critical",
		"HIGH":     "critical",
		"critical": "critical",
		"medium":   "warning",
		"low":      "warning",
		"warning":  "warning",
		"":         "unknown",
		// An unrecognised word is passed through rather than mapped to a
		// severity it might not have: inventing "warning" here would soften a
		// finding the library graded some other way.
		"catastrophic": "catastrophic",
	}
	for input, want := range xfsCases {
		if got := xfsSeverityName(input); got != want {
			t.Errorf("xfsSeverityName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAnomalyLocationNamesWhatItHas(t *testing.T) {
	cases := []struct {
		path  string
		inode uint64
		want  string
	}{
		{"/var/log", 42, "/var/log (inode 42)"},
		{"/var/log", 0, "/var/log"},
		{"", 42, "inode 42"},
		{"", 0, "volume"},
	}
	for _, tc := range cases {
		if got := anomalyLocation(tc.path, tc.inode); got != tc.want {
			t.Errorf("anomalyLocation(%q, %d) = %q, want %q", tc.path, tc.inode, got, tc.want)
		}
	}
}

// A check's detail is what a report quotes to justify the verdict, so an empty
// one turns a finding into an assertion with no reasoning attached.
func TestEveryCheckCarriesItsReasoning(t *testing.T) {
	result := fsVerifyResult{
		Filesystem: "test",
		Checks: []fsVerifyCheck{
			{Name: "a", Checked: true, Passed: true, Examined: 3, Detail: "why"},
		},
		Scope: "what was not reached",
	}

	hash := result.toHash("h")
	checks := mustHashArrayValue(t, hash, "checks")
	if len(checks) != 1 {
		t.Fatalf("got %d checks, want 1", len(checks))
	}
	check, ok := checks[0].(*object.Hash)
	if !ok {
		t.Fatalf("a check is not HASH. got=%T", checks[0])
	}
	if got := mustHashStringValue(t, check, "detail"); got != "why" {
		t.Errorf("detail = %q", got)
	}
	if got := mustHashStringValue(t, check, "name"); got != "a" {
		t.Errorf("name = %q", got)
	}
	if got := mustHashIntValue(t, check, "examined"); got != 3 {
		t.Errorf("examined = %d, want 3", got)
	}
	if !mustHashBoolValue(t, check, "checked") || !mustHashBoolValue(t, check, "passed") {
		t.Error("checked/passed did not survive the round trip")
	}
	if got := mustHashStringValue(t, hash, "scope"); got == "" {
		t.Error("scope is empty")
	}
}

// Every *_verify summary has to say what the family's verdict means, because
// `verified: false` on a volume with nothing checkable reads as a failure to
// anyone who has not been told otherwise.
func TestVerifyMetadataExplainsTheVerdict(t *testing.T) {
	names := []string{
		BuiltinNameNtfsVerify, BuiltinNameFatVerify, BuiltinNameXfatVerify,
		BuiltinNameExtVerify, BuiltinNameHfsVerify, BuiltinNameXfsVerify,
	}
	for _, name := range names {
		doc, ok := builtinDocs[name]
		if !ok {
			t.Errorf("%s has no metadata entry", name)
			continue
		}
		if !strings.Contains(doc.summary, "checks_run") {
			t.Errorf("%s does not say how to tell nothing-to-check from a failure", name)
		}
		if !strings.Contains(doc.summary, "`checked`") {
			t.Errorf("%s does not explain the checked bit", name)
		}
	}
}

// --- real volumes -----------------------------------------------------------
//
// fat_verify makes the subtlest claim in the family: that walking the directory
// tree gives libfat's incidental mirror counter a denominator worth quoting.
// That rests on the walk actually causing FAT entries to be read, which no fake
// can demonstrate. FAT is also the one of the six whose on-disk format is small
// enough to build by hand, so it is built here.

const (
	fatTestSectorSize    = 512
	fatTestClusters      = 5000 // comfortably inside FAT16's 4085..65525 range
	fatTestFATSectors    = 20   // (5000+2) 16-bit entries, rounded up to sectors
	fatTestRootDirSector = 32   // 512 root entries at 32 bytes each
)

// buildFAT16Image assembles a FAT16 volume holding one subdirectory.
//
// The subdirectory is what makes the image useful: FAT16 keeps its root in a
// fixed region that needs no FAT lookup, so a volume of only root entries can
// be walked end to end without reading a single FAT entry -- and the mirror
// comparison would never run.
func buildFAT16Image(t *testing.T, numberOfFATs byte, divergeSecondFATAtCluster uint32) []byte {
	t.Helper()

	fatSectors := uint32(fatTestFATSectors)
	reserved := uint32(1)
	rootSectors := uint32(fatTestRootDirSector)
	totalSectors := reserved + uint32(numberOfFATs)*fatSectors + rootSectors + fatTestClusters

	image := make([]byte, int(totalSectors)*fatTestSectorSize)

	boot := image[:fatTestSectorSize]
	copy(boot[0:3], []byte{0xEB, 0x3C, 0x90})
	copy(boot[3:11], []byte("MUTANT  "))
	putUint16LE(boot, 11, fatTestSectorSize)
	boot[13] = 1 // sectors per cluster
	putUint16LE(boot, 14, uint16(reserved))
	boot[16] = numberOfFATs
	putUint16LE(boot, 17, 512) // root entry count
	putUint16LE(boot, 19, uint16(totalSectors))
	boot[21] = 0xF8 // fixed disk
	putUint16LE(boot, 22, uint16(fatSectors))
	putUint16LE(boot, 24, 63)
	putUint16LE(boot, 26, 255)
	boot[38] = 0x29 // extended boot signature
	copy(boot[43:54], []byte("MUTANTTEST "))
	copy(boot[54:62], []byte("FAT16   "))
	putUint16LE(boot, 510, 0xAA55)

	// The FAT. Entry 0 is the media descriptor, entry 1 the end-of-chain mark,
	// and cluster 2 holds the subdirectory and ends its own chain.
	fat := make([]byte, int(fatSectors)*fatTestSectorSize)
	putUint16LE(fat, 0, 0xFFF8)
	putUint16LE(fat, 2, 0xFFFF)
	putUint16LE(fat, 4, 0xFFFF) // cluster 2: end of chain

	firstFATOffset := int(reserved) * fatTestSectorSize
	copy(image[firstFATOffset:], fat)
	if numberOfFATs > 1 {
		secondFATOffset := firstFATOffset + len(fat)
		copy(image[secondFATOffset:], fat)
		if divergeSecondFATAtCluster != 0 {
			// A value that disagrees with the primary but is still a legal
			// cluster number, so the disagreement is a disagreement and not a
			// parse failure.
			putUint16LE(image, secondFATOffset+int(divergeSecondFATAtCluster)*2, 0x0003)
		}
	}

	rootOffset := firstFATOffset + int(numberOfFATs)*len(fat)
	writeFATDirEntry(image[rootOffset:], "SUBDIR  ", 0x10, 2, 0)

	dataOffset := rootOffset + int(rootSectors)*fatTestSectorSize
	cluster2 := image[dataOffset:]
	writeFATDirEntry(cluster2, ".       ", 0x10, 2, 0)
	writeFATDirEntry(cluster2[32:], "..      ", 0x10, 0, 0)

	return image
}

func writeFATDirEntry(dst []byte, name string, attr byte, firstCluster uint16, size uint32) {
	copy(dst[0:11], []byte(name + "   ")[:11])
	dst[11] = attr
	putUint16LE(dst, 26, firstCluster)
	putUint32LE(dst, 28, size)
}

func putUint16LE(b []byte, at int, v uint16) {
	b[at] = byte(v)
	b[at+1] = byte(v >> 8)
}

func putUint32LE(b []byte, at int, v uint32) {
	b[at] = byte(v)
	b[at+1] = byte(v >> 8)
	b[at+2] = byte(v >> 16)
	b[at+3] = byte(v >> 24)
}

// openRealFATSession opens an in-memory image through libfat itself. The
// session's img field stays nil: Verify reads only the volume, and a real
// *os.File would add nothing but a temp directory.
func openRealFATSession(t *testing.T, image []byte) *realFATSession {
	t.Helper()

	volume, err := libfat.Open(bytes.NewReader(image))
	if err != nil {
		t.Fatalf("libfat could not open the built image: %v", err)
	}
	return &realFATSession{volume: volume}
}

func TestRealFATVerifyPassesOnAnIntactMirror(t *testing.T) {
	session := openRealFATSession(t, buildFAT16Image(t, 2, 0))

	result, err := session.Verify()
	if err != nil {
		t.Fatalf("Verify returned an error: %v", err)
	}
	if !result.verified() {
		t.Fatalf("an intact two-FAT volume was not verified: %+v", result.Checks)
	}
	if len(result.Checks) != 1 || result.Checks[0].Name != "fat_mirror" {
		t.Fatalf("unexpected checks: %+v", result.Checks)
	}
	if !result.Checks[0].Checked {
		t.Fatal("the mirror check reported itself unavailable on a two-FAT volume")
	}
	// This is the assertion the whole approach rests on. Without the walk the
	// counter is never touched and examined stays zero, which would make a
	// pass meaningless.
	if result.Checks[0].Examined == 0 {
		t.Fatal("the walk reached no entries, so the mirror comparison had no denominator")
	}
	if result.FindingCount != 0 {
		t.Fatalf("an intact volume produced findings: %+v", result.Findings)
	}
}

func TestRealFATVerifyReportsADivergentMirror(t *testing.T) {
	session := openRealFATSession(t, buildFAT16Image(t, 2, 2))

	result, err := session.Verify()
	if err != nil {
		t.Fatalf("Verify returned an error: %v", err)
	}
	if result.verified() {
		t.Fatal("a volume whose two FATs disagree was reported as verified")
	}
	if result.Checks[0].Passed {
		t.Fatal("the mirror check passed although the tables disagree")
	}
	if result.FindingCount == 0 {
		t.Fatal("a divergent mirror produced no finding")
	}
	if !strings.Contains(result.Findings[0].Issue, "disagree") {
		t.Fatalf("the finding does not say what went wrong: %+v", result.Findings[0])
	}
	if result.Findings[0].Severity != "critical" {
		t.Fatalf("a FAT mirror divergence graded %q", result.Findings[0].Severity)
	}
}

// The case the family exists for: a volume with nothing to check is not
// verified, and is not a failure either.
func TestRealFATVerifyIsNotVerifiedWithASingleFAT(t *testing.T) {
	session := openRealFATSession(t, buildFAT16Image(t, 1, 0))

	result, err := session.Verify()
	if err != nil {
		t.Fatalf("Verify returned an error: %v", err)
	}
	if result.verified() {
		t.Fatal("a single-FAT volume was reported as verified; it has nothing to verify")
	}

	run, passed, failed, unavailable := result.tally()
	if run != 0 || passed != 0 || failed != 0 || unavailable != 1 {
		t.Fatalf("tally = run %d, passed %d, failed %d, unavailable %d; want 0, 0, 0, 1",
			run, passed, failed, unavailable)
	}
	if result.FindingCount != 0 {
		t.Fatalf("having one FAT is not a finding, but produced %d", result.FindingCount)
	}
	if !strings.Contains(result.Checks[0].Detail, "single file allocation table") {
		t.Fatalf("the check does not say why it could not run: %q", result.Checks[0].Detail)
	}
}
