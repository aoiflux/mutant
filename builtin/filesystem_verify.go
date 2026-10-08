package builtin

// The *_verify family: what each filesystem can prove about itself.
//
// These six builtins share one return shape, and the shape is the point. A
// filesystem verification is not a boolean. Asking "is this volume intact" of
// six different formats gets six different kinds of answer, and three of the
// six cannot answer it at all:
//
//   - ext carries CRC32c on its metadata, but only when the volume was made
//     with RO_COMPAT_METADATA_CSUM. Without it there is nothing to compare.
//   - exFAT carries two independent checks, an entry-set checksum and a name
//     hash, and libxfat's docs are explicit that neither subsumes the other.
//   - XFS carries a superblock CRC, but only on v5. Every v4 image has none.
//   - FAT carries no checksum anywhere. The one integrity signal it has is
//     whether its two allocation tables agree, and only if it has two.
//   - NTFS carries no volume checksum either. Its integrity mechanism is the
//     update sequence array, which detects a torn write per MFT record.
//   - HFS+ carries nothing at all. Apple never put a checksum in it.
//
// Collapsing that into `ok: true` would be the exact failure
// docs/EVIDENCE_HANDLING_POLICY.md names: "a manifest that asserts something
// nobody verifies is worse than a manifest that says nothing, because it looks
// like verification." An HFS+ volume reporting `ok: true` would be asserting a
// check that does not exist in the format.
//
// So every check reports two bits, not one -- and that is not an invention
// here, it is what the libraries themselves do. libxfat returns
// ChecksumChecked alongside ChecksumVerified; libxfs returns
// SuperblockCRCChecked alongside SuperblockCRCValid; both document that the
// second bit is meaningless without the first. This family adopts that
// throughout, and derives the verdict from it by the same rule
// libewf.VerifyResult.OK() uses for images: a volume is verified only when at
// least one check actually ran and every check that ran passed. Nothing to
// check is not a pass.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"math/bits"
	"strings"

	libext "github.com/aoiflux/libext"
	libfat "github.com/aoiflux/libfat"
	libhfs "github.com/aoiflux/libhfs"
	libntfs "github.com/aoiflux/libntfs"
	libxfat "github.com/aoiflux/libxfat"
	libxfs "github.com/aoiflux/libxfs"

	"mutant/object"
)

// fsVerifyCheck is one integrity check a format offers, and what came of it.
//
// Checked and Passed are separate bits because a check that never ran says
// nothing about the volume, and one boolean cannot tell "intact" from "there
// was nothing to compare against". Passed is only meaningful when Checked.
//
// Examined is the denominator: how many records, entries or structures this
// check actually looked at. A check that passed over two entries and a check
// that passed over two million are not the same evidence, and without the
// count a report cannot tell them apart.
type fsVerifyCheck struct {
	Name     string
	Checked  bool
	Passed   bool
	Examined int64
	Detail   string

	// Structural marks a check that is not one of the format's integrity
	// mechanisms -- a plausibility test, a flag the filesystem keeps about
	// itself, whether a structure could be reached at all. What it finds
	// wrong is wrong, so it can fail a volume; it cannot verify one, because
	// passing it says nothing was found implausible, not that the bytes are
	// the ones written. Rendered as kind "structural" beside "integrity".
	Structural bool
}

// fsVerifyFinding is one thing a check objected to. Severity is the library's
// own word for it where the library has one, so that a report quotes the
// parser rather than this package's opinion of it.
type fsVerifyFinding struct {
	Severity string
	Location string
	Issue    string
	Detail   string
}

// fsVerifyMaxFindings bounds the findings array.
//
// A volume damaged enough to produce more findings than this is already
// established as damaged; what the extra hundred thousand entries would buy is
// a hash big enough to exhaust memory rendering it. The true count is reported
// separately and is never truncated, so the number an examiner quotes stays
// right even when the list they read is short. libhfs bounds its own anomaly
// list for the same reason.
const fsVerifyMaxFindings = 1000

// fsVerifyResult is what a *_verify builtin reports.
type fsVerifyResult struct {
	Filesystem string
	Checks     []fsVerifyCheck
	Findings   []fsVerifyFinding
	// FindingCount is the number of findings observed, which is larger than
	// len(Findings) once the cap bites.
	FindingCount int64
	// Scope states what the checks covered and, more importantly, what they
	// did not. Every one of these checks has a boundary -- a walk reaches only
	// the live tree, a warning list holds only what has been parsed so far --
	// and a verification whose boundary is not written down invites the reader
	// to assume it had none.
	Scope string
}

// addFinding records a finding, keeping the count honest past the cap.
func (r *fsVerifyResult) addFinding(finding fsVerifyFinding) {
	r.FindingCount++
	if len(r.Findings) < fsVerifyMaxFindings {
		r.Findings = append(r.Findings, finding)
	}
}

// verified reports whether this volume can be called verified.
//
// True only when at least one integrity check actually ran and every check
// that ran -- integrity or structural -- passed. A format that carries no
// checksums therefore reports false with integrity_checks_run zero, however
// many structural checks held -- which is not the same as failing, and the
// two are told apart by integrity_checks_run rather than by this bit. It is
// libewf.VerifyResult.OK()'s rule, that an image storing no digests is not
// verified, applied to filesystems.
func (r fsVerifyResult) verified() bool {
	integrity := 0
	for _, check := range r.Checks {
		if !check.Checked {
			continue
		}
		if !check.Passed {
			return false
		}
		if !check.Structural {
			integrity++
		}
	}
	return integrity > 0
}

// tally counts the checks by outcome, and the integrity checks that ran.
func (r fsVerifyResult) tally() (run, passed, failed, unavailable, integrityRun int64) {
	for _, check := range r.Checks {
		if check.Checked && !check.Structural {
			integrityRun++
		}
		switch {
		case !check.Checked:
			unavailable++
		case check.Passed:
			run++
			passed++
		default:
			run++
			failed++
		}
	}
	return run, passed, failed, unavailable, integrityRun
}

// toHash renders the result in the family's one return shape.
func (r fsVerifyResult) toHash(handle string) *object.Hash {
	checks := make([]object.Object, 0, len(r.Checks))
	for _, check := range r.Checks {
		kind := "integrity"
		if check.Structural {
			kind = "structural"
		}
		checks = append(checks, makeHashObject(map[string]object.Object{
			"name":     stringObj(check.Name),
			"kind":     stringObj(kind),
			"checked":  boolObj(check.Checked),
			"passed":   boolObj(check.Passed),
			"examined": intObj(check.Examined),
			"detail":   stringObj(check.Detail),
		}))
	}

	findings := make([]object.Object, 0, len(r.Findings))
	for _, finding := range r.Findings {
		findings = append(findings, makeHashObject(map[string]object.Object{
			"severity": stringObj(finding.Severity),
			"location": stringObj(finding.Location),
			"issue":    stringObj(finding.Issue),
			"detail":   stringObj(finding.Detail),
		}))
	}

	run, passed, failed, unavailable, integrityRun := r.tally()

	return makeHashObject(map[string]object.Object{
		"handle":               stringObj(handle),
		"filesystem":           stringObj(r.Filesystem),
		"verified":             boolObj(r.verified()),
		"checks":               &object.Array{Elements: checks},
		"integrity_checks_run": intObj(integrityRun),
		"checks_run":           intObj(run),
		"checks_passed":        intObj(passed),
		"checks_failed":        intObj(failed),
		"checks_unavailable":   intObj(unavailable),
		"findings":             &object.Array{Elements: findings},
		"finding_count":        intObj(r.FindingCount),
		"findings_truncated":   boolObj(r.FindingCount > int64(len(r.Findings))),
		"scope":                stringObj(r.Scope),
		"status":               stringObj("ok"),
	})
}

// --- the builtins -----------------------------------------------------------

func NtfsVerify(args ...object.Object) object.Object {
	state, errObj := verifyArgs(args, BuiltinNameNtfsVerify, func(arg object.Object, op string) (fsVerifier, *object.Error) {
		resolved, err := resolveNTFSHandle(arg, op)
		return resolved.Session, err
	})
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return runVerify(state, args[0], BuiltinNameNtfsVerify)
}

func FatVerify(args ...object.Object) object.Object {
	state, errObj := verifyArgs(args, BuiltinNameFatVerify, func(arg object.Object, op string) (fsVerifier, *object.Error) {
		resolved, err := resolveFATHandle(arg, op)
		return resolved.Session, err
	})
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return runVerify(state, args[0], BuiltinNameFatVerify)
}

func XFATVerify(args ...object.Object) object.Object {
	state, errObj := verifyArgs(args, BuiltinNameXfatVerify, func(arg object.Object, op string) (fsVerifier, *object.Error) {
		resolved, err := resolveXFATHandle(arg, op)
		return resolved.Session, err
	})
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return runVerify(state, args[0], BuiltinNameXfatVerify)
}

func ExtVerify(args ...object.Object) object.Object {
	state, errObj := verifyArgs(args, BuiltinNameExtVerify, func(arg object.Object, op string) (fsVerifier, *object.Error) {
		resolved, err := resolveEXTHandle(arg, op)
		return resolved.Session, err
	})
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return runVerify(state, args[0], BuiltinNameExtVerify)
}

func HFSVerify(args ...object.Object) object.Object {
	state, errObj := verifyArgs(args, BuiltinNameHfsVerify, func(arg object.Object, op string) (fsVerifier, *object.Error) {
		resolved, err := resolveHFSHandle(arg, op)
		return resolved.Session, err
	})
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return runVerify(state, args[0], BuiltinNameHfsVerify)
}

func XFSVerify(args ...object.Object) object.Object {
	state, errObj := verifyArgs(args, BuiltinNameXfsVerify, func(arg object.Object, op string) (fsVerifier, *object.Error) {
		resolved, err := resolveXFSHandle(arg, op)
		return resolved.Session, err
	})
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return runVerify(state, args[0], BuiltinNameXfsVerify)
}

// fsVerifier is the one method the six sessions have in common here. Each
// session interface declares Verify in its own right; this is what lets the
// six builtins share an implementation rather than repeat it.
type fsVerifier interface {
	Verify() (fsVerifyResult, error)
}

func verifyArgs(args []object.Object, op string,
	resolve func(object.Object, string) (fsVerifier, *object.Error),
) (fsVerifier, *object.Error) {
	if len(args) != 1 {
		return nil, newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	return resolve(args[0], op)
}

func runVerify(session fsVerifier, handleArg object.Object, op string) object.Object {
	// The touch is recorded by the resolve*Handle that verifyArgs went through,
	// which is also where an unknown handle is refused. Recording it again here
	// counted one verification as two in the manifest, which is the kind of
	// number an examiner quotes.
	handle := ""
	if handleObj, ok := handleArg.(*object.String); ok {
		handle = handleObj.Value
	}

	result, err := session.Verify()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}

	return resultAndError(result.toHash(handle), nil)
}

// --- ext --------------------------------------------------------------------

func (s *realEXTSession) Verify() (fsVerifyResult, error) {
	result := fsVerifyResult{
		Filesystem: "ext",
		Scope: "The plausibility check reads the superblock only. On a volume " +
			"made with metadata checksums the checksum check reads every " +
			"allocated inode, so it costs O(inodes in use) rather than a seek. " +
			"It compares the checksums libext can compare -- the superblock, " +
			"the group descriptors, the allocation bitmaps and the inodes -- " +
			"and no other: extent tree blocks, directory blocks, extended " +
			"attribute blocks and the journal carry CRCs nothing here reads, " +
			"and no file content is checked, because ext stores no checksum " +
			"over data.",
	}

	reports := s.fs.ValidateSuperblockIntegrity()
	result.Checks = append(result.Checks, fsVerifyCheck{
		Name:       "superblock_plausibility",
		Structural: true,
		Checked:    true,
		Passed:     len(reports) == 0,
		Examined:   1,
		Detail: "Range and consistency checks on the superblock's geometry: " +
			"block and inode sizes, inodes per group, first data block, " +
			"reserved percentage. This is not a checksum -- on a volume that " +
			"has one, the superblock's CRC is the metadata checksum check's -- " +
			"so a pass means nothing implausible was found, not that the " +
			"superblock is unmodified.",
	})
	for _, report := range reports {
		result.addFinding(fsVerifyFinding{
			Severity: extSeverityName(report.Severity),
			Location: report.Location,
			Issue:    report.Issue,
			Detail:   report.Suggestion,
		})
	}

	if !s.fs.Capabilities().MetadataChecksums {
		result.Checks = append(result.Checks, fsVerifyCheck{
			Name:    "metadata_checksums",
			Checked: false,
			Detail: "This volume was made without RO_COMPAT_METADATA_CSUM, so " +
				"its metadata carries no CRC32c and there is nothing to " +
				"verify. A torn or edited structure on this volume is not " +
				"detectable by checksum at all.",
		})
	} else {
		s.verifyMetadataChecksums(&result)
	}

	for _, warning := range s.fs.Warnings() {
		if warning.Code == libext.WarnChecksumMismatch {
			continue
		}
		result.addFinding(fsVerifyFinding{
			Severity: "warning",
			Location: warning.Feature,
			Issue:    warning.Code.String(),
			Detail:   warning.Detail,
		})
	}
	if _, saturated := s.extWarningsSince(0); saturated {
		result.addFinding(fsVerifyFinding{
			Severity: "warning",
			Location: "libext warnings",
			Issue:    fsWarnWarningsSaturated,
			Detail:   extWarningsSaturatedDetail,
		})
	}

	return result, nil
}

// extCSumSeedFeature is INCOMPAT_CSUM_SEED (e2fsprogs' ext2_fs.h): the seed
// every metadata checksum starts from is stored in the superblock rather than
// derived from the volume's UUID.
const extCSumSeedFeature = 0x2000

// extZeroInodeBytes is how much of an inode e2fsck looks at before it accepts
// one with a bad checksum as never written: the 128-byte base inode
// (e2fsprogs lib/ext2fs/csum.c, ext2fs_inode_csum_verify).
const extZeroInodeBytes = 128

const extChecksumsDetail = "CRC32c comparisons on a volume made with metadata " +
	"checksums: the superblock, every group descriptor, the block and inode " +
	"bitmaps of every group that has them initialised, and every inode the " +
	"inode bitmaps say is allocated. examined counts the structures compared. " +
	"An inode whose first 128 bytes are zero is accepted without a checksum, " +
	"as e2fsck accepts it. Unallocated inodes are not compared -- past a " +
	"group's last used inode the table may never have been written -- and " +
	"nor is anything libext cannot compare: extent tree blocks, directory " +
	"blocks, extended attribute blocks and the journal."

// verifyMetadataChecksums compares every checksum libext can compare on a
// volume made with metadata checksums, and adds the checks that say so.
//
// A handle reports, as warnings, only the superblock and group descriptor
// comparisons it makes at open. It compares an inode's checksum on every read
// too, and throws the answer away unless the handle was opened to refuse a
// mismatch, so this check once passed a volume with an edited inode -- and
// told the examiner that verifying again after a walk would widen it, which
// no walk ever did. The comparisons are made on a second handle opened to
// refuse mismatches instead: that it opens at all says the superblock and every
// descriptor matched, whatever the warning list has room for, and every
// allocated inode is read through it.
func (s *realEXTSession) verifyMetadataChecksums(result *fsVerifyResult) {
	sb := s.fs.Superblock()
	if sb.FeatureIncompat&extCSumSeedFeature != 0 && sb.ChecksumSeed == 0 {
		result.Checks = append(result.Checks, fsVerifyCheck{
			Name: "metadata_checksums",
			Detail: extChecksumsDetail + " Nothing was compared: the volume " +
				"says its checksum seed is stored in the superblock and the " +
				"stored seed is zero, which the kernel uses as it is and libext " +
				"replaces with one derived from the UUID, so every comparison " +
				"would be against a checksum the kernel never computed.",
		})
		return
	}

	var compared, mismatched, read, unreadable int64
	mismatch := func(location, detail string) {
		mismatched++
		result.addFinding(fsVerifyFinding{
			Severity: "critical",
			Location: location,
			Issue:    "metadata checksum mismatch",
			Detail:   detail,
		})
	}
	unread := func(location string, err error) {
		unreadable++
		result.addFinding(fsVerifyFinding{
			Severity: "critical",
			Location: location,
			Issue:    "checksummed metadata could not be read",
			Detail:   err.Error(),
		})
	}

	groups := s.fs.GroupDescriptors()
	// The default handle compared the superblock and every descriptor when it
	// opened; a mismatch among them is a warning on it, and keeps the strict
	// handle below from opening at all.
	compared += 1 + int64(len(groups))
	read += 1 + int64(len(groups))
	options := s.options
	options.VerifyChecksums = true
	var strict *libext.FS
	if opened, strictErr := libext.OpenWithOptions(s.volume, options); strictErr == nil {
		strict = opened
		defer strict.Close()
	} else {
		recorded := false
		for _, warning := range s.fs.Warnings() {
			if warning.Code == libext.WarnChecksumMismatch {
				recorded = true
				mismatch("superblock or group descriptor", warning.Detail)
			}
		}
		switch {
		case !errors.Is(strictErr, libext.ErrChecksumMismatch):
			unread("superblock and group descriptors", strictErr)
		case !recorded:
			mismatch("superblock or group descriptor", strictErr.Error())
		}
	}

	for _, gd := range groups {
		if !gd.BlockUninit() {
			bitmap, err := s.fs.BlockBitmap(gd.Group)
			if err == nil {
				err = s.fs.VerifyBlockBitmapChecksum(gd.Group, bitmap)
			}
			extTallyChecksum(fmt.Sprintf("block bitmap of group %d", gd.Group), err,
				&compared, &read, mismatch, unread)
		}
		if gd.InodeUninit() {
			continue
		}
		bitmap, err := s.fs.InodeBitmap(gd.Group)
		if err == nil {
			err = s.fs.VerifyInodeBitmapChecksum(gd.Group, bitmap)
		}
		extTallyChecksum(fmt.Sprintf("inode bitmap of group %d", gd.Group), err,
			&compared, &read, mismatch, unread)
		if strict == nil || (err != nil && !errors.Is(err, libext.ErrChecksumMismatch)) {
			continue
		}
		for index := uint64(0); index < uint64(sb.InodesPerGroup) && index/8 < uint64(len(bitmap)); index++ {
			if bitmap[index/8]&(1<<(index%8)) == 0 {
				continue
			}
			number := uint64(gd.Group)*uint64(sb.InodesPerGroup) + index + 1
			if number > uint64(sb.InodesCount) {
				break
			}
			_, err := strict.ReadInode(uint32(number))
			if errors.Is(err, libext.ErrChecksumMismatch) {
				zero, zeroErr := s.extInodeIsZero(gd, index, sb)
				switch {
				case zeroErr != nil:
					err = zeroErr
				case zero:
					err = nil
				}
			}
			extTallyChecksum(fmt.Sprintf("inode %d", number), err, &compared, &read, mismatch, unread)
		}
	}

	check := fsVerifyCheck{
		Name:     "metadata_checksums",
		Checked:  true,
		Passed:   mismatched == 0,
		Examined: compared,
		Detail:   extChecksumsDetail,
	}
	if strict == nil {
		check.Detail += " No inode was compared: a handle that refuses a " +
			"mismatch does not open on a volume whose superblock or a " +
			"descriptor already fails, and the inodes are read through one."
	}
	result.Checks = append(result.Checks, check, fsVerifyCheck{
		Name:       "metadata_readable",
		Structural: true,
		Checked:    true,
		Passed:     unreadable == 0,
		Examined:   read,
		Detail: "Every structure the checksum check set out to compare, read " +
			"from the image. One whose read failed fails this, and the findings " +
			"name which: a volume missing part of its inode table must not " +
			"verify on the part that is left. It says the checksum check covered " +
			"what it set out to, not that anything is intact.",
	})
}

// extTallyChecksum counts one comparison: err is nil for a match, wraps
// libext.ErrChecksumMismatch for a mismatch, and is anything else for a
// structure that could not be read, which was not compared.
func extTallyChecksum(location string, err error, compared, read *int64,
	mismatch func(string, string), unread func(string, error)) {
	switch {
	case err == nil:
		*compared++
		*read++
	case errors.Is(err, libext.ErrChecksumMismatch):
		*compared++
		*read++
		mismatch(location, err.Error())
	default:
		unread(location, err)
	}
}

// extInodeIsZero reports whether the base of inode index in gd's table is
// all zero bytes, read from the volume where libext reads it.
func (s *realEXTSession) extInodeIsZero(gd libext.GroupDescriptor, index uint64, sb libext.Superblock) (bool, error) {
	hi, table := bits.Mul64(gd.InodeTableBlock, uint64(sb.BlockSize))
	within, inTable := bits.Mul64(index, uint64(sb.InodeSize))
	offset, carry := bits.Add64(table, inTable, 0)
	if hi != 0 || within != 0 || carry != 0 || offset > math.MaxInt64 {
		return false, fmt.Errorf("inode %d of group %d lies beyond any byte an image can hold", index, gd.Group)
	}
	raw := make([]byte, min(extZeroInodeBytes, int(sb.InodeSize)))
	if _, err := s.volume.ReadAt(raw, int64(offset)); err != nil {
		return false, err
	}
	for _, b := range raw {
		if b != 0 {
			return false, nil
		}
	}
	return true, nil
}

// extSeverityName spells a libext severity for a report. The constants are an
// unexported-looking iota with no String method, so the mapping lives here.
func extSeverityName(severity libext.CorruptionSeverity) string {
	switch severity {
	case libext.SeverityCritical:
		return "critical"
	case libext.SeverityWarning:
		return "warning"
	case libext.SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// --- fat --------------------------------------------------------------------

func (s *realFATSession) Verify() (fsVerifyResult, error) {
	result := fsVerifyResult{
		Filesystem: "fat",
		Scope: "FAT carries no checksum. Whether its two allocation tables " +
			"agree is the only integrity signal the format has, and only a " +
			"volume with a second FAT has it at all.",
	}

	if !s.volume.Capabilities().SecondFAT {
		result.Checks = append(result.Checks, fsVerifyCheck{
			Name:    "fat_mirror",
			Checked: false,
			Detail: "This volume carries a single file allocation table, so " +
				"there is no mirror to compare it against. FAT has no other " +
				"integrity mechanism: nothing about this volume can be " +
				"verified from the volume itself.",
		})
		return result, nil
	}

	// libfat compares the two tables inside readFATEntry and counts the
	// disagreements, so the counter only moves for entries something actually
	// read. Read nothing and it stays zero, which would otherwise look exactly
	// like agreement. Walking the tree first is what turns an incidental
	// counter into a comparison with a denominator worth quoting.
	entries := int64(0)
	if err := s.volume.Walk(context.Background(),
		func(string, uint32, libfat.DirEntry) error {
			entries++
			return nil
		}); err != nil {
		return result, fmt.Errorf("walking the directory tree to compare the FAT mirror: %w", err)
	}

	mismatches := s.volume.FATMirrorMismatches()
	if mismatches > 0 {
		result.addFinding(fsVerifyFinding{
			Severity: "critical",
			Location: "file allocation table",
			Issue:    "the two allocation tables disagree",
			Detail: fmt.Sprintf("%d FAT entry read(s) found the primary and "+
				"secondary tables holding different values. A volume written "+
				"by a driver that maintains both should never produce one.",
				mismatches),
		})
	}

	result.Checks = append(result.Checks, fsVerifyCheck{
		Name:     "fat_mirror",
		Checked:  true,
		Passed:   mismatches == 0,
		Examined: entries,
		Detail: "Compares each FAT entry against its copy in the second table " +
			"as the entry is read. Covered here: the cluster chains reached " +
			"by walking every live directory. Not covered: the data chains " +
			"of files nothing read, and clusters no directory references. " +
			"examined counts directory entries walked. The mismatch count is " +
			"cumulative for this handle since it was opened, and rises again " +
			"each time the same bad entry is re-read, so it bounds the number " +
			"of disagreeing entries from above rather than counting them.",
	})

	result.Scope += " Reads that happened before this call on the same handle " +
		"are included in the count."

	return result, nil
}

// --- xfat -------------------------------------------------------------------

func (s *realXFATSession) Verify() (fsVerifyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := fsVerifyResult{
		Filesystem: "xfat",
		Scope: "Covers the live, reachable directory tree. Deleted records and " +
			"carved entries are not walked, and libxfat has no warning sink " +
			"for a directory it could not read -- a walk that stepped over " +
			"one returns the same nil a clean walk does -- so examined is the " +
			"count of entries actually reached, not a claim about the volume.",
	}

	var entries, checksumChecked, checksumFailed int64
	var hashChecked, hashFailed int64

	err := s.fs.Walk(context.Background(), func(path string, _ uint32, entry libxfat.Entry) error {
		entries++

		// The entry-set checksum is compared while parsing, and only in strict
		// mode -- which is how the session opens every volume.
		if entry.NameChecksumVerified() || entry.NameChecksumMismatch() {
			checksumChecked++
			if entry.NameChecksumMismatch() {
				checksumFailed++
				expected, computed, _ := entry.EntrySetChecksums()
				result.addFinding(fsVerifyFinding{
					Severity: "critical",
					Location: path,
					Issue:    "entry set checksum mismatch",
					Detail: fmt.Sprintf("the set records checksum 0x%04x and "+
						"computes 0x%04x; the name is still reported, because a "+
						"damaged record is the only record of what the file was "+
						"called", expected, computed),
				})
			}
		}

		// The name hash is the second, independent check. libxfat's own doc is
		// explicit that the checksum does not subsume it: an entry whose name
		// was rewritten and whose checksum was recomputed, but whose hash was
		// not, passes one and fails the other.
		switch hashErr := s.fs.VerifyNameHash(entry); {
		case hashErr == nil:
			hashChecked++
		case errors.Is(hashErr, libxfat.ErrNoNameHash):
			// A synthetic or stream entry records no hash. Nothing to check,
			// and not a finding.
		case errors.Is(hashErr, libxfat.ErrNameHashMismatch):
			hashChecked++
			hashFailed++
			result.addFinding(fsVerifyFinding{
				Severity: "critical",
				Location: path,
				Issue:    "name hash mismatch",
				Detail:   hashErr.Error(),
			})
		default:
			// ErrUpcaseTableNotFound and anything else: the check could not be
			// made, which is not the same as failing it.
			result.addFinding(fsVerifyFinding{
				Severity: "warning",
				Location: path,
				Issue:    "name hash could not be checked",
				Detail:   hashErr.Error(),
			})
		}

		if entry.HasSyntheticName() {
			result.addFinding(fsVerifyFinding{
				Severity: "info",
				Location: path,
				Issue:    "name is a library placeholder, not evidence",
				Detail: "the entry set carried no usable name characters, so " +
					"libxfat supplied a placeholder to keep the subtree " +
					"addressable; the name here was invented, not read",
			})
		}

		return nil
	})
	if err != nil {
		return result, fmt.Errorf("walking the directory tree: %w", err)
	}

	result.Checks = append(result.Checks,
		fsVerifyCheck{
			Name:     "entry_set_checksum",
			Checked:  checksumChecked > 0,
			Passed:   checksumFailed == 0,
			Examined: checksumChecked,
			Detail: "Each file entry set's recorded checksum against the " +
				"checksum computed over the set as read. Synthetic entries " +
				"($MBR, $FAT1, $BitMap, $UpCase) carry none and are not " +
				"counted. This says the set's bytes are internally " +
				"consistent, not that the name is the one the volume indexed.",
		},
		fsVerifyCheck{
			Name:     "name_hash",
			Checked:  hashChecked > 0,
			Passed:   hashFailed == 0,
			Examined: hashChecked,
			Detail: "Each entry's name re-hashed through the volume's own " +
				"up-case table and compared with the hash in its stream " +
				"extension record. Independent of the entry set checksum: a " +
				"name rewritten with the checksum recomputed but the hash " +
				"left alone passes one and fails this.",
		})

	if entries == 0 {
		result.Scope += " The walk reached no entries at all."
	}

	return result, nil
}

// --- ntfs -------------------------------------------------------------------

func (s *realNTFSSession) Verify() (fsVerifyResult, error) {
	result := fsVerifyResult{
		Filesystem: "ntfs",
		Scope: "Reads every MFT record on the volume, so it costs O(MFT size) " +
			"rather than a seek. It checks the records' own framing and says " +
			"nothing about file content: NTFS stores no checksum over data.",
	}

	// The walk covers the records the image holds, however many the $MFT
	// declares: its own run list is what declares them, and nothing bounds it.
	plan, err := ntfsPlanMFT(s.volume, s.reader)
	if err != nil {
		return result, fmt.Errorf("planning the MFT walk: %w", err)
	}

	var examined, torn, read, unreadable int64
	for _, span := range plan.Walk {
		for entryNum := span.First; entryNum < span.First+span.Count; entryNum++ {
			_, entryErr := s.volume.GetMFTEntry(entryNum)
			switch {
			case entryErr == nil:
				examined++
				read++
			case errors.Is(entryErr, libntfs.ErrVolumeClosed):
				return result, entryErr
			case errors.Is(entryErr, libntfs.ErrUpdateSequence):
				// The record says FILE and its fixups do not hold. That is the
				// one thing NTFS's update sequence array exists to catch: a write
				// that did not complete, or a record edited without the fixups
				// being recomputed.
				examined++
				read++
				torn++
				result.addFinding(fsVerifyFinding{
					Severity: "critical",
					Location: fmt.Sprintf("MFT record %d", entryNum),
					Issue:    "update sequence (fixup) validation failed",
					Detail:   entryErr.Error(),
				})
			case errors.Is(entryErr, libntfs.ErrInvalidMFTEntry):
				// A never-written record, a record the volume itself marked
				// bad, or a header that is not a record's. A volume-wide walk
				// meets unallocated records constantly, so counting these as
				// damage would report every healthy volume as corrupt. They are
				// not examined either -- there was no record to check -- but
				// their bytes were read.
				read++
			default:
				// Anything else -- the read failed, or a FILE record's
				// attributes would not parse -- is a record this walk could not
				// check, and saying nothing about it would let a volume missing
				// half its MFT verify on the half that is left.
				unreadable++
				result.addFinding(fsVerifyFinding{
					Severity: "critical",
					Location: fmt.Sprintf("MFT record %d", entryNum),
					Issue:    "record could not be read",
					Detail:   entryErr.Error(),
				})
			}
		}
	}
	if gap := plan.describe(); gap != "" {
		result.addFinding(fsVerifyFinding{
			Severity: "critical",
			Location: "$MFT",
			Issue:    "records the MFT declares were not read",
			Detail:   gap,
		})
	}

	result.Checks = append(result.Checks, fsVerifyCheck{
		Name:     "mft_update_sequence",
		Checked:  examined > 0,
		Passed:   torn == 0,
		Examined: examined,
		Detail: "Every MFT record carrying the FILE signature, checked against " +
			"its update sequence array -- the per-sector mark NTFS uses to " +
			"detect a torn write. Records that are unallocated or marked bad " +
			"are skipped rather than failed, and are not counted in examined. " +
			"This is the only integrity check NTFS defines; the format has no " +
			"volume checksum and libntfs exposes no other verifier.",
	}, fsVerifyCheck{
		Name:       "mft_readable",
		Structural: true,
		Checked:    true,
		Passed:     unreadable == 0 && plan.unread() == 0 && plan.LayoutKnown,
		Examined:   read,
		Detail: "Every record the $MFT's run list declares, read from the image. A " +
			"record whose read failed, whose attributes would not parse, that lies " +
			"outside the image or that no run places fails this, and the findings " +
			"name which. examined counts the records whose bytes came back. It " +
			"says the update sequence check covered the whole MFT, not that " +
			"anything in it is intact.",
	})

	if examined == 0 && plan.Declared > 0 {
		result.Scope += fmt.Sprintf(" No record in the %d-entry MFT parsed as a "+
			"FILE record, so nothing was checked.", plan.Declared)
	}

	return result, nil
}

// --- hfs --------------------------------------------------------------------

func (s *realHFSSession) Verify() (fsVerifyResult, error) {
	result := fsVerifyResult{
		Filesystem: "hfs",
		Scope: "HFS and HFS+ carry no checksums anywhere in the format, so " +
			"there is nothing on this volume to verify against. What is " +
			"reported here is structural: whether the trees the volume header " +
			"points at can be read, and what libhfs noticed going wrong while " +
			"this handle parsed. Anomalies accumulate as a side effect of " +
			"whatever was parsed, so an empty list is not a clean bill of " +
			"health -- it can equally mean little was read.",
	}

	result.Checks = append(result.Checks, fsVerifyCheck{
		Name:    "metadata_checksums",
		Checked: false,
		Detail: "HFS+ records no checksum over its metadata or its data. " +
			"Neither a torn write nor an edit is detectable from the volume " +
			"itself, and no tool can make it so. An integrity claim about " +
			"this volume has to rest on the image's own digests -- see " +
			"ewf_verify -- rather than on the filesystem.",
	})

	var readable, failed int64
	trees := []struct {
		name string
		read func() (libhfs.BTreeHeaderRecord, error)
	}{
		{"catalog", s.volume.CatalogBTreeHeader},
		{"extents overflow", s.volume.ExtentsBTreeHeader},
	}
	// Classic HFS has no attributes tree at all, and HFS+ has one only when
	// the volume header names it; asking a volume without one for its header
	// failed a freshly formatted volume as critically corrupt. The header's
	// own word decides, and a tree it does not name is absent, not broken.
	if s.volume.Capabilities().ExtendedAttributes {
		trees = append(trees, struct {
			name string
			read func() (libhfs.BTreeHeaderRecord, error)
		}{"attributes", s.volume.AttributesBTreeHeader})
	} else {
		result.Scope += " The volume header names no attributes b-tree, so there " +
			"is none to read: it is absent by format, not unreadable."
	}
	for _, tree := range trees {
		header, err := tree.read()
		if err != nil {
			failed++
			severity := "warning"
			if libhfs.IsCorrupt(err) {
				severity = "critical"
			}
			result.addFinding(fsVerifyFinding{
				Severity: severity,
				Location: tree.name + " b-tree header",
				Issue:    "header could not be read",
				Detail:   err.Error(),
			})
			continue
		}
		readable++
		if header.NodeSize == 0 || header.TotalNodes == 0 {
			result.addFinding(fsVerifyFinding{
				Severity: "warning",
				Location: tree.name + " b-tree header",
				Issue:    "header describes an empty tree",
				Detail: fmt.Sprintf("node size %d over %d node(s); a tree the "+
					"volume header points at should describe at least one",
					header.NodeSize, header.TotalNodes),
			})
		}
	}

	result.Checks = append(result.Checks, fsVerifyCheck{
		Name:       "btree_headers",
		Structural: true,
		Checked:    true,
		Passed:     failed == 0,
		Examined:   readable + failed,
		Detail: "Reads the header node of each b-tree the volume header names. " +
			"A header that will not parse means the tree beneath it is not " +
			"reachable, which is the closest thing HFS+ offers to a " +
			"structural integrity signal. It is not a checksum: a tree whose " +
			"header reads cleanly can still have been edited.",
	})

	for _, anomaly := range s.volume.Anomalies() {
		result.addFinding(fsVerifyFinding{
			Severity: "warning",
			Location: anomaly.Op,
			Issue:    "parser recorded an anomaly",
			Detail:   anomaly.Detail,
		})
	}

	if total := int64(s.volume.AnomalyCount()); total > 0 {
		result.Checks = append(result.Checks, fsVerifyCheck{
			Name:       "parser_anomalies",
			Structural: true,
			Checked:    true,
			Passed:     false,
			Examined:   total,
			Detail: "Structural inconsistencies libhfs met while parsing on " +
				"this handle and carried on past. A catalog whose records " +
				"largely fail to decode is a finding in its own right. The " +
				"total counts repeats and anything beyond the library's " +
				"tracking limit, so it can exceed the findings listed.",
		})
	} else {
		result.Checks = append(result.Checks, fsVerifyCheck{
			Name:       "parser_anomalies",
			Structural: true,
			Checked:    true,
			Passed:     true,
			Examined:   0,
			Detail: "libhfs recorded no structural inconsistency while parsing " +
				"on this handle. Anomalies are noticed only in what was " +
				"actually read, so this is a statement about the reads made " +
				"so far and not about the volume.",
		})
	}

	return result, nil
}

// --- xfs --------------------------------------------------------------------

func (s *realXFSSession) Verify() (fsVerifyResult, error) {
	result := fsVerifyResult{
		Filesystem: "xfs",
		Scope: "Covers the superblock. XFS records CRC32c over its metadata " +
			"only from v5 onward, so on a v4 image there is no checksum to " +
			"check and the CRC result says so rather than passing.",
	}

	report, err := s.volume.VolumeIntegrityReport()
	if err != nil {
		return result, fmt.Errorf("building the volume integrity report: %w", err)
	}

	crcChecked, crcValid, crcErr := s.xfsSuperblockCRC()
	switch {
	case crcErr != nil:
		result.Checks = append(result.Checks, fsVerifyCheck{
			Name:   "superblock_crc",
			Detail: "The superblock's sector could not be read to compare its CRC32c: " + crcErr.Error(),
		})
	case !crcChecked:
		result.Checks = append(result.Checks, fsVerifyCheck{
			Name:    "superblock_crc",
			Checked: false,
			Detail: "This image records no superblock CRC, which is every v4 " +
				"XFS filesystem. superblock_crc_valid would read false here " +
				"whatever the state of the volume, so it is reported as " +
				"unchecked instead.",
		})
	default:
		result.Checks = append(result.Checks, fsVerifyCheck{
			Name:     "superblock_crc",
			Checked:  true,
			Passed:   crcValid,
			Examined: 1,
			Detail: "The v5 superblock's stored CRC32c against the checksum " +
				"computed over its sector as read, compared here: libxfs's own " +
				"comparison reads the stored value in the wrong byte order and " +
				"fails every v5 superblock.",
		})
		if !crcValid {
			result.addFinding(fsVerifyFinding{
				Severity: "critical",
				Location: "superblock",
				Issue:    "v5 superblock CRC32c mismatch",
				Detail: "the superblock's stored checksum does not match the " +
					"bytes on the volume",
			})
		}
	}

	needsRepair := s.volume.Superblock().NeedsRepair()
	result.Checks = append(result.Checks, fsVerifyCheck{
		Name:       "clean_state",
		Structural: true,
		Checked:    true,
		Passed:     !needsRepair,
		Examined:   1,
		Detail: "Whether the filesystem carries the needs-repair incompat " +
			"feature bit. It is a flag the filesystem set about itself, not a " +
			"check of the bytes, so a pass means it never recorded being left " +
			"inconsistent -- not that it is consistent.",
	})
	if needsRepair {
		result.addFinding(fsVerifyFinding{
			Severity: "critical",
			Location: "superblock",
			Issue:    "filesystem is marked as needing repair",
			Detail: "the volume was left in an inconsistent state; its " +
				"metadata should be treated with suspicion regardless of what " +
				"the other checks report",
		})
	}

	for _, anomaly := range report.Anomalies {
		if s.xfsAnomalyDisproved(anomaly, crcErr == nil && crcChecked && crcValid) {
			continue
		}
		result.addFinding(fsVerifyFinding{
			Severity: xfsSeverityName(anomaly.Severity),
			Location: anomalyLocation(anomaly.Path, anomaly.Inode),
			Issue:    anomaly.Code,
			Detail:   anomaly.Message,
		})
	}

	return result, nil
}

// The checksum fields XFS's v5 metadata carries (xfs_format.h): sb_crc at
// XFS_SB_CRC_OFF, di_crc at XFS_DINODE_CRC_OFF.
const (
	xfsSuperblockCRCOffset = 224
	xfsInodeCRCOffset      = 100
)

// xfsSuperblockCRC compares the v5 superblock's stored CRC32c with one
// computed over its sector the way the kernel computes it (xfs_sb.c: the
// superblock buffer is one sector, checksummed with sb_crc zeroed). libxfs
// v0.4.1 reads the stored value big-endian where XFS stores it little-endian
// -- its log record check beside it does not -- so it reports a mismatch on
// every v5 superblock, and a healthy, freshly made volume failed xfs_verify
// with a critical finding.
func (s *realXFSSession) xfsSuperblockCRC() (checked, valid bool, err error) {
	sb := s.volume.Superblock()
	if sb.FormatVersion != 5 {
		return false, false, nil
	}
	sector := make([]byte, sb.SectorSize)
	if len(sector) < xfsSuperblockCRCOffset+4 {
		return true, false, fmt.Errorf("the superblock gives a sector of %d bytes, "+
			"too short to hold its own checksum", len(sector))
	}
	if _, err := s.img.ReadAt(sector, s.volume.BaseOffset()); err != nil {
		return true, false, err
	}
	return true, xfsCRCHolds(sector, xfsSuperblockCRCOffset), nil
}

// xfsCRCHolds reports whether data's CRC32c, computed with the four bytes at at
// zeroed, is the little-endian value stored there. XFS seeds crc32c with ~0
// and stores the complement, which is the standard CRC-32C hash/crc32 gives.
func xfsCRCHolds(data []byte, at int) bool {
	if at < 0 || at+4 > len(data) {
		return false
	}
	stored := binary.LittleEndian.Uint32(data[at:])
	working := append([]byte(nil), data...)
	clear(working[at : at+4])
	return crc32.Checksum(working, crc32.MakeTable(crc32.Castagnoli)) == stored
}

// xfsAnomalyDisproved reports whether a libxfs anomaly is one of its two
// byte-order false alarms, disproved by the comparison made here: the
// superblock's, or a v3 inode's, whose check libxfs makes the same way and
// so flags every inode on every v5 volume. One the comparison here does not
// disprove -- a real mismatch, or an inode that would not reopen -- stands.
func (s *realXFSSession) xfsAnomalyDisproved(anomaly libxfs.ReportAnomaly, superblockValid bool) bool {
	switch anomaly.Code {
	case "VERIFY_SUPERBLOCK_CRC_MISMATCH":
		return superblockValid
	case "VERIFY_INODE_CRC_MISMATCH":
		if anomaly.Inode == 0 {
			return false
		}
		inode, err := s.volume.OpenInode(anomaly.Inode)
		return err == nil && inode.FormatVersion == 3 && xfsCRCHolds(inode.Raw, xfsInodeCRCOffset)
	}
	return false
}

// xfsSeverityName normalises libxfs's severity strings onto the same three
// words the other five report, so a script can branch on one vocabulary.
func xfsSeverityName(severity string) string {
	switch strings.ToLower(severity) {
	case "high", "critical":
		return "critical"
	case "medium", "warning", "low":
		return "warning"
	case "":
		return "unknown"
	default:
		return strings.ToLower(severity)
	}
}

// anomalyLocation spells where a libxfs anomaly was seen. Both fields are
// optional there, and an anomaly with neither is about the volume as a whole.
func anomalyLocation(path string, inode uint64) string {
	switch {
	case path != "" && inode != 0:
		return fmt.Sprintf("%s (inode %d)", path, inode)
	case path != "":
		return path
	case inode != 0:
		return fmt.Sprintf("inode %d", inode)
	default:
		return "volume"
	}
}
