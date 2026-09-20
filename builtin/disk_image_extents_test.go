package builtin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	libvhdi "github.com/aoiflux/libvhdi"

	"mutant/object"
)

// errFakeVHDILibrary stands for a failure inside libvhdi: a header that will
// not parse, a block allocation table that does not fit the file, an I/O error
// part way through a chain. What it is does not matter to the builtins; that it
// is reported rather than rendered as an empty answer does.
var errFakeVHDILibrary = errors.New("synthetic virtual disk failure")

const vhdiTestBlockSize = 2 * 1024 * 1024

// ---------------------------------------------------------------------------
// Against real bytes
// ---------------------------------------------------------------------------

// openRealVHDI opens a fixture through the ordinary open path, with the real
// backend in place, and closes it when the test ends.
func openRealVHDI(t *testing.T, path string) string {
	t.Helper()

	payload, errObj := unwrapPair(t, VHDIOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("vhdi_open(%s): %s", path, errObj.Inspect())
	}
	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("vhdi_open payload is not HASH. got=%T", payload)
	}
	handle := mustHashStringValue(t, hash, "handle")
	t.Cleanup(func() { VHDIClose(stringObj(handle)) })
	return handle
}

// sparseFixture writes a dynamic image of four blocks, of which the first and
// the third are stored. Blocks one and three exist nowhere in the file.
func sparseFixture(t *testing.T) (dir, path string) {
	t.Helper()

	dir = vhdFixtureDir(t)
	path = filepath.Join(dir, "sparse.vhd")

	full := make([]byte, vhdiTestBlockSize)
	for i := range full {
		full[i] = 0xAB
	}
	writeDynamicVHD(t, path, vhdiTestBlockSize, [][]byte{full, nil, full, nil}, [16]byte{9, 9, 9, 9})
	return dir, path
}

// chainFixture writes a parent holding block two and a differencing child
// holding block zero, so that the device is assembled from both files and one
// block exists in neither.
func chainFixture(t *testing.T) (dir, parent, child string) {
	t.Helper()

	dir = vhdFixtureDir(t)
	parent = filepath.Join(dir, "base.vhd")
	child = filepath.Join(dir, "snap.avhd")

	full := make([]byte, vhdiTestBlockSize)
	for i := range full {
		full[i] = 0xAB
	}
	parentID := [16]byte{7, 7, 7, 7}
	writeDynamicVHD(t, parent, vhdiTestBlockSize, [][]byte{nil, nil, full, nil}, parentID)
	writeDifferencingVHD(t, child, parent, vhdiTestBlockSize,
		[]bool{true, false, false, false}, 0xCD, [16]byte{8, 8, 8, 8}, parentID)
	return dir, parent, child
}

func extentAt(t *testing.T, payload object.Object, index int) *object.Hash {
	t.Helper()

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("payload is not HASH. got=%T", payload)
	}
	extents := mustHashArrayValue(t, hash, "extents")
	if index >= len(extents) {
		t.Fatalf("wanted extent %d of %d", index, len(extents))
	}
	entry, ok := extents[index].(*object.Hash)
	if !ok {
		t.Fatalf("extent %d is not HASH. got=%T", index, extents[index])
	}
	return entry
}

// TestARangeWithNoBytesBehindItHasNoFileOffset is the trap this family exists
// to avoid, asserted against an image whose holes are real.
//
// libvhdi leaves Extent.FileOffset at its zero value for every kind but mapped,
// and zero is a byte a caller can seek to -- the first byte of the file, which
// on a dynamic VHD is the mirrored footer. A script reading file_offset without
// checking kind would read the footer and call it disk content.
func TestARangeWithNoBytesBehindItHasNoFileOffset(t *testing.T) {
	_, path := sparseFixture(t)
	handle := openRealVHDI(t, path)

	payload, errObj := unwrapPair(t, VHDIExtents(stringObj(handle), intObj(0), intObj(4*vhdiTestBlockSize)))
	if errObj != nil {
		t.Fatalf("vhdi_extents: %s", errObj.Inspect())
	}

	want := []struct {
		kind       string
		fileOffset int64
	}{
		{vhdiExtentMapped, vhdBlockDataOffset(vhdiTestBlockSize, 0, 4)},
		{vhdiExtentZero, -1},
		{vhdiExtentMapped, vhdBlockDataOffset(vhdiTestBlockSize, 1, 4)},
		{vhdiExtentZero, -1},
	}
	for i, expected := range want {
		entry := extentAt(t, payload, i)
		if got := mustHashStringValue(t, entry, "kind"); got != expected.kind {
			t.Errorf("extent %d kind = %q, want %q", i, got, expected.kind)
		}
		if got := mustHashIntValue(t, entry, "file_offset"); got != expected.fileOffset {
			t.Errorf("extent %d file_offset = %d, want %d", i, got, expected.fileOffset)
		}
	}
}

// TestASparseImageAccountsForEveryByteOfTheDevice pins the totals: what an
// acquisition must read plus what it may skip is the whole address space, and
// neither number is the file's size on disk.
func TestASparseImageAccountsForEveryByteOfTheDevice(t *testing.T) {
	_, path := sparseFixture(t)
	handle := openRealVHDI(t, path)

	payload, errObj := unwrapPair(t, VHDIExtents(stringObj(handle), intObj(0), intObj(4*vhdiTestBlockSize)))
	if errObj != nil {
		t.Fatalf("vhdi_extents: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	mapped := mustHashIntValue(t, hash, "mapped_bytes")
	zero := mustHashIntValue(t, hash, "zero_bytes")
	size := mustHashIntValue(t, hash, "virtual_size")

	if mapped != 2*vhdiTestBlockSize {
		t.Errorf("mapped_bytes = %d, want %d", mapped, 2*vhdiTestBlockSize)
	}
	if mapped+zero != size {
		t.Errorf("mapped %d + zero %d = %d, want the device's %d", mapped, zero, mapped+zero, size)
	}
	if got := mustHashIntValue(t, hash, "unresolved_bytes"); got != 0 {
		t.Errorf("a complete chain reported %d unresolved bytes", got)
	}
	if !mustHashBoolValue(t, hash, "complete") {
		t.Errorf("a whole map of a complete chain reported itself incomplete")
	}
}

// TestTwoLinksCanBackTheSameFileOffset is why an extent carries a chain index
// and a path at all.
//
// On this chain the child's block and the parent's block sit at the same offset
// in their respective files. A map that reported only an offset would show two
// ranges of the device coming from one place, which is the limitation
// vhdi_map_offset documents and cannot get past: one file offset cannot express
// an address space assembled from several files.
func TestTwoLinksCanBackTheSameFileOffset(t *testing.T) {
	_, parent, child := chainFixture(t)
	handle := openRealVHDI(t, child)

	payload, errObj := unwrapPair(t, VHDIExtents(stringObj(handle), intObj(0), intObj(4*vhdiTestBlockSize)))
	if errObj != nil {
		t.Fatalf("vhdi_extents: %s", errObj.Inspect())
	}

	fromChild := extentAt(t, payload, 0)
	fromParent := extentAt(t, payload, 2)

	if a, b := mustHashIntValue(t, fromChild, "file_offset"), mustHashIntValue(t, fromParent, "file_offset"); a != b {
		t.Fatalf("this fixture is meant to put both blocks at one offset: %d and %d", a, b)
	}
	if got := mustHashIntValue(t, fromChild, "chain_index"); got != 0 {
		t.Errorf("the child's own block reports chain_index %d, want 0", got)
	}
	if got := mustHashIntValue(t, fromParent, "chain_index"); got != 1 {
		t.Errorf("the parent's block reports chain_index %d, want 1", got)
	}
	if got := mustHashStringValue(t, fromChild, "path"); got != child {
		t.Errorf("the child's block names %q, want %q", got, child)
	}
	if got := mustHashStringValue(t, fromParent, "path"); got != parent {
		t.Errorf("the parent's block names %q, want %q", got, parent)
	}
}

// TestOnlyWhatTheChildWroteIsChanged pins the differencing answer against an
// image where exactly one block was written by the leaf.
func TestOnlyWhatTheChildWroteIsChanged(t *testing.T) {
	_, _, child := chainFixture(t)
	handle := openRealVHDI(t, child)

	payload, errObj := unwrapPair(t, VHDIChangedExtents(stringObj(handle), intObj(1)))
	if errObj != nil {
		t.Fatalf("vhdi_changed_extents: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if got := mustHashIntValue(t, hash, "extent_count"); got != 1 {
		t.Fatalf("extent_count = %d, want the child's single block", got)
	}
	if got := mustHashIntValue(t, hash, "changed_bytes"); got != vhdiTestBlockSize {
		t.Errorf("changed_bytes = %d, want %d", got, vhdiTestBlockSize)
	}
	entry := extentAt(t, payload, 0)
	if got := mustHashIntValue(t, entry, "virtual_offset"); got != 0 {
		t.Errorf("the changed range starts at %d, want 0", got)
	}
	if !mustHashBoolValue(t, entry, "is_write") {
		t.Errorf("a range the child wrote does not report itself as a write")
	}
	if got := mustHashIntValue(t, hash, "since_chain_index"); got != 1 {
		t.Errorf("since_chain_index = %d, want 1", got)
	}
}

// TestAVhdChainCannotExpressADeletion is the honesty field, asserted where it
// is true. VHD has no block state meaning zero, so a region the guest cleared
// is recorded as belonging to the parent and reads back as the parent's old
// contents: the deletion is absent from the format, not merely from the answer.
func TestAVhdChainCannotExpressADeletion(t *testing.T) {
	_, _, child := chainFixture(t)
	handle := openRealVHDI(t, child)

	payload, errObj := unwrapPair(t, VHDIChangedExtents(stringObj(handle), intObj(1)))
	if errObj != nil {
		t.Fatalf("vhdi_changed_extents: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if mustHashBoolValue(t, hash, "deletions_expressible") {
		t.Errorf("a VHD chain claimed it could express a deletion")
	}
	if !hasWarningCode(t, hash, vhdiWarnDeletionsNotStored) {
		t.Errorf("a VHD chain did not raise %s", vhdiWarnDeletionsNotStored)
	}
	if got := mustHashIntValue(t, hash, "zeroed_by_child_bytes"); got != 0 {
		t.Errorf("a VHD chain reported %d explicitly cleared bytes, which the format cannot store", got)
	}
}

// TestAChangedSincePathResolvesToItsChainIndex pins the path-addressed form
// against the index-addressed one: the same question, the same answer, and the
// index reported so a document can name what it measured from.
func TestAChangedSincePathResolvesToItsChainIndex(t *testing.T) {
	_, parent, child := chainFixture(t)
	handle := openRealVHDI(t, child)

	payload, errObj := unwrapPair(t, VHDIChangedSince(stringObj(handle), stringObj(parent)))
	if errObj != nil {
		t.Fatalf("vhdi_changed_since: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if got := mustHashIntValue(t, hash, "since_chain_index"); got != 1 {
		t.Errorf("since_chain_index = %d, want 1", got)
	}
	if got := mustHashStringValue(t, hash, "since_path"); got != parent {
		t.Errorf("since_path = %q, want %q", got, parent)
	}
	if got := mustHashIntValue(t, hash, "changed_bytes"); got != vhdiTestBlockSize {
		t.Errorf("changed_bytes = %d, want the child's one block", got)
	}
	if hasWarningCode(t, hash, vhdiWarnIndexUnresolved) {
		t.Errorf("a path libvhdi placed in the chain was not placed here")
	}
}

// TestNothingHasBeenWrittenSinceTheLeaf keeps an empty answer apart from a
// missing one. Naming the disk that was opened is a question with a definition
// for an answer, not a finding of no change.
func TestNothingHasBeenWrittenSinceTheLeaf(t *testing.T) {
	_, _, child := chainFixture(t)
	handle := openRealVHDI(t, child)

	payload, errObj := unwrapPair(t, VHDIChangedSince(stringObj(handle), stringObj(child)))
	if errObj != nil {
		t.Fatalf("vhdi_changed_since: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if got := mustHashIntValue(t, hash, "extent_count"); got != 0 {
		t.Errorf("extent_count = %d, want nothing written since the leaf", got)
	}
	if got := mustHashIntValue(t, hash, "since_chain_index"); got != 0 {
		t.Errorf("since_chain_index = %d, want 0", got)
	}
	if !hasWarningCode(t, hash, vhdiWarnNamedDiskIsLeaf) {
		t.Errorf("an empty answer by definition did not say so")
	}
}

// TestAPathOutsideTheChainIsRefusedRatherThanAnswered. An empty list would read
// as "nothing changed", which is a different and much more reassuring claim
// than "the disk you named is not part of this device".
func TestAPathOutsideTheChainIsRefusedRatherThanAnswered(t *testing.T) {
	_, _, child := chainFixture(t)
	handle := openRealVHDI(t, child)

	_, errObj := unwrapPairNoFatal(VHDIChangedSince(stringObj(handle), stringObj("nowhere.vhd")))
	if errObj == nil {
		t.Fatalf("a path outside the chain was answered instead of refused")
	}
	if !containsSubstring(errObj.Message, "vhdi_changed_since") {
		t.Errorf("the refusal does not name the builtin: %s", errObj.Message)
	}
}

// TestAChangedIndexOutsideTheChainIsRefused. libvhdi accepts an index past the
// chain and quietly answers with everything every link wrote, which is not the
// question that was asked.
func TestAChangedIndexOutsideTheChainIsRefused(t *testing.T) {
	_, _, child := chainFixture(t)
	handle := openRealVHDI(t, child)

	for _, since := range []int64{0, -1, 2, 99} {
		_, errObj := unwrapPairNoFatal(VHDIChangedExtents(stringObj(handle), intObj(since)))
		if errObj == nil {
			t.Errorf("since_chain_index %d was answered on a chain of depth 2", since)
		}
	}
}

// TestADiskWithNoChainHasNothingToBeComparedAgainst.
func TestADiskWithNoChainHasNothingToBeComparedAgainst(t *testing.T) {
	_, path := sparseFixture(t)
	handle := openRealVHDI(t, path)

	_, errObj := unwrapPairNoFatal(VHDIChangedExtents(stringObj(handle), intObj(1)))
	if errObj == nil {
		t.Fatalf("a disk with no parent answered a question about what changed since one")
	}
}

// TestAChainNamesEveryFileTheDeviceIsMadeOf.
func TestAChainNamesEveryFileTheDeviceIsMadeOf(t *testing.T) {
	_, parent, child := chainFixture(t)
	handle := openRealVHDI(t, child)

	payload, errObj := unwrapPair(t, VHDIChain(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("vhdi_chain: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if got := mustHashIntValue(t, hash, "link_count"); got != 2 {
		t.Fatalf("link_count = %d, want 2", got)
	}
	if !mustHashBoolValue(t, hash, "complete") {
		t.Errorf("a resolved chain reported itself incomplete: %s",
			mustHashStringValue(t, hash, "incomplete_reason"))
	}

	paths := mustHashStringArray(t, hash, "paths")
	if len(paths) != 2 || paths[0] != child || paths[1] != parent {
		t.Fatalf("paths = %v, want the child then the parent", paths)
	}

	links := mustHashArrayValue(t, hash, "links")
	leaf := links[0].(*object.Hash)
	base := links[1].(*object.Hash)

	if got := mustHashStringValue(t, leaf, "disk_type"); got != "differencing" {
		t.Errorf("the leaf reports disk_type %q", got)
	}
	if got := mustHashStringValue(t, base, "disk_type"); got != "dynamic" {
		t.Errorf("the base reports disk_type %q", got)
	}
	// The creator is per link because links are made by different tools. This
	// fixture writes its own four-byte code into both.
	if got := mustHashStringValue(t, leaf, "creator_application"); got != "mtnt" {
		t.Errorf("creator_application = %q, want the code the fixture wrote", got)
	}
	if got := mustHashStringValue(t, leaf, "footer_source"); got != "trailing" {
		t.Errorf("an intact image reports footer_source %q", got)
	}
	if mustHashBoolValue(t, leaf, "footer_recovered") {
		t.Errorf("an intact image reported itself recovered")
	}
}

// TestADiscoveredTreeJoinsAChildToItsParent.
func TestADiscoveredTreeJoinsAChildToItsParent(t *testing.T) {
	dir, parent, child := chainFixture(t)

	payload, errObj := unwrapPair(t, VHDIDiscover(stringObj(dir)))
	if errObj != nil {
		t.Fatalf("vhdi_discover: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if got := mustHashIntValue(t, hash, "node_count"); got != 2 {
		t.Fatalf("node_count = %d, want 2", got)
	}
	if roots := mustHashStringArray(t, hash, "root_paths"); len(roots) != 1 || roots[0] != parent {
		t.Errorf("root_paths = %v, want just the base", roots)
	}
	if leaves := mustHashStringArray(t, hash, "leaf_paths"); len(leaves) != 1 || leaves[0] != child {
		t.Errorf("leaf_paths = %v, want just the checkpoint", leaves)
	}
	if mustHashBoolValue(t, hash, "branched") {
		t.Errorf("a single-lineage directory reported itself branched")
	}

	lineages := mustHashArrayValue(t, hash, "lineages")
	if len(lineages) != 1 {
		t.Fatalf("lineage_count = %d, want 1", len(lineages))
	}
	lineage := lineages[0].(*object.Hash)
	if !mustHashBoolValue(t, lineage, "complete") {
		t.Errorf("a lineage holding its own base reported itself incomplete")
	}
	if got := mustHashIntValue(t, lineage, "checkpoint_count"); got != 1 {
		t.Errorf("checkpoint_count = %d, want 1", got)
	}
	if got := mustHashStringValue(t, lineage, "root_path"); got != parent {
		t.Errorf("root_path = %q, want %q", got, parent)
	}
}

// TestABranchedCheckpointTreeIsReportedAndNotResolved. Two children of one
// parent are two devices, and which one a virtual machine is using is recorded
// in the machine's configuration rather than in the disks.
func TestABranchedCheckpointTreeIsReportedAndNotResolved(t *testing.T) {
	dir, parent, _ := chainFixture(t)
	sibling := filepath.Join(dir, "other.avhd")
	writeDifferencingVHD(t, sibling, parent, vhdiTestBlockSize,
		[]bool{false, true, false, false}, 0xEF, [16]byte{5, 5, 5, 5}, [16]byte{7, 7, 7, 7})

	payload, errObj := unwrapPair(t, VHDIDiscover(stringObj(dir)))
	if errObj != nil {
		t.Fatalf("vhdi_discover: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if !mustHashBoolValue(t, hash, "branched") {
		t.Fatalf("two leaves did not report a branch")
	}
	if got := len(mustHashStringArray(t, hash, "leaf_paths")); got != 2 {
		t.Errorf("leaf_paths holds %d entries, want 2", got)
	}
	if got := mustHashIntValue(t, hash, "lineage_count"); got != 2 {
		t.Errorf("lineage_count = %d, want one device per leaf", got)
	}
	if !hasWarningCode(t, hash, vhdiWarnTreeBranched) {
		t.Errorf("a branched tree did not raise %s", vhdiWarnTreeBranched)
	}
}

// TestAChildWhoseParentIsElsewhereStaysARoot.
func TestAChildWhoseParentIsElsewhereStaysARoot(t *testing.T) {
	_, _, child := chainFixture(t)

	lonely := vhdFixtureDir(t)
	moved := filepath.Join(lonely, filepath.Base(child))
	content, err := os.ReadFile(child)
	if err != nil {
		t.Fatalf("reading the child: %v", err)
	}
	if err := os.WriteFile(moved, content, 0o600); err != nil {
		t.Fatalf("writing the child: %v", err)
	}

	payload, errObj := unwrapPair(t, VHDIDiscover(stringObj(lonely)))
	if errObj != nil {
		t.Fatalf("vhdi_discover: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if roots := mustHashStringArray(t, hash, "root_paths"); len(roots) != 1 || roots[0] != moved {
		t.Errorf("root_paths = %v, want the orphan itself", roots)
	}
	if !hasWarningCode(t, hash, vhdiWarnOrphanedChild) {
		t.Errorf("a child with no parent in the directory did not raise %s", vhdiWarnOrphanedChild)
	}
	if !hasWarningCode(t, hash, vhdiWarnLineageIncomplete) {
		t.Errorf("a lineage with no base did not raise %s", vhdiWarnLineageIncomplete)
	}
}

// TestAFileThatIsNotAnImageIsKeptApartFromOneThatFailed. A machine folder holds
// configuration, memory and save-state files beside the disks; listing those as
// failures would bury the file that really would not parse.
func TestAFileThatIsNotAnImageIsKeptApartFromOneThatFailed(t *testing.T) {
	dir, _ := sparseFixture(t)

	notes := filepath.Join(dir, "machine.vmcx")
	if err := os.WriteFile(notes, []byte("not a disk"), 0o600); err != nil {
		t.Fatalf("writing the decoy: %v", err)
	}
	broken := filepath.Join(dir, "torn.vhd")
	if err := os.WriteFile(broken, make([]byte, 100), 0o600); err != nil {
		t.Fatalf("writing the broken image: %v", err)
	}

	payload, errObj := unwrapPair(t, VHDIDiscover(stringObj(dir)))
	if errObj != nil {
		t.Fatalf("vhdi_discover: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	skipped := mustHashStringArray(t, hash, "skipped")
	if len(skipped) != 1 || skipped[0] != notes {
		t.Errorf("skipped = %v, want just the non-image file", skipped)
	}
	unreadable := mustHashStringArray(t, hash, "unreadable")
	if len(unreadable) != 1 || unreadable[0] != broken {
		t.Errorf("unreadable = %v, want just the image that would not parse", unreadable)
	}
	if !hasWarningCode(t, hash, vhdiWarnImageUnreadable) {
		t.Errorf("an unreadable image did not raise %s", vhdiWarnImageUnreadable)
	}
	if mustHashBoolValue(t, hash, "complete") {
		t.Errorf("a scan that could not read one of its files called itself complete")
	}
}

// TestAProbeReadsTheHeadersAndNothingElse.
func TestAProbeReadsTheHeadersAndNothingElse(t *testing.T) {
	_, path := sparseFixture(t)

	payload, errObj := unwrapPair(t, VHDIProbe(stringObj(path)))
	if errObj != nil {
		t.Fatalf("vhdi_probe: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if got := mustHashStringValue(t, hash, "format"); got != "VHD" {
		t.Errorf("format = %q", got)
	}
	if got := mustHashStringValue(t, hash, "disk_type"); got != "dynamic" {
		t.Errorf("disk_type = %q", got)
	}
	if got := mustHashStringValue(t, hash, "role"); got != "base" {
		t.Errorf("role = %q, want base", got)
	}
	if !mustHashBoolValue(t, hash, "readable") {
		t.Errorf("a readable image reported itself unreadable")
	}
	// A header-only probe is cheap precisely because the file is larger than
	// the structures it read, and smaller than the device it describes.
	virtual := mustHashIntValue(t, hash, "virtual_size")
	file := mustHashIntValue(t, hash, "file_size")
	if virtual != 4*vhdiTestBlockSize {
		t.Errorf("virtual_size = %d", virtual)
	}
	if file >= virtual {
		t.Errorf("a sparse image's file (%d) is not smaller than its device (%d)", file, virtual)
	}
}

// TestAProbeOfSomethingThatIsNotAnImageIsRefused.
func TestAProbeOfSomethingThatIsNotAnImageIsRefused(t *testing.T) {
	dir := vhdFixtureDir(t)
	path := filepath.Join(dir, "notes.vhd")
	if err := os.WriteFile(path, []byte("nothing to see"), 0o600); err != nil {
		t.Fatalf("writing the decoy: %v", err)
	}

	_, errObj := unwrapPairNoFatal(VHDIProbe(stringObj(path)))
	if errObj == nil {
		t.Fatalf("a file that is not an image was described instead of refused")
	}
}

// TestAWindowPastTheDeviceIsClampedAndSaysSo.
func TestAWindowPastTheDeviceIsClampedAndSaysSo(t *testing.T) {
	_, path := sparseFixture(t)
	handle := openRealVHDI(t, path)

	payload, errObj := unwrapPair(t, VHDIExtents(stringObj(handle), intObj(0), intObj(1<<40)))
	if errObj != nil {
		t.Fatalf("vhdi_extents: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)

	if !hasWarningCode(t, hash, vhdiWarnWindowClamped) {
		t.Errorf("a window past the end of the device did not raise %s", vhdiWarnWindowClamped)
	}
	if got := mustHashIntValue(t, hash, "length"); got != 1<<40 {
		t.Errorf("length = %d; the window is echoed as asked for", got)
	}
	total := mustHashIntValue(t, hash, "mapped_bytes") + mustHashIntValue(t, hash, "zero_bytes")
	if total != 4*vhdiTestBlockSize {
		t.Errorf("the totals cover %d bytes, want the device's %d", total, 4*vhdiTestBlockSize)
	}
}

// TestAWindowOfNothingMapsNothing. Zero is a length, not a request for the
// whole device; nothing in this language reads a zero length as "everything".
func TestAWindowOfNothingMapsNothing(t *testing.T) {
	_, path := sparseFixture(t)
	handle := openRealVHDI(t, path)

	payload, errObj := unwrapPair(t, VHDIExtents(stringObj(handle), intObj(0), intObj(0)))
	if errObj != nil {
		t.Fatalf("vhdi_extents: %s", errObj.Inspect())
	}
	hash := payload.(*object.Hash)
	if got := mustHashIntValue(t, hash, "extent_count"); got != 0 {
		t.Errorf("a zero-length window produced %d extents", got)
	}
}

// ---------------------------------------------------------------------------
// The renderers, without a disk
// ---------------------------------------------------------------------------

// TestAClearedRangeIsAWriteAndAnUntouchedOneIsNot. Both read back as zeroes and
// they are opposite facts: one is a disk having done something, the other is no
// disk ever having done anything there.
func TestAClearedRangeIsAWriteAndAnUntouchedOneIsNot(t *testing.T) {
	var list vhdiExtentList
	list.add(libvhdi.Extent{VirtualOffset: 0, Length: 100, Kind: libvhdi.ExtentZero})
	list.add(libvhdi.Extent{VirtualOffset: 100, Length: 200, Kind: libvhdi.ExtentZeroedByChild})

	if list.ZeroBytes != 100 || list.ZeroedByChildBytes != 200 {
		t.Fatalf("zero=%d zeroed_by_child=%d; the two are counted apart",
			list.ZeroBytes, list.ZeroedByChildBytes)
	}
	untouched, cleared := list.Extents[0], list.Extents[1]
	if untouched.IsWrite || !untouched.ReadsAsZero {
		t.Errorf("an untouched range: is_write=%v reads_as_zero=%v", untouched.IsWrite, untouched.ReadsAsZero)
	}
	if !cleared.IsWrite || !cleared.ReadsAsZero {
		t.Errorf("a cleared range: is_write=%v reads_as_zero=%v", cleared.IsWrite, cleared.ReadsAsZero)
	}
	if cleared.Kind != vhdiExtentZeroedByChild {
		t.Errorf("kind = %q; the spelling a script matches on carries no hyphen", cleared.Kind)
	}
}

// TestTheExtentCapKeepsTheTotalsHonestPastIt.
func TestTheExtentCapKeepsTheTotalsHonestPastIt(t *testing.T) {
	var list vhdiExtentList
	const over = vhdiMaxExtents + 7
	for i := 0; i < over; i++ {
		list.add(libvhdi.Extent{
			VirtualOffset: int64(i) * 512,
			Length:        512,
			Kind:          libvhdi.ExtentMapped,
			FileOffset:    int64(i) * 512,
		})
	}

	if len(list.Extents) != vhdiMaxExtents {
		t.Errorf("rendered %d extents, want the cap of %d", len(list.Extents), vhdiMaxExtents)
	}
	if list.Count != over {
		t.Errorf("extent_count = %d, want every extent found: %d", list.Count, over)
	}
	if !list.Truncated {
		t.Errorf("a capped list did not report itself truncated")
	}
	if list.MappedBytes != over*512 {
		t.Errorf("mapped_bytes = %d, want the total over all %d extents", list.MappedBytes, over)
	}
}

// TestTheFirstReasonAnExtentAnswerStoppedIsTheOneKept. A range nothing can
// describe is a deeper gap than a list that was too long to print, so it is the
// reason the answer carries.
func TestTheFirstReasonAnExtentAnswerStoppedIsTheOneKept(t *testing.T) {
	var list vhdiExtentList
	list.add(libvhdi.Extent{Length: 4096, Kind: libvhdi.ExtentUnresolved, ChainIndex: 2})
	for i := 0; i <= vhdiMaxExtents; i++ {
		list.add(libvhdi.Extent{Length: 512, Kind: libvhdi.ExtentMapped})
	}

	findings := vhdiFindings{Complete: true}
	vhdiListFindings(&findings, list, "image.vhdx")

	if findings.Complete {
		t.Fatalf("an answer with an unresolved range called itself complete")
	}
	if !containsSubstring(findings.IncompleteReason, "parent") {
		t.Errorf("incomplete_reason = %q, want the unresolved range", findings.IncompleteReason)
	}
	if len(findings.Warnings) != 2 {
		t.Fatalf("want both the unresolved range and the truncation, got %d", len(findings.Warnings))
	}
}

// TestAnUnresolvedRangeIsNeitherMappedNorZero.
func TestAnUnresolvedRangeIsNeitherMappedNorZero(t *testing.T) {
	var list vhdiExtentList
	list.add(libvhdi.Extent{Length: 8192, Kind: libvhdi.ExtentUnresolved, ChainIndex: 3})

	if list.UnresolvedBytes != 8192 {
		t.Errorf("unresolved_bytes = %d", list.UnresolvedBytes)
	}
	if list.MappedBytes != 0 || list.ZeroBytes != 0 {
		t.Errorf("an unresolved range was counted as mapped (%d) or zero (%d)", list.MappedBytes, list.ZeroBytes)
	}
	entry := list.Extents[0]
	if entry.FileOffset != -1 {
		t.Errorf("file_offset = %d, want -1: there is no file", entry.FileOffset)
	}
	if entry.Path != "" {
		t.Errorf("path = %q; the file that would back it is the one that is missing", entry.Path)
	}
	if entry.ChainIndex != 3 {
		t.Errorf("chain_index = %d, want the index of the missing link", entry.ChainIndex)
	}
}

// TestOnlyTheLinksBeingReportedOnDecideWhetherDeletionsAreExpressible.
//
// The real-image test above proves the VHD case against bytes; this one covers
// the two the fixtures cannot reach, since nothing here writes a VHDX. A VHDX
// chain can record a clear, and a VHD base sitting under a VHDX checkpoint does
// not stop that checkpoint from recording its own.
func TestOnlyTheLinksBeingReportedOnDecideWhetherDeletionsAreExpressible(t *testing.T) {
	vhdx := libvhdi.ChainEntry{Format: libvhdi.FormatVHDX, Path: "snap.avhdx"}
	vhd := libvhdi.ChainEntry{Format: libvhdi.FormatVHD, Path: "base.vhd"}

	cases := []struct {
		name      string
		chain     []libvhdi.ChainEntry
		reporting int64
		want      int64
	}{
		{"a VHDX checkpoint over a VHDX base", []libvhdi.ChainEntry{vhdx, vhdx}, 1, -1},
		{"a VHDX checkpoint over a VHD base", []libvhdi.ChainEntry{vhdx, vhd}, 1, -1},
		{"reporting on the VHD base as well", []libvhdi.ChainEntry{vhdx, vhd}, 2, 1},
		{"a VHD checkpoint", []libvhdi.ChainEntry{vhd, vhd}, 1, 0},
		{"nothing being reported on", []libvhdi.ChainEntry{vhd, vhd}, 0, -1},
		{"a reporting count past the chain", []libvhdi.ChainEntry{vhdx}, 9, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := vhdiFirstVHDLink(tc.chain, tc.reporting); got != tc.want {
				t.Errorf("first VHD link = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestAZeroGUIDIsNotAnIdentifier. Rendered in full, the zero GUID invites a
// reader to match two images that each recorded nothing.
func TestAZeroGUIDIsNotAnIdentifier(t *testing.T) {
	if got := vhdiGUID([16]byte{}); got != "" {
		t.Errorf("the zero GUID rendered as %q", got)
	}
	if got := vhdiGUID([16]byte{1}); got == "" {
		t.Errorf("a real GUID rendered as nothing")
	}
}

// TestTheFooterCopyAnImageWasReadFromIsNamed. Anything but the trailing copy
// means the image is damaged even though it opened, and an acquisition record
// that does not say so presents a recovered read as an intact one.
func TestTheFooterCopyAnImageWasReadFromIsNamed(t *testing.T) {
	cases := []struct {
		source    libvhdi.FooterSource
		name      string
		recovered bool
	}{
		{libvhdi.FooterSourceTrailing, "trailing", false},
		{libvhdi.FooterSourceTrailingLegacy, "trailing_legacy_511", true},
		{libvhdi.FooterSourceMirror, "mirror_at_zero", true},
		{libvhdi.FooterSourceUnknown, "unknown", false},
	}
	for _, tc := range cases {
		if got := vhdiFooterSourceName(tc.source); got != tc.name {
			t.Errorf("%v rendered as %q, want %q", tc.source, got, tc.name)
		}
		if got := tc.source.Recovered(); got != tc.recovered {
			t.Errorf("%v recovered = %v", tc.source, got)
		}
		if strings.ContainsAny(tc.name, "- ") {
			t.Errorf("%q carries punctuation a script would have to match on", tc.name)
		}
	}
}

// TestAnImageWhoseExtensionDisagreesWithItsTypeIsReported. Hyper-V names a
// checkpoint .avhdx by convention, and the convention is not the format: the
// disk type decides, and a disagreement means the file was renamed or converted.
func TestAnImageWhoseExtensionDisagreesWithItsTypeIsReported(t *testing.T) {
	cases := []struct {
		name           string
		checkpointExt  bool
		isDifferencing bool
		want           bool
	}{
		{"a checkpoint named as one", true, true, false},
		{"a base named as one", false, false, false},
		{"a base wearing a checkpoint's extension", true, false, true},
		{"a checkpoint wearing a base's extension", false, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := vhdiFindings{Complete: true}
			vhdiImageFindings(&findings, vhdiImageInfo{
				Path:                   "image.vhd",
				Readable:               true,
				LinkIdentity:           "1-2-3",
				HasCheckpointExtension: tc.checkpointExt,
				IsDifferencing:         tc.isDifferencing,
			})
			if got := findingsHaveCode(findings, vhdiWarnExtensionMismatch); got != tc.want {
				t.Errorf("%s raised %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestAnUnreadableImageRaisesOnlyThatItCouldNotBeRead. Every other check below
// reads a field that a failed probe left at its zero value, so running them
// would report a file as recording no link identity when nothing was read from
// it at all.
func TestAnUnreadableImageRaisesOnlyThatItCouldNotBeRead(t *testing.T) {
	findings := vhdiFindings{Complete: true}
	vhdiImageFindings(&findings, vhdiImageInfo{Path: "torn.vhd", Readable: false, Error: "bad signature"})

	if len(findings.Warnings) != 1 {
		t.Fatalf("an unreadable image raised %d warnings, want only that it could not be read: %+v",
			len(findings.Warnings), findings.Warnings)
	}
	if findings.Warnings[0].Code != vhdiWarnImageUnreadable {
		t.Errorf("code = %q", findings.Warnings[0].Code)
	}
	if findings.Warnings[0].Detail != "bad signature" {
		t.Errorf("the library's own reason was not carried: %q", findings.Warnings[0].Detail)
	}
}

// TestAPathIsPlacedInTheChainByItsResolvedForm. A chain records the path an
// image was opened from, and a script naming the same file differently has
// named the same file.
func TestAPathIsPlacedInTheChainByItsResolvedForm(t *testing.T) {
	dir := vhdFixtureDir(t)
	absolute := filepath.Join(dir, "base.vhd")
	chain := []libvhdi.ChainEntry{
		{Index: 0, Path: filepath.Join(dir, "snap.avhd")},
		{Index: 1, Path: absolute},
	}

	if got := vhdiChainIndexOf(chain, absolute); got != 1 {
		t.Errorf("an absolute path resolved to %d, want 1", got)
	}
	if got := vhdiChainIndexOf(chain, filepath.Join(dir, ".", "base.vhd")); got != 1 {
		t.Errorf("an uncleaned path resolved to %d, want 1", got)
	}
	if got := vhdiChainIndexOf(chain, filepath.Join(dir, "absent.vhd")); got != -1 {
		t.Errorf("a path outside the chain resolved to %d, want -1", got)
	}
	// An entry with no path is a disk opened from a bare reader. The empty
	// string normalises to the working directory, which is a real place, so a
	// pathless entry must not be reachable by naming nothing.
	if got := vhdiChainIndexOf([]libvhdi.ChainEntry{{Index: 0}}, ""); got != -1 {
		t.Errorf("an empty argument matched a pathless entry at %d", got)
	}
}

// ---------------------------------------------------------------------------
// Dispatch, arity and error propagation
// ---------------------------------------------------------------------------

func installFakeVHDIHandle(t *testing.T, backend fakeVHDIBackend) string {
	t.Helper()

	installFakeVHDIBackend(t, backend)
	payload, errObj := unwrapPair(t, VHDIOpen(stringObj("synthetic.vhdx")))
	if errObj != nil {
		t.Fatalf("vhdi_open: %s", errObj.Inspect())
	}
	return mustHashStringValue(t, payload.(*object.Hash), "handle")
}

// TestEveryVhdiExtentBuiltinReturnsTheDeclaredFields. The registry promises the
// editor a shape; a builtin that returns a different one makes hover, signature
// help and every report generator wrong at once.
func TestEveryVhdiExtentBuiltinReturnsTheDeclaredFields(t *testing.T) {
	t.Run(BuiltinNameVhdiExtents, func(t *testing.T) {
		handle := installFakeVHDIHandle(t, fakeVHDIBackend{session: &fakeVHDISession{}})
		payload, errObj := unwrapPair(t, VHDIExtents(stringObj(handle), intObj(0), intObj(4096)))
		if errObj != nil {
			t.Fatalf("%s", errObj.Inspect())
		}
		assertDeclaredFields(t, BuiltinNameVhdiExtents, payload, handle)
	})

	t.Run(BuiltinNameVhdiChain, func(t *testing.T) {
		handle := installFakeVHDIHandle(t, fakeVHDIBackend{session: &fakeVHDISession{}})
		payload, errObj := unwrapPair(t, VHDIChain(stringObj(handle)))
		if errObj != nil {
			t.Fatalf("%s", errObj.Inspect())
		}
		assertDeclaredFields(t, BuiltinNameVhdiChain, payload, handle)
	})

	t.Run(BuiltinNameVhdiChangedExtents, func(t *testing.T) {
		handle := installFakeVHDIHandle(t, fakeVHDIBackend{session: &fakeVHDISession{}})
		payload, errObj := unwrapPair(t, VHDIChangedExtents(stringObj(handle), intObj(1)))
		if errObj != nil {
			t.Fatalf("%s", errObj.Inspect())
		}
		assertDeclaredFields(t, BuiltinNameVhdiChangedExtents, payload, handle)
	})

	t.Run(BuiltinNameVhdiChangedSince, func(t *testing.T) {
		handle := installFakeVHDIHandle(t, fakeVHDIBackend{session: &fakeVHDISession{}})
		payload, errObj := unwrapPair(t, VHDIChangedSince(stringObj(handle), stringObj("base.vhdx")))
		if errObj != nil {
			t.Fatalf("%s", errObj.Inspect())
		}
		assertDeclaredFields(t, BuiltinNameVhdiChangedSince, payload, handle)
	})

	t.Run(BuiltinNameVhdiProbe, func(t *testing.T) {
		installFakeVHDIBackend(t, fakeVHDIBackend{})
		payload, errObj := unwrapPair(t, VHDIProbe(stringObj("image.vhdx")))
		if errObj != nil {
			t.Fatalf("%s", errObj.Inspect())
		}
		assertDeclaredFieldsNoHandle(t, BuiltinNameVhdiProbe, payload)
	})

	t.Run(BuiltinNameVhdiDiscover, func(t *testing.T) {
		installFakeVHDIBackend(t, fakeVHDIBackend{})
		payload, errObj := unwrapPair(t, VHDIDiscover(stringObj("C:/machines")))
		if errObj != nil {
			t.Fatalf("%s", errObj.Inspect())
		}
		assertDeclaredFieldsNoHandle(t, BuiltinNameVhdiDiscover, payload)
	})
}

// TestEachVhdiExtentBuiltinAsksItsOwnQuestion pins the dispatch: four methods
// on one session with one handle between them is exactly the shape where a
// copied line answers a different question and nothing looks wrong.
func TestEachVhdiExtentBuiltinAsksItsOwnQuestion(t *testing.T) {
	var (
		windows [][2]int64
		indices []int64
		paths   []string
		probed  []string
		dirs    []string
	)
	session := &fakeVHDISession{
		extentsWindow:    &windows,
		changedIndex:     &indices,
		changedSincePath: &paths,
	}
	handle := installFakeVHDIHandle(t, fakeVHDIBackend{
		session:     session,
		probePath:   &probed,
		discoverDir: &dirs,
	})

	if _, errObj := unwrapPair(t, VHDIExtents(stringObj(handle), intObj(4096), intObj(8192))); errObj != nil {
		t.Fatalf("%s", errObj.Inspect())
	}
	if _, errObj := unwrapPair(t, VHDIChangedExtents(stringObj(handle), intObj(2))); errObj != nil {
		t.Fatalf("%s", errObj.Inspect())
	}
	if _, errObj := unwrapPair(t, VHDIChangedSince(stringObj(handle), stringObj("D:/vm/base.vhdx"))); errObj != nil {
		t.Fatalf("%s", errObj.Inspect())
	}
	if _, errObj := unwrapPair(t, VHDIProbe(stringObj("D:/vm/snap.avhdx"))); errObj != nil {
		t.Fatalf("%s", errObj.Inspect())
	}
	if _, errObj := unwrapPair(t, VHDIDiscover(stringObj("D:/vm"))); errObj != nil {
		t.Fatalf("%s", errObj.Inspect())
	}

	if len(windows) != 1 || windows[0] != [2]int64{4096, 8192} {
		t.Errorf("the window reached the session as %v", windows)
	}
	if len(indices) != 1 || indices[0] != 2 {
		t.Errorf("the chain index reached the session as %v", indices)
	}
	if len(paths) != 1 || paths[0] != "D:/vm/base.vhdx" {
		t.Errorf("the path reached the session as %v", paths)
	}
	if len(probed) != 1 || probed[0] != "D:/vm/snap.avhdx" {
		t.Errorf("the probe path reached the backend as %v", probed)
	}
	if len(dirs) != 1 || dirs[0] != "D:/vm" {
		t.Errorf("the directory reached the backend as %v", dirs)
	}
}

// TestAVirtualDiskLibraryErrorIsReportedAndNotRendered. An empty extent map is
// a claim that the device is entirely sparse, which is not what a parse failure
// means.
func TestAVirtualDiskLibraryErrorIsReportedAndNotRendered(t *testing.T) {
	cases := []struct {
		name    string
		backend fakeVHDIBackend
		call    func(handle string) object.Object
	}{
		{BuiltinNameVhdiExtents,
			fakeVHDIBackend{session: &fakeVHDISession{extentsErr: errFakeVHDILibrary}},
			func(h string) object.Object { return VHDIExtents(stringObj(h), intObj(0), intObj(512)) }},
		{BuiltinNameVhdiChain,
			fakeVHDIBackend{session: &fakeVHDISession{chainErr: errFakeVHDILibrary}},
			func(h string) object.Object { return VHDIChain(stringObj(h)) }},
		{BuiltinNameVhdiChangedExtents,
			fakeVHDIBackend{session: &fakeVHDISession{changedErr: errFakeVHDILibrary}},
			func(h string) object.Object { return VHDIChangedExtents(stringObj(h), intObj(1)) }},
		{BuiltinNameVhdiChangedSince,
			fakeVHDIBackend{session: &fakeVHDISession{changedSinceErr: errFakeVHDILibrary}},
			func(h string) object.Object { return VHDIChangedSince(stringObj(h), stringObj("base.vhdx")) }},
		{BuiltinNameVhdiProbe,
			fakeVHDIBackend{session: &fakeVHDISession{}, probeErr: errFakeVHDILibrary},
			func(string) object.Object { return VHDIProbe(stringObj("image.vhdx")) }},
		{BuiltinNameVhdiDiscover,
			fakeVHDIBackend{session: &fakeVHDISession{}, discoverErr: errFakeVHDILibrary},
			func(string) object.Object { return VHDIDiscover(stringObj("C:/machines")) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handle := installFakeVHDIHandle(t, tc.backend)
			payload, errObj := unwrapPairNoFatal(tc.call(handle))
			if errObj == nil {
				t.Fatalf("%s rendered an answer over a library failure: %s", tc.name, payload.Inspect())
			}
			if !containsSubstring(errObj.Message, tc.name) {
				t.Errorf("the refusal does not name the builtin: %s", errObj.Message)
			}
			if !containsSubstring(errObj.Message, errFakeVHDILibrary.Error()) {
				t.Errorf("the library's own reason was dropped: %s", errObj.Message)
			}
		})
	}
}

// TestEveryVhdiExtentBuiltinChecksItsArity.
func TestEveryVhdiExtentBuiltinChecksItsArity(t *testing.T) {
	handle := installFakeVHDIHandle(t, fakeVHDIBackend{session: &fakeVHDISession{}})

	cases := []struct {
		name string
		call func() object.Object
	}{
		{BuiltinNameVhdiExtents, func() object.Object { return VHDIExtents(stringObj(handle), intObj(0)) }},
		{BuiltinNameVhdiChain, func() object.Object { return VHDIChain(stringObj(handle), intObj(0)) }},
		{BuiltinNameVhdiChangedExtents, func() object.Object { return VHDIChangedExtents(stringObj(handle)) }},
		{BuiltinNameVhdiChangedSince, func() object.Object { return VHDIChangedSince(stringObj(handle)) }},
		{BuiltinNameVhdiProbe, func() object.Object { return VHDIProbe() }},
		{BuiltinNameVhdiDiscover, func() object.Object { return VHDIDiscover(stringObj("a"), stringObj("b")) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, errObj := unwrapPairNoFatal(tc.call())
			if errObj == nil {
				t.Fatalf("%s accepted the wrong number of arguments", tc.name)
			}
			if !containsSubstring(errObj.Message, "wrong number of arguments") {
				t.Errorf("%s: %s", tc.name, errObj.Message)
			}
		})
	}
}

// TestAnExtentArgumentOfTheWrongTypeIsRefused.
func TestAnExtentArgumentOfTheWrongTypeIsRefused(t *testing.T) {
	handle := installFakeVHDIHandle(t, fakeVHDIBackend{session: &fakeVHDISession{}})

	cases := []struct {
		name string
		call func() object.Object
	}{
		{"extents offset", func() object.Object { return VHDIExtents(stringObj(handle), stringObj("0"), intObj(1)) }},
		{"extents length", func() object.Object { return VHDIExtents(stringObj(handle), intObj(0), stringObj("1")) }},
		{"changed index", func() object.Object { return VHDIChangedExtents(stringObj(handle), stringObj("1")) }},
		{"changed_since path", func() object.Object { return VHDIChangedSince(stringObj(handle), intObj(1)) }},
		{"probe path", func() object.Object { return VHDIProbe(intObj(1)) }},
		{"discover dir", func() object.Object { return VHDIDiscover(intObj(1)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, errObj := unwrapPairNoFatal(tc.call()); errObj == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
		})
	}
}

// TestAnExtentWindowMustBeNonNegative.
func TestAnExtentWindowMustBeNonNegative(t *testing.T) {
	handle := installFakeVHDIHandle(t, fakeVHDIBackend{session: &fakeVHDISession{}})

	if _, errObj := unwrapPairNoFatal(VHDIExtents(stringObj(handle), intObj(-1), intObj(512))); errObj == nil {
		t.Errorf("a negative offset was accepted")
	}
	if _, errObj := unwrapPairNoFatal(VHDIExtents(stringObj(handle), intObj(0), intObj(-512))); errObj == nil {
		t.Errorf("a negative length was accepted")
	}
}

// TestAnEmptyChangedSincePathIsRefused. An empty path normalises to the working
// directory, and a disk is never there.
func TestAnEmptyChangedSincePathIsRefused(t *testing.T) {
	handle := installFakeVHDIHandle(t, fakeVHDIBackend{session: &fakeVHDISession{}})

	if _, errObj := unwrapPairNoFatal(VHDIChangedSince(stringObj(handle), stringObj("   "))); errObj == nil {
		t.Errorf("an empty path was accepted")
	}
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func hasWarningCode(t *testing.T, hash *object.Hash, code string) bool {
	t.Helper()
	for _, got := range mustHashStringArray(t, hash, "warning_codes") {
		if got == code {
			return true
		}
	}
	return false
}

func findingsHaveCode(findings vhdiFindings, code string) bool {
	for _, warning := range findings.Warnings {
		if warning.Code == code {
			return true
		}
	}
	return false
}
