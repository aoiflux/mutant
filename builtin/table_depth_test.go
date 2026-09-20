package builtin

import (
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mutant/object"
)

// The images in this file are built rather than checked in, so every assertion
// can point at the byte that produces it. They are small on purpose: the
// partition table is the first few sectors and the last few, and nothing here
// reads what lies between them.

const tableSectorSize = 512

type testMBREntry struct {
	Type     byte
	StartLBA uint32
	SizeLBA  uint32
}

func writeTestMBRSector(sector []byte, entries []testMBREntry) {
	binary.LittleEndian.PutUint16(sector[510:512], 0xAA55)
	for i, entry := range entries {
		if i >= 4 {
			break
		}
		off := 446 + i*16
		sector[off+4] = entry.Type
		binary.LittleEndian.PutUint32(sector[off+8:off+12], entry.StartLBA)
		binary.LittleEndian.PutUint32(sector[off+12:off+16], entry.SizeLBA)
	}
}

// testGUIDBytes encodes a GUID into the mixed-endian layout GPT stores: the
// first three groups little-endian, the last two big-endian. Getting this wrong
// produces a table that parses and names every partition type incorrectly,
// which is why the test writes real GUIDs rather than arbitrary bytes.
func testGUIDBytes(t *testing.T, guid string) []byte {
	t.Helper()

	groups := strings.Split(guid, "-")
	if len(groups) != 5 {
		t.Fatalf("malformed guid %q", guid)
	}
	raw := make([][]byte, 5)
	for i, group := range groups {
		decoded, err := hex.DecodeString(group)
		if err != nil {
			t.Fatalf("malformed guid %q: %s", guid, err)
		}
		raw[i] = decoded
	}

	out := make([]byte, 0, 16)
	for _, i := range []int{0, 1, 2} {
		for j := len(raw[i]) - 1; j >= 0; j-- {
			out = append(out, raw[i][j])
		}
	}
	out = append(out, raw[3]...)
	out = append(out, raw[4]...)
	if len(out) != 16 {
		t.Fatalf("guid %q encoded to %d bytes", guid, len(out))
	}
	return out
}

type testGPTEntry struct {
	TypeGUID string
	Name     string
	StartLBA uint64
	EndLBA   uint64
}

type testGPTOpts struct {
	Sectors int
	Entries []testGPTEntry
	// Hybrid are real MBR records written beside the protective 0xEE one, which
	// is what makes the disk a hybrid rather than a plain GPT.
	Hybrid []testMBREntry
	// NoBackup leaves the tail of the disk empty. Every real tool writes a
	// secondary GPT, so this is what a truncated acquisition looks like.
	NoBackup bool
	// DivergeBackup rewrites one entry in the secondary array and re-checksums
	// only that copy, so both parse and the two disagree.
	DivergeBackup bool
}

const (
	testGPTEntryCount  = 128
	testGPTEntrySize   = 128
	testGPTTableBlocks = testGPTEntryCount * testGPTEntrySize / tableSectorSize
)

func buildTestGPTImage(t *testing.T, opts testGPTOpts) []byte {
	t.Helper()

	if opts.Sectors == 0 {
		opts.Sectors = 4096
	}
	disk := make([]byte, opts.Sectors*tableSectorSize)
	lastLBA := uint64(opts.Sectors - 1)

	entries := make([]testMBREntry, 4)
	entries[0] = testMBREntry{Type: 0xEE, StartLBA: 1, SizeLBA: 0xFFFFFFFF}
	for i, hybrid := range opts.Hybrid {
		if i+1 > 3 {
			break
		}
		entries[i+1] = hybrid
	}
	writeTestMBRSector(disk[:tableSectorSize], entries)

	writeTestGPTAt(t, disk, 1, 2, lastLBA, opts, false)
	if !opts.NoBackup {
		writeTestGPTAt(t, disk, lastLBA, lastLBA-testGPTTableBlocks, lastLBA, opts, true)
		if opts.DivergeBackup {
			// One byte in one entry of the secondary array, then that copy's
			// own checksums. The primary is untouched, so both headers validate
			// and the entry-table CRCs no longer agree.
			array := int(lastLBA-testGPTTableBlocks) * tableSectorSize
			disk[array+32]++
			setTestGPTCRCs(disk, int(lastLBA))
		}
	}

	return disk
}

func writeTestGPTAt(t *testing.T, disk []byte, headerLBA, tableLBA, lastLBA uint64, opts testGPTOpts, backup bool) {
	t.Helper()

	header := disk[int(headerLBA)*tableSectorSize : int(headerLBA)*tableSectorSize+tableSectorSize]
	copy(header[0:8], "EFI PART")
	binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:16], 92)
	binary.LittleEndian.PutUint64(header[24:32], headerLBA)
	if backup {
		binary.LittleEndian.PutUint64(header[32:40], 1)
	} else {
		binary.LittleEndian.PutUint64(header[32:40], lastLBA)
	}
	binary.LittleEndian.PutUint64(header[40:48], 2+testGPTTableBlocks)
	binary.LittleEndian.PutUint64(header[48:56], lastLBA-testGPTTableBlocks-1)
	copy(header[56:72], testGUIDBytes(t, "0a0b0c0d-0e0f-4a4b-8c8d-101112131415"))
	binary.LittleEndian.PutUint64(header[72:80], tableLBA)
	binary.LittleEndian.PutUint32(header[80:84], testGPTEntryCount)
	binary.LittleEndian.PutUint32(header[84:88], testGPTEntrySize)

	base := int(tableLBA) * tableSectorSize
	for i, entry := range opts.Entries {
		off := base + i*testGPTEntrySize
		slot := disk[off : off+testGPTEntrySize]
		copy(slot[0:16], testGUIDBytes(t, entry.TypeGUID))
		copy(slot[16:32], testGUIDBytes(t, "00000000-0000-4000-8000-00000000000"+string(rune('1'+i))))
		binary.LittleEndian.PutUint64(slot[32:40], entry.StartLBA)
		binary.LittleEndian.PutUint64(slot[40:48], entry.EndLBA)
		for j, r := range []rune(entry.Name) {
			if 56+j*2+2 > len(slot) {
				break
			}
			binary.LittleEndian.PutUint16(slot[56+j*2:58+j*2], uint16(r))
		}
	}

	setTestGPTCRCs(disk, int(headerLBA))
}

func setTestGPTCRCs(disk []byte, headerLBA int) {
	header := disk[headerLBA*tableSectorSize : headerLBA*tableSectorSize+tableSectorSize]
	tableLBA := binary.LittleEndian.Uint64(header[72:80])

	start := int(tableLBA) * tableSectorSize
	total := testGPTEntryCount * testGPTEntrySize
	binary.LittleEndian.PutUint32(header[88:92], crc32.ChecksumIEEE(disk[start:start+total]))

	scratch := make([]byte, 92)
	copy(scratch, header[:92])
	binary.LittleEndian.PutUint32(scratch[16:20], 0)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(scratch))
}

type testBSDPart struct {
	SizeLBA  uint32
	StartLBA uint32
	FSType   byte
}

func writeTestBSDLabel(sector []byte, parts []testBSDPart) {
	binary.LittleEndian.PutUint32(sector[0:4], 0x82564557)
	binary.LittleEndian.PutUint32(sector[132:136], 0x82564557)
	binary.LittleEndian.PutUint16(sector[138:140], uint16(len(parts)))
	for i, part := range parts {
		off := 148 + i*16
		binary.LittleEndian.PutUint32(sector[off:off+4], part.SizeLBA)
		binary.LittleEndian.PutUint32(sector[off+4:off+8], part.StartLBA)
		sector[off+12] = part.FSType
	}
}

// The slice a nested disklabel lives in. Addresses inside the label are
// relative to the slice, which is the convention that makes the inner table's
// own offset load-bearing: read it as disk-absolute and every entry is 64
// sectors too early.
const (
	testNestedSliceStart = 64
	testNestedSliceSize  = 512
)

func buildTestNestedBSDImage() []byte {
	sectors := testNestedSliceStart + testNestedSliceSize + 2
	disk := make([]byte, sectors*tableSectorSize)

	writeTestMBRSector(disk[:tableSectorSize], []testMBREntry{
		{Type: 0xA5, StartLBA: testNestedSliceStart, SizeLBA: testNestedSliceSize},
	})

	label := (testNestedSliceStart + 1) * tableSectorSize
	writeTestBSDLabel(disk[label:label+tableSectorSize], []testBSDPart{
		{SizeLBA: 128, StartLBA: 16, FSType: 7},
		{SizeLBA: 64, StartLBA: 200, FSType: 1},
	})

	return disk
}

// buildTestMBRPlusBSDImage is media on which two schemes parse cleanly and
// neither is wrong: an MBR in sector 0 and a disklabel in sector 1.
func buildTestMBRPlusBSDImage() []byte {
	disk := make([]byte, 4096*tableSectorSize)
	writeTestMBRSector(disk[:tableSectorSize], []testMBREntry{
		{Type: 0x83, StartLBA: 2048, SizeLBA: 1024},
	})
	writeTestBSDLabel(disk[tableSectorSize:2*tableSectorSize], []testBSDPart{
		{SizeLBA: 1024, StartLBA: 3000, FSType: 7},
	})
	return disk
}

func writeTableImage(t *testing.T, name string, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %s", name, err)
	}
	return path
}

// tableOpenImage opens through the real backend and registers the close, so no
// test leaves a descriptor or a handle behind.
func tableOpenImage(t *testing.T, open func(...object.Object) object.Object, args ...object.Object) *object.Hash {
	t.Helper()

	payload, errObj := unwrapPair(t, open(args...))
	if errObj != nil {
		t.Fatalf("open returned error: %s", errObj.Inspect())
	}
	info, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("open payload is not a HASH. got=%T", payload)
	}

	handle := mustHashStringValue(t, info, "handle")
	t.Cleanup(func() { TableClose(stringObj(handle)) })

	return info
}

func tableHashBool(t *testing.T, hash *object.Hash, key string) bool {
	t.Helper()

	pair, ok := hash.Pairs[(&object.String{Value: key}).HashKey()]
	if !ok {
		t.Fatalf("key %q is absent", key)
	}
	value, ok := pair.Value.(*object.Boolean)
	if !ok {
		t.Fatalf("key %q is not a BOOLEAN. got=%T", key, pair.Value)
	}
	return value.Value
}

func tableHashKeys(hash *object.Hash) []string {
	keys := make([]string, 0, len(hash.Pairs))
	for _, pair := range hash.Pairs {
		if key, ok := pair.Key.(*object.String); ok {
			keys = append(keys, key.Value)
		}
	}
	sort.Strings(keys)
	return keys
}

func tableContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// A hybrid disk is one on which the protective MBR also carries real records.
// It is not a defect and it is not ambiguous media resolved by a coin toss: two
// schemes genuinely describe the same sectors, and the parse says which one it
// answered with.
func TestAHybridDiskReportsTheSchemeItChoseAndSaysWhyThereWasAChoice(t *testing.T) {
	path := writeTableImage(t, "hybrid.img", buildTestGPTImage(t, testGPTOpts{
		Entries: []testGPTEntry{
			{TypeGUID: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", Name: "EFI System Partition", StartLBA: 2048, EndLBA: 2559},
			{TypeGUID: "0fc63daf-8483-4772-8e79-3d69d8477de4", Name: "rootfs", StartLBA: 2560, EndLBA: 4000},
		},
		Hybrid: []testMBREntry{{Type: 0x83, StartLBA: 2048, SizeLBA: 512}},
	}))

	info := tableOpenImage(t, TableOpen, stringObj(path))

	if got := mustHashStringValue(t, info, "table_type"); got != "gpt" {
		t.Errorf("table_type = %q, want gpt", got)
	}
	if !tableHashBool(t, info, "ambiguous") {
		t.Error("a hybrid disk is ambiguous media; ambiguous said otherwise")
	}
	codes := mustHashStringArray(t, info, "warning_codes")
	if !tableContains(codes, "hybrid_mbr") {
		t.Errorf("warning_codes = %v, want hybrid_mbr among them", codes)
	}
	if candidates := mustHashStringArray(t, info, "candidates"); len(candidates) != 2 {
		t.Errorf("candidates = %v, want gpt and mbr", candidates)
	}
}

// The entries of the losing scheme are reachable by no other route: Parse has
// to answer with one table, and on a hybrid the other one is real.
func TestAHybridDiskKeepsTheEntriesThatOpeningItDiscards(t *testing.T) {
	path := writeTableImage(t, "hybrid.img", buildTestGPTImage(t, testGPTOpts{
		Entries: []testGPTEntry{
			{TypeGUID: "0fc63daf-8483-4772-8e79-3d69d8477de4", Name: "rootfs", StartLBA: 2560, EndLBA: 4000},
		},
		Hybrid: []testMBREntry{{Type: 0x83, StartLBA: 2048, SizeLBA: 512}},
	}))

	payload, errObj := unwrapPair(t, TableOpenAll(stringObj(path)))
	if errObj != nil {
		t.Fatalf("table_open_all returned error: %s", errObj.Inspect())
	}
	tables, ok := payload.(*object.Array)
	if !ok {
		t.Fatalf("table_open_all payload is not an ARRAY. got=%T", payload)
	}
	if len(tables.Elements) != 2 {
		t.Fatalf("table_open_all returned %d tables, want gpt and mbr", len(tables.Elements))
	}

	found := map[string]*object.Hash{}
	for _, element := range tables.Elements {
		info, ok := element.(*object.Hash)
		if !ok {
			t.Fatalf("table is not a HASH. got=%T", element)
		}
		found[mustHashStringValue(t, info, "table_type")] = info
		handle := mustHashStringValue(t, info, "handle")
		t.Cleanup(func() { TableClose(stringObj(handle)) })
	}

	mbr, ok := found["mbr"]
	if !ok {
		t.Fatalf("no mbr table among %v", found)
	}

	// Every handle is independent, so closing one must not disturb another.
	gpt, ok := found["gpt"]
	if !ok {
		t.Fatal("no gpt table")
	}
	if _, errObj := unwrapPair(t, TableClose(stringObj(mustHashStringValue(t, gpt, "handle")))); errObj != nil {
		t.Fatalf("closing the gpt handle: %s", errObj.Inspect())
	}

	partitions := tablePartitionsOf(t, mustHashStringValue(t, mbr, "handle"))
	hit := false
	for _, part := range partitions {
		if !tableHashBool(t, part, "allocated") {
			continue
		}
		if mustHashIntValue(t, part, "start_lba") == 2048 {
			hit = true
		}
	}
	if !hit {
		t.Error("the mbr record at lba 2048 was not reachable through table_open_all")
	}
}

func tablePartitionsOf(t *testing.T, handle string) []*object.Hash {
	t.Helper()

	payload, errObj := unwrapPair(t, TableListPartitions(stringObj(handle)))
	if errObj != nil {
		t.Fatalf("table_list_partitions returned error: %s", errObj.Inspect())
	}
	array, ok := payload.(*object.Array)
	if !ok {
		t.Fatalf("table_list_partitions payload is not an ARRAY. got=%T", payload)
	}

	out := make([]*object.Hash, 0, len(array.Elements))
	for _, element := range array.Elements {
		hash, ok := element.(*object.Hash)
		if !ok {
			t.Fatalf("partition is not a HASH. got=%T", element)
		}
		out = append(out, hash)
	}
	return out
}

// Preference order is deterministic, which is not the same as being right. A
// script that cannot afford a silently chosen winner asks for the refusal.
func TestAmbiguousMediaIsRefusedWhenTheScriptSaysItMustBe(t *testing.T) {
	path := writeTableImage(t, "ambiguous.img", buildTestMBRPlusBSDImage())

	info := tableOpenImage(t, TableOpen, stringObj(path))
	if got := mustHashStringValue(t, info, "table_type"); got != "mbr" {
		t.Fatalf("table_open chose %q, want mbr by preference order", got)
	}
	if !tableHashBool(t, info, "ambiguous") {
		t.Fatal("two schemes parsed; ambiguous said otherwise")
	}

	_, errObj := unwrapPair(t, TableOpenStrict(stringObj(path)))
	if errObj == nil {
		t.Fatal("table_open_strict accepted ambiguous media")
	}
	message := errObj.Inspect()
	for _, want := range []string{"mbr", "bsd", "table_open_as", "table_open_all"} {
		if !strings.Contains(message, want) {
			t.Errorf("refusal does not mention %q: %s", want, message)
		}
	}
}

func TestForcingASchemeReadsTheOneThatPreferenceDiscarded(t *testing.T) {
	path := writeTableImage(t, "ambiguous.img", buildTestMBRPlusBSDImage())

	info := tableOpenImage(t, TableOpenAs, stringObj(path), stringObj("bsd"))
	if got := mustHashStringValue(t, info, "table_type"); got != "bsd" {
		t.Fatalf("table_type = %q, want bsd", got)
	}

	partitions := tablePartitionsOf(t, mustHashStringValue(t, info, "handle"))
	hit := false
	for _, part := range partitions {
		if tableHashBool(t, part, "allocated") && mustHashIntValue(t, part, "start_lba") == 3000 {
			hit = true
		}
	}
	if !hit {
		t.Error("the disklabel slice at lba 3000 was not reported")
	}
}

func TestASchemeTheParserDoesNotHaveIsRefusedByName(t *testing.T) {
	path := writeTableImage(t, "ambiguous.img", buildTestMBRPlusBSDImage())

	_, errObj := unwrapPair(t, TableOpenAs(stringObj(path), stringObj("zfs")))
	if errObj == nil {
		t.Fatal("table_open_as accepted a scheme that does not exist")
	}
	if !strings.Contains(errObj.Inspect(), "table_open_as") || !strings.Contains(errObj.Inspect(), "zfs") {
		t.Errorf("refusal should name the builtin and the scheme: %s", errObj.Inspect())
	}
}

// The two GPT copies are written together. What they say about each other is
// therefore evidence, and all three answers mean different things.
func TestTheSecondaryGPTIsReportedByWhatItIsNotByWhetherItWasLookedFor(t *testing.T) {
	entries := []testGPTEntry{
		{TypeGUID: "0fc63daf-8483-4772-8e79-3d69d8477de4", Name: "rootfs", StartLBA: 2560, EndLBA: 4000},
	}

	for _, tc := range []struct {
		name  string
		opts  testGPTOpts
		want  string
		code  string
		clean bool
	}{
		{name: "intact", opts: testGPTOpts{Entries: entries}, want: "ok", clean: true},
		{name: "absent", opts: testGPTOpts{Entries: entries, NoBackup: true}, want: "missing", code: "backup_missing"},
		{name: "disagrees", opts: testGPTOpts{Entries: entries, DivergeBackup: true}, want: "mismatch", code: "backup_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTableImage(t, "gpt.img", buildTestGPTImage(t, tc.opts))
			info := tableOpenImage(t, TableOpen, stringObj(path))

			if got := mustHashStringValue(t, info, "gpt_backup"); got != tc.want {
				t.Errorf("gpt_backup = %q, want %q", got, tc.want)
			}

			codes := mustHashStringArray(t, info, "warning_codes")
			if tc.clean {
				for _, code := range codes {
					if strings.HasPrefix(code, "backup_") {
						t.Errorf("an intact pair of copies produced %q", code)
					}
				}
				return
			}
			if !tableContains(codes, tc.code) {
				t.Errorf("warning_codes = %v, want %s among them", codes, tc.code)
			}
		})
	}
}

// A disklabel inside an MBR slice is the partition table an examiner is looking
// for on a BSD disk; the MBR entry that holds it is only the container.
func TestADisklabelInsideASliceIsReachableFromTheSliceThatHoldsIt(t *testing.T) {
	path := writeTableImage(t, "nested.img", buildTestNestedBSDImage())
	info := tableOpenImage(t, TableOpen, stringObj(path))
	handle := mustHashStringValue(t, info, "handle")

	if codes := mustHashStringArray(t, info, "warning_codes"); !tableContains(codes, "nested") {
		t.Errorf("warning_codes = %v, want nested among them", codes)
	}

	container := -1
	for _, part := range tablePartitionsOf(t, handle) {
		if !tableHashBool(t, part, "has_nested") {
			continue
		}
		if got := mustHashStringValue(t, part, "nested_type"); got != "bsd" {
			t.Errorf("nested_type = %q, want bsd", got)
		}
		container = int(mustHashIntValue(t, part, "index"))
	}
	if container < 0 {
		t.Fatal("no partition reported a nested scheme")
	}

	payload, errObj := unwrapPair(t, TableNested(stringObj(handle), intObj(int64(container))))
	if errObj != nil {
		t.Fatalf("table_nested returned error: %s", errObj.Inspect())
	}
	nested, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("table_nested payload is not a HASH. got=%T", payload)
	}

	if got := mustHashStringValue(t, nested, "table_type"); got != "bsd" {
		t.Errorf("nested table_type = %q, want bsd", got)
	}
	if got := mustHashIntValue(t, nested, "table_offset"); got != testNestedSliceStart*tableSectorSize {
		t.Errorf("nested table_offset = %d, want %d", got, testNestedSliceStart*tableSectorSize)
	}

	// The load-bearing number. The label's addresses are relative to the slice,
	// so the absolute offset is the slice's base plus them. Arithmetic over
	// start_lba alone lands 64 sectors early, in the MBR's own gap.
	inner := mustHashArrayValue(t, nested, "partitions")
	want := int64((testNestedSliceStart + 16) * tableSectorSize)
	hit := false
	for _, element := range inner {
		part, ok := element.(*object.Hash)
		if !ok {
			t.Fatalf("nested partition is not a HASH. got=%T", element)
		}
		if !tableHashBool(t, part, "allocated") {
			continue
		}
		if mustHashIntValue(t, part, "start_lba") != 16 {
			continue
		}
		hit = true
		if got := mustHashIntValue(t, part, "start_byte"); got != want {
			t.Errorf("nested start_byte = %d, want %d", got, want)
		}
		if naive := int64(16 * tableSectorSize); want == naive {
			t.Fatal("the test is not exercising a nested base offset")
		}
	}
	if !hit {
		t.Error("the disklabel's first slice was not reported")
	}
}

func TestAPartitionThatHoldsNoSchemeIsRefusedRatherThanReportedEmpty(t *testing.T) {
	path := writeTableImage(t, "gpt.img", buildTestGPTImage(t, testGPTOpts{
		Entries: []testGPTEntry{
			{TypeGUID: "0fc63daf-8483-4772-8e79-3d69d8477de4", Name: "rootfs", StartLBA: 2560, EndLBA: 4000},
		},
	}))
	info := tableOpenImage(t, TableOpen, stringObj(path))
	handle := mustHashStringValue(t, info, "handle")

	_, errObj := unwrapPair(t, TableNested(stringObj(handle), intObj(0)))
	if errObj == nil {
		t.Fatal("table_nested returned a table for a partition that holds none")
	}
	if !strings.Contains(errObj.Inspect(), "nested") {
		t.Errorf("refusal should say what was not there: %s", errObj.Inspect())
	}
}

// The listing maps the device, not its volumes. A script that opens every row
// as a filesystem is opening GPT headers and interior gaps, so the rows say
// which they are.
func TestTheListingSaysWhichRowsAreAVolumeAndWhichAreTheTableItself(t *testing.T) {
	const sectors = 4096
	path := writeTableImage(t, "gpt.img", buildTestGPTImage(t, testGPTOpts{
		Sectors: sectors,
		Entries: []testGPTEntry{
			{TypeGUID: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", Name: "EFI System Partition", StartLBA: 2048, EndLBA: 2559},
			{TypeGUID: "0fc63daf-8483-4772-8e79-3d69d8477de4", Name: "rootfs", StartLBA: 2560, EndLBA: 4000},
		},
	}))
	info := tableOpenImage(t, TableOpen, stringObj(path))

	var volumes, structures, covered int64
	for _, part := range tablePartitionsOf(t, mustHashStringValue(t, info, "handle")) {
		if tableHashBool(t, part, "allocated") {
			volumes++
		}
		if tableHashBool(t, part, "structure") {
			structures++
			if !tableHashBool(t, part, "meta") {
				t.Error("a structure row that is not also a meta row would be invisible to every existing meta check")
			}
			if tableHashBool(t, part, "allocated") {
				t.Errorf("%q is the table itself, not a volume", mustHashStringValue(t, part, "type_name"))
			}
		}
		if tableHashBool(t, part, "occupies_space") {
			covered += mustHashIntValue(t, part, "length_byte")
		}
	}

	if volumes != 2 {
		t.Errorf("allocated rows = %d, want the two partitions", volumes)
	}
	if structures == 0 {
		t.Error("no row was marked as the on-disk structure; both GPT copies occupy sectors")
	}
	// Every row that occupies sectors tiles the device exactly once: no gap, and
	// no byte twice. A script summing free space is summing space that is free.
	if want := int64(sectors * tableSectorSize); covered != want {
		t.Errorf("rows that occupy space cover %d bytes, want the whole %d-byte device", covered, want)
	}
}

func TestDetectionNamesTheSchemesAndIssuesNoHandle(t *testing.T) {
	path := writeTableImage(t, "ambiguous.img", buildTestMBRPlusBSDImage())

	payload, errObj := unwrapPair(t, TableDetect(stringObj(path)))
	if errObj != nil {
		t.Fatalf("table_detect returned error: %s", errObj.Inspect())
	}
	info, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("table_detect payload is not a HASH. got=%T", payload)
	}

	if got := mustHashStringValue(t, info, "table_type"); got != "mbr" {
		t.Errorf("table_type = %q, want the preferred scheme", got)
	}
	if got := mustHashIntValue(t, info, "candidate_count"); got != 2 {
		t.Errorf("candidate_count = %d, want 2", got)
	}
	if !tableHashBool(t, info, "ambiguous") {
		t.Error("two schemes parsed; ambiguous said otherwise")
	}
	if _, present := info.Pairs[(&object.String{Value: "handle"}).HashKey()]; present {
		t.Error("table_detect issued a handle, which nothing would ever close")
	}

	tableStore.RLock()
	open := len(tableStore.handles)
	tableStore.RUnlock()
	if open != 0 {
		t.Errorf("%d table handles are open after a detection that issues none", open)
	}
}

// A single-handle opener asked for one table. Anything else the backend returns
// is a descriptor no script holds and nothing closes.
func TestASingleHandleOpenerReleasesTheTablesItDoesNotReturn(t *testing.T) {
	first := &fakeTableSession{info: tableInfo{TableType: "gpt", BlockSize: 512}}
	second := &fakeTableSession{info: tableInfo{TableType: "mbr", BlockSize: 512}}
	installFakeTableBackend(t, fakeTableBackend{session: first, sessions: []tableSession{first, second}})

	info := tableOpenImage(t, TableOpen, stringObj("synthetic.img"))
	if got := mustHashStringValue(t, info, "table_type"); got != "gpt" {
		t.Errorf("table_type = %q, want the first table", got)
	}

	if !second.closed {
		t.Error("the table that was not returned is still open")
	}
	tableStore.RLock()
	open := len(tableStore.handles)
	tableStore.RUnlock()
	if open != 1 {
		t.Errorf("%d handles registered, want 1", open)
	}
}

// Four openers, four parses. The difference between them is invisible in the
// result on unambiguous media, which is exactly why it is asserted here.
func TestEachOpenerAsksForTheParseItSaysItDoes(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func() object.Object
		want tableParseOptions
	}{
		{"table_open", func() object.Object { return TableOpen(stringObj("x.img")) }, tableParseOptions{}},
		{"table_open_strict", func() object.Object { return TableOpenStrict(stringObj("x.img")) }, tableParseOptions{RefuseAmbiguous: true}},
		{"table_open_as", func() object.Object { return TableOpenAs(stringObj("x.img"), stringObj("GPT")) }, tableParseOptions{Scheme: "gpt"}},
		{"table_open_all", func() object.Object { return TableOpenAll(stringObj("x.img")) }, tableParseOptions{All: true}},
		{"table_detect", func() object.Object { return TableDetect(stringObj("x.img")) }, tableParseOptions{All: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen tableParseOptions
			installFakeTableBackend(t, fakeTableBackend{
				session:     &fakeTableSession{info: tableInfo{TableType: "gpt"}},
				lastOptions: &seen,
			})

			if _, errObj := unwrapPair(t, tc.call()); errObj != nil {
				t.Fatalf("%s returned error: %s", tc.name, errObj.Inspect())
			}
			if seen != tc.want {
				t.Errorf("%s parsed with %+v, want %+v", tc.name, seen, tc.want)
			}
		})
	}
}

// The registry's documentation is what the LSP hovers, completes and type
// checks against, so a field the implementation returns and the metadata does
// not declare is a field the editor cannot see.
func TestTheTableBuiltinsDeclareTheFieldsTheyReturn(t *testing.T) {
	path := writeTableImage(t, "nested.img", buildTestNestedBSDImage())
	info := tableOpenImage(t, TableOpen, stringObj(path))
	handle := stringObj(mustHashStringValue(t, info, "handle"))

	container := int64(-1)
	for _, part := range tablePartitionsOf(t, handle.Value) {
		if tableHashBool(t, part, "has_nested") {
			container = mustHashIntValue(t, part, "index")
		}
	}
	if container < 0 {
		t.Fatal("no nested container in the image")
	}

	for name, produce := range map[string]func() object.Object{
		BuiltinNameTableOpen:          func() object.Object { return TableOpen(stringObj(path)) },
		BuiltinNameTableOpenStrict:    func() object.Object { return TableOpenStrict(stringObj(path)) },
		BuiltinNameTableOpenAs:        func() object.Object { return TableOpenAs(stringObj(path), stringObj("mbr")) },
		BuiltinNameTableDetect:        func() object.Object { return TableDetect(stringObj(path)) },
		BuiltinNameTableNested:        func() object.Object { return TableNested(handle, intObj(container)) },
		BuiltinNameTablePartitionInfo: func() object.Object { return TablePartitionInfo(handle, intObj(container)) },
	} {
		doc, ok := builtinDocs[name]
		if !ok {
			t.Fatalf("%s has no documentation entry", name)
		}

		payload, errObj := unwrapPair(t, produce())
		if errObj != nil {
			t.Fatalf("%s returned error: %s", name, errObj.Inspect())
		}
		hash, ok := payload.(*object.Hash)
		if !ok {
			t.Fatalf("%s payload is not a HASH. got=%T", name, payload)
		}
		if opened, present := hash.Pairs[(&object.String{Value: "handle"}).HashKey()]; present {
			if handleObj, ok := opened.Value.(*object.String); ok && handleObj.Value != handle.Value {
				t.Cleanup(func() { TableClose(stringObj(handleObj.Value)) })
			}
		}

		got := tableHashKeys(hash)
		want := append([]string(nil), doc.returns.fields...)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s returns %v, metadata declares %v", name, got, want)
		}
	}
}
