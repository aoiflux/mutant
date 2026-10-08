package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

// buildExt3BrokenOrphanChain is buildExt2Image's volume given a journal, with
// its one file made the head of the orphan list -- links count zero, the
// superblock's s_last_orphan naming it -- and the next link in the chain, which
// ext keeps in the orphan's dtime, pointing at an inode the volume does not
// have. libext warns about that link on every scan of the orphan list.
//
// The journal is inode 8, ext's reserved journal inode, over blocks 16-23: a
// JBD2 version 2 superblock (big-endian, e2fsprogs' kernel-jbd.h) in the first
// and nothing after it, so the walk reads seven blocks, finds no transactions
// and raises no warning of its own.
func buildExt3BrokenOrphanChain() []byte {
	const bs = 1024
	img := buildExt2Image("hello.txt", []byte("hi\n"))
	sb := img[1024:2048]
	binary.LittleEndian.PutUint32(sb[0x5C:], binary.LittleEndian.Uint32(sb[0x5C:])|0x4) // compat: has_journal
	binary.LittleEndian.PutUint32(sb[0xE0:], 8)                                         // s_journal_inum
	binary.LittleEndian.PutUint32(sb[0xE8:], 12)                                        // s_last_orphan
	binary.LittleEndian.PutUint32(sb[0x0C:], 47)                                        // free blocks
	binary.LittleEndian.PutUint16(img[2*bs+12:], 47)
	img[3*bs+1] |= 0x80 // blocks 16-23 in use; bit 0 is block 1
	img[3*bs+2] |= 0x7F

	journal := img[5*bs+7*128 : 5*bs+8*128]
	binary.LittleEndian.PutUint16(journal[0:], 0x8180) // regular file, 0600
	binary.LittleEndian.PutUint32(journal[4:], 8*bs)
	binary.LittleEndian.PutUint16(journal[26:], 1)
	binary.LittleEndian.PutUint32(journal[28:], 16) // 512-byte sectors
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(journal[40+4*i:], uint32(16+i))
	}
	jsb := img[16*bs : 17*bs]
	binary.BigEndian.PutUint32(jsb[0:], 0xC03B3998) // JBD2 magic
	binary.BigEndian.PutUint32(jsb[4:], 4)          // superblock, version 2
	binary.BigEndian.PutUint32(jsb[12:], bs)        // s_blocksize
	binary.BigEndian.PutUint32(jsb[16:], 8)         // s_maxlen
	binary.BigEndian.PutUint32(jsb[20:], 1)         // s_first
	binary.BigEndian.PutUint32(jsb[24:], 1)         // s_sequence
	binary.BigEndian.PutUint32(jsb[64:], 1)         // s_nr_users

	file := img[5*bs+11*128 : 5*bs+12*128]
	binary.LittleEndian.PutUint16(file[26:], 0)      // links count
	binary.LittleEndian.PutUint32(file[20:], 999999) // dtime: the next orphan, which does not exist
	return img
}

func openBrokenOrphanChain(t *testing.T) object.Object {
	t.Helper()
	path := filepath.Join(t.TempDir(), "orphans.img")
	if err := os.WriteFile(path, buildExt3BrokenOrphanChain(), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, errObj := unwrapPair(t, ExtOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("ext_open: %s", errObj.Inspect())
	}
	handle := mustHashValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { ExtClose(handle) })
	return handle
}

func hashWarningCodes(t *testing.T, result *object.Hash) []string {
	t.Helper()
	var codes []string
	for _, c := range mustHashArrayValue(t, result, "warning_codes") {
		codes = append(codes, c.(*object.String).Value)
	}
	return codes
}

func hasCode(codes []string, code string) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}

// extJournalCalls are the three builtins that walk the JBD2 journal, each
// called on the fixture's handle.
func extJournalCalls(handle object.Object) map[string]func() object.Object {
	return map[string]func() object.Object{
		"ext_journal":              func() object.Object { return ExtJournal(handle) },
		"ext_journal_block_copies": func() object.Object { return ExtJournalBlockCopies(handle, intObj(8)) },
		"ext_inode_versions":       func() object.Object { return ExtInodeVersions(handle, intObj(12)) },
	}
}

// TestTheFixtureJournalIsAJournal holds the fixture to libext before the tests
// below lean on it: a journal that is present, readable and empty.
func TestTheFixtureJournalIsAJournal(t *testing.T) {
	handle := openBrokenOrphanChain(t)
	payload, errObj := unwrapPair(t, ExtJournal(handle))
	if errObj != nil {
		t.Fatalf("ext_journal: %s", errObj.Inspect())
	}
	journal := payload.(*object.Hash)
	if !mustHashBoolValue(t, journal, "present") {
		t.Fatalf("the fixture's journal is not present: %s", journal.Inspect())
	}
	if codes := hashWarningCodes(t, journal); len(codes) != 0 {
		t.Fatalf("the fixture's journal raises warnings of its own %v: %s", codes, journal.Inspect())
	}
}

// TestAFullExtWarningListIsSaidToBeFull is M26-FS2-008's regression test.
// libext keeps 256 warnings for a handle's whole life and drops every one
// after. ext_deleted took the delta of the list around its scan, which is
// empty for ever once the list fills: the first scan of a broken orphan chain
// said incomplete, and the 300th, meeting the same damage, said complete with
// no warnings. The journal walks reported the full list under the code for an
// unreadable journal superblock and said nothing about being incomplete.
func TestAFullExtWarningListIsSaidToBeFull(t *testing.T) {
	handle := openBrokenOrphanChain(t)

	var last *object.Hash
	for scan := 1; scan <= 300; scan++ {
		payload, errObj := unwrapPair(t, ExtDeleted(handle))
		if errObj != nil {
			t.Fatalf("ext_deleted, scan %d: %s", scan, errObj.Inspect())
		}
		last = payload.(*object.Hash)
		if scan == 1 && mustHashBoolValue(t, last, "complete") {
			t.Fatalf("the first scan of a broken orphan chain says complete; the fixture raises no warning")
		}
	}
	if mustHashBoolValue(t, last, "complete") {
		t.Errorf("the 300th scan of the same broken chain says complete: %s", last.Inspect())
	}
	if codes := hashWarningCodes(t, last); !hasCode(codes, fsWarnWarningsSaturatedCode) {
		t.Errorf("the 300th scan's warning codes %v do not say the list is full", codes)
	}

	for name, call := range extJournalCalls(handle) {
		payload, errObj := unwrapPair(t, call())
		if errObj != nil {
			t.Fatalf("%s: %s", name, errObj.Inspect())
		}
		result := payload.(*object.Hash)
		codes := hashWarningCodes(t, result)
		if !hasCode(codes, fsWarnWarningsSaturatedCode) || hasCode(codes, "journal_superblock_unreadable") {
			t.Errorf("%s on a full handle reports %v", name, codes)
		}
		if mustHashBoolValue(t, result, "complete") {
			t.Errorf("%s on a full handle says complete", name)
		}
	}
}

// TestAJournalWalkReportsOnlyItsOwnWarnings is the other half of M26-FS2-008.
// libext's warning list belongs to the volume. The journal walks reported all
// of it, so an orphan-chain warning raised by an earlier ext_deleted came back
// as a warning about a journal that had none.
func TestAJournalWalkReportsOnlyItsOwnWarnings(t *testing.T) {
	handle := openBrokenOrphanChain(t)
	payload, errObj := unwrapPair(t, ExtDeleted(handle))
	if errObj != nil {
		t.Fatalf("ext_deleted: %s", errObj.Inspect())
	}
	orphanCodes := hashWarningCodes(t, payload.(*object.Hash))
	if len(orphanCodes) == 0 {
		t.Fatal("the broken orphan chain raised no warning")
	}

	for name, call := range extJournalCalls(handle) {
		payload, errObj := unwrapPair(t, call())
		if errObj != nil {
			t.Fatalf("%s: %s", name, errObj.Inspect())
		}
		for _, code := range hashWarningCodes(t, payload.(*object.Hash)) {
			if hasCode(orphanCodes, code) {
				t.Errorf("%s reports %q, which ext_deleted raised walking the orphan list", name, code)
			}
		}
	}
}

// fsWarnWarningsSaturatedCode is the code spelled out, so the test compiles
// against code that does not yet define the constant.
const fsWarnWarningsSaturatedCode = "warnings_saturated"
