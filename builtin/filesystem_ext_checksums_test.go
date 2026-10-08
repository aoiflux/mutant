package builtin

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

// ext4CRC32C is the CRC32c ext4 computes: Linux's crc32c is a running update
// with no complement on the way in or out, and hash/crc32 complements both.
func ext4CRC32C(seed uint32, data []byte) uint32 {
	return ^crc32.Update(^seed, crc32.MakeTable(crc32.Castagnoli), data)
}

// buildExt4ChecksummedImage is buildExt2Image's volume made with metadata
// checksums (RO_COMPAT_METADATA_CSUM). The superblock, the group descriptor,
// both bitmaps and every inode that is not all zero carry the CRC32c the
// kernel computes for them (fs/ext4: ext4_superblock_csum,
// ext4_group_desc_csum, ext4_block_bitmap_csum_set, ext4_inode_bitmap_csum_set
// and ext4_inode_csum). The reserved inodes 1, 3-11 are allocated and all zero,
// which e2fsck accepts without a checksum. edit runs before the checksums are
// computed and tamper after.
func buildExt4ChecksummedImage(edit, tamper func(img []byte)) []byte {
	const bs = 1024
	le := binary.LittleEndian
	img := buildExt2Image("hello.txt", []byte("hi\n"))
	sb := img[1024:2048]
	le.PutUint32(sb[0x64:], le.Uint32(sb[0x64:])|0x400) // ro_compat: metadata_csum
	sb[0x175] = 1                                       // s_checksum_type: crc32c
	copy(sb[0x68:0x78], "mutant-ext4-uuid")             // s_uuid
	if edit != nil {
		edit(img)
	}

	seed := ext4CRC32C(^uint32(0), sb[0x68:0x78])
	if stored := le.Uint32(sb[0x270:]); le.Uint32(sb[0x60:])&0x2000 != 0 && stored != 0 {
		seed = stored // s_checksum_seed, under incompat csum_seed
	}
	number := make([]byte, 4)
	for n := 1; n <= 16; n++ {
		inode := img[5*bs+(n-1)*128 : 5*bs+n*128]
		if allZeroBytes(inode) {
			continue
		}
		inode[0x7C], inode[0x7D] = 0, 0
		le.PutUint32(number, uint32(n))
		c := ext4CRC32C(seed, number)
		c = ext4CRC32C(c, inode[0x64:0x68]) // i_generation
		le.PutUint16(inode[0x7C:], uint16(ext4CRC32C(c, inode)))
	}
	gd := img[2*bs : 2*bs+32]
	le.PutUint16(gd[0x18:], uint16(ext4CRC32C(seed, img[3*bs:4*bs])))   // 8192 blocks per group
	le.PutUint16(gd[0x1A:], uint16(ext4CRC32C(seed, img[4*bs:4*bs+2]))) // 16 inodes per group
	gd[0x1E], gd[0x1F] = 0, 0
	le.PutUint32(number, 0) // group 0
	le.PutUint16(gd[0x1E:], uint16(ext4CRC32C(ext4CRC32C(seed, number), gd)))
	le.PutUint32(sb[0x3FC:], ext4CRC32C(^uint32(0), sb[:0x3FC]))

	if tamper != nil {
		tamper(img)
	}
	return img
}

func allZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func extVerifyImage(t *testing.T, image []byte) *object.Hash {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ext4.img")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	payload, errObj := unwrapPair(t, ExtOpen(stringObj(path)))
	if errObj != nil {
		t.Fatalf("ext_open: %s", errObj.Inspect())
	}
	handle := mustHashValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { ExtClose(handle) })
	payload, errObj = unwrapPair(t, ExtVerify(handle))
	if errObj != nil {
		t.Fatalf("ext_verify: %s", errObj.Inspect())
	}
	return payload.(*object.Hash)
}

func verifyCheckNamed(t *testing.T, result *object.Hash, name string) *object.Hash {
	t.Helper()
	for _, c := range mustHashArrayValue(t, result, "checks") {
		check := c.(*object.Hash)
		if mustHashStringValue(t, check, "name") == name {
			return check
		}
	}
	return nil
}

func verifyFindingAt(t *testing.T, result *object.Hash, location, issue string) bool {
	t.Helper()
	for _, f := range mustHashArrayValue(t, result, "findings") {
		finding := f.(*object.Hash)
		if mustHashStringValue(t, finding, "location") == location &&
			mustHashStringValue(t, finding, "issue") == issue {
			return true
		}
	}
	return false
}

// TestAnIntactChecksummedExtVolumeVerifies holds the fixture to libext: every
// checksum in it is the kernel's, so the volume verifies, before and after.
func TestAnIntactChecksummedExtVolumeVerifies(t *testing.T) {
	result := extVerifyImage(t, buildExt4ChecksummedImage(nil, nil))
	if !mustHashBoolValue(t, result, "verified") {
		t.Fatalf("an intact checksummed volume is not verified: %s", result.Inspect())
	}
	if failed := mustHashIntValue(t, result, "checks_failed"); failed != 0 {
		t.Errorf("an intact checksummed volume failed %d checks: %s", failed, result.Inspect())
	}
}

// TestAnExtInodeWhoseChecksumFailsIsNotVerified is the regression test for
// ext_verify's inode checksums. libext compares an inode's checksum when it
// reads the inode and keeps the answer only on a handle opened to refuse a
// mismatch, which a script's handle is not. So a volume with an inode edited
// after its checksum was written verified, with a scope saying inodes would
// be covered once a walk had read them -- no walk ever did.
func TestAnExtInodeWhoseChecksumFailsIsNotVerified(t *testing.T) {
	result := extVerifyImage(t, buildExt4ChecksummedImage(nil, func(img []byte) {
		binary.LittleEndian.PutUint32(img[5*1024+11*128+4:], 3000) // inode 12's size
	}))
	if mustHashBoolValue(t, result, "verified") {
		t.Errorf("a volume with an edited inode verified: %s", result.Inspect())
	}
	if !verifyFindingAt(t, result, "inode 12", "metadata checksum mismatch") {
		t.Errorf("no finding names inode 12: %s", result.Inspect())
	}
}

// TestAnExtBitmapWhoseChecksumFailsIsNotVerified: the same for an allocation
// bitmap, which libext exports a verifier for and nothing called. The inode
// the edited bitmap claims is all zero, so the walk accepts it.
func TestAnExtBitmapWhoseChecksumFailsIsNotVerified(t *testing.T) {
	result := extVerifyImage(t, buildExt4ChecksummedImage(nil, func(img []byte) {
		img[4*1024+1] |= 0x10 // inode 13 marked in use
	}))
	if mustHashBoolValue(t, result, "verified") {
		t.Errorf("a volume with an edited inode bitmap verified: %s", result.Inspect())
	}
	if !verifyFindingAt(t, result, "inode bitmap of group 0", "metadata checksum mismatch") {
		t.Errorf("no finding names the inode bitmap: %s", result.Inspect())
	}
	if verifyFindingAt(t, result, "inode 13", "metadata checksum mismatch") {
		t.Errorf("an all-zero inode was failed, which e2fsck accepts: %s", result.Inspect())
	}
}

// TestEveryExtChecksumComparedIsCounted: examined is the structures compared.
// It was the number of mismatches, so an intact volume said it had examined
// nothing. The fixture holds a superblock, one descriptor, two bitmaps and
// twelve allocated inodes.
func TestEveryExtChecksumComparedIsCounted(t *testing.T) {
	result := extVerifyImage(t, buildExt4ChecksummedImage(nil, nil))
	check := verifyCheckNamed(t, result, "metadata_checksums")
	if check == nil {
		t.Fatalf("no metadata_checksums check: %s", result.Inspect())
	}
	if got := mustHashIntValue(t, check, "examined"); got != 16 {
		t.Errorf("metadata_checksums examined %d structures, want 16: %s", got, check.Inspect())
	}
	readable := verifyCheckNamed(t, result, "metadata_readable")
	if readable == nil || !mustHashBoolValue(t, readable, "passed") ||
		mustHashIntValue(t, readable, "examined") != 16 {
		t.Errorf("metadata_readable does not say all 16 were read: %v", readable)
	}
}

// TestAZeroStoredChecksumSeedIsNotCompared: under csum_seed a stored seed of
// zero is the kernel's seed, and libext replaces it with one taken from the
// UUID, so every comparison it made would be against a checksum the kernel
// never computed. The check said "mismatch" for a volume nobody had compared.
func TestAZeroStoredChecksumSeedIsNotCompared(t *testing.T) {
	result := extVerifyImage(t, buildExt4ChecksummedImage(func(img []byte) {
		sb := img[1024:2048]
		binary.LittleEndian.PutUint32(sb[0x60:], binary.LittleEndian.Uint32(sb[0x60:])|0x2000)
	}, nil))
	check := verifyCheckNamed(t, result, "metadata_checksums")
	if check == nil || mustHashBoolValue(t, check, "checked") {
		t.Errorf("checksums seeded differently from the kernel were compared: %v", check)
	}
	for _, f := range mustHashArrayValue(t, result, "findings") {
		if mustHashStringValue(t, f.(*object.Hash), "issue") == "metadata checksum mismatch" {
			t.Errorf("a mismatch was reported on a volume nothing compared: %s", f.Inspect())
		}
	}
}

// TestAnExtSuperblockWhoseChecksumFailsIsNotVerified: the comparison libext
// made at open still reaches the result, and says nothing else was compared.
func TestAnExtSuperblockWhoseChecksumFailsIsNotVerified(t *testing.T) {
	result := extVerifyImage(t, buildExt4ChecksummedImage(nil, func(img []byte) {
		copy(img[1024+0x78:], "edited") // s_volume_name
	}))
	if mustHashBoolValue(t, result, "verified") {
		t.Errorf("a volume with an edited superblock verified: %s", result.Inspect())
	}
	check := verifyCheckNamed(t, result, "metadata_checksums")
	if check == nil || mustHashBoolValue(t, check, "passed") {
		t.Errorf("metadata_checksums passed an edited superblock: %v", check)
	}
}
