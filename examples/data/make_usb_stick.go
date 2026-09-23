//go:build ignore

// make_usb_stick.go builds usb_stick.img: a 100 KiB disk image with an MBR
// partition table and one FAT12 partition, holding phish.eml at
// /INBOX/PHISH.EML. It is the seized device examples/forensics/record_disclosure.mut
// opens, verifies and reads the exhibit out of.
//
// Built by hand, byte by byte, because no tool that makes a FAT image makes the
// same one twice: every field that a formatter would fill from the clock or a
// random source is fixed here, so the image is a pure function of phish.eml.
//
// A pure function of its content, not of the checkout. An email's lines end in
// CRLF on the wire (RFC 5322), but git stores phish.eml with LF endings and
// hands it back with whichever ending the machine is configured for, so the
// email is put back into its wire form before it goes in -- otherwise the same
// commit builds a 1471-byte exhibit on one machine and a 1431-byte one on
// another. example_record_disclosure_test.go compares against the same form.
//
//	go run examples/data/make_usb_stick.go
//
// Run it again whenever phish.eml changes; the record_disclosure end-to-end test
// fails until the two agree.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

const (
	sectorSize      = 512
	partitionStart  = 63  // the classic DOS start: one track in
	reservedSectors = 1   // the boot sector
	fatCount        = 2   // two FATs, so fat_verify has a mirror to compare
	fatSectors      = 1   // 341 FAT12 entries, more than enough
	rootEntries     = 32  // two sectors of root directory
	dataClusters    = 120 // one sector each; FAT12 below 4085
	trailingSectors = 12  // unallocated space after the partition
)

// 2026-04-13 09:12:00, in FAT's packed local-time form.
const (
	fatDate = (2026-1980)<<9 | 4<<5 | 13
	fatTime = 9<<11 | 12<<5
)

func main() {
	dir := filepath.Join("examples", "data")
	eml, err := os.ReadFile(filepath.Join(dir, "phish.eml"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading phish.eml (run this from the repository root):", err)
		os.Exit(1)
	}
	image, err := build(wireLineEndings(eml))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := filepath.Join(dir, "usb_stick.img")
	if err := os.WriteFile(out, image, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s: %d bytes, partition at byte %d\n", out, len(image), partitionStart*sectorSize)
}

// wireLineEndings gives every line of an email the CRLF ending it has on the
// wire, whichever ending the checkout gave it.
func wireLineEndings(eml []byte) []byte {
	lf := bytes.ReplaceAll(eml, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
}

func build(eml []byte) ([]byte, error) {
	rootSectors := rootEntries * 32 / sectorSize
	volumeSectors := reservedSectors + fatCount*fatSectors + rootSectors + dataClusters
	emlClusters := (len(eml) + sectorSize - 1) / sectorSize
	// Cluster 2 is the INBOX directory; the email follows it.
	if 1+emlClusters > dataClusters {
		return nil, fmt.Errorf("phish.eml is %d bytes, too large for a %d-cluster volume", len(eml), dataClusters)
	}

	disk := make([]byte, (partitionStart+volumeSectors+trailingSectors)*sectorSize)

	// --- the MBR ------------------------------------------------------------
	mbr := disk[:sectorSize]
	binary.LittleEndian.PutUint32(mbr[440:], 0x20260413) // disk signature
	entry := mbr[446:462]
	entry[0] = 0x00 // not bootable
	putCHS(entry[1:4], partitionStart)
	entry[4] = 0x01 // FAT12
	putCHS(entry[5:8], partitionStart+volumeSectors-1)
	binary.LittleEndian.PutUint32(entry[8:], partitionStart)
	binary.LittleEndian.PutUint32(entry[12:], uint32(volumeSectors))
	binary.LittleEndian.PutUint16(mbr[510:], 0xAA55)

	volume := disk[partitionStart*sectorSize : (partitionStart+volumeSectors)*sectorSize]

	// --- the boot sector ----------------------------------------------------
	boot := volume[:sectorSize]
	copy(boot[0:3], []byte{0xEB, 0x3C, 0x90})
	copy(boot[3:11], "MSWIN4.1")
	binary.LittleEndian.PutUint16(boot[11:], sectorSize)
	boot[13] = 1 // sectors per cluster
	binary.LittleEndian.PutUint16(boot[14:], reservedSectors)
	boot[16] = fatCount
	binary.LittleEndian.PutUint16(boot[17:], rootEntries)
	binary.LittleEndian.PutUint16(boot[19:], uint16(volumeSectors))
	boot[21] = 0xF8 // fixed disk
	binary.LittleEndian.PutUint16(boot[22:], fatSectors)
	binary.LittleEndian.PutUint16(boot[24:], 63)  // sectors per track
	binary.LittleEndian.PutUint16(boot[26:], 255) // heads
	binary.LittleEndian.PutUint32(boot[28:], partitionStart)
	boot[36] = 0x80 // drive number
	boot[38] = 0x29 // extended boot signature
	binary.LittleEndian.PutUint32(boot[39:], 0x0413_2026)
	copy(boot[43:54], "EXHIBIT-7  ")
	copy(boot[54:62], "FAT12   ")
	binary.LittleEndian.PutUint16(boot[510:], 0xAA55)

	// --- the FATs -----------------------------------------------------------
	fat := make([]byte, fatSectors*sectorSize)
	putFAT12(fat, 0, 0xFF8) // media descriptor
	putFAT12(fat, 1, 0xFFF)
	putFAT12(fat, 2, 0xFFF) // INBOX: one cluster
	for i := range emlClusters {
		cluster := 3 + i
		next := uint16(cluster + 1)
		if i == emlClusters-1 {
			next = 0xFFF
		}
		putFAT12(fat, cluster, next)
	}
	fatOffset := reservedSectors * sectorSize
	for i := range fatCount {
		copy(volume[fatOffset+i*len(fat):], fat)
	}

	// --- the root directory -------------------------------------------------
	root := volume[fatOffset+fatCount*len(fat):]
	putDirEntry(root[0:], "EXHIBIT-7  ", 0x08, 0, 0)
	putDirEntry(root[32:], "INBOX      ", 0x10, 2, 0)

	// --- the data area: INBOX, then the email --------------------------------
	data := volume[(reservedSectors+fatCount*fatSectors+rootSectors)*sectorSize:]
	inbox := data[:sectorSize]
	putDirEntry(inbox[0:], ".          ", 0x10, 2, 0)
	putDirEntry(inbox[32:], "..         ", 0x10, 0, 0)
	putDirEntry(inbox[64:], "PHISH   EML", 0x20, 3, uint32(len(eml)))
	copy(data[sectorSize:], eml)

	return disk, nil
}

// putFAT12 writes a 12-bit FAT entry: two entries share three bytes.
func putFAT12(fat []byte, cluster int, value uint16) {
	at := cluster * 3 / 2
	current := binary.LittleEndian.Uint16(fat[at:])
	if cluster%2 == 0 {
		current = current&0xF000 | value&0x0FFF
	} else {
		current = current&0x000F | value<<4
	}
	binary.LittleEndian.PutUint16(fat[at:], current)
}

func putDirEntry(dst []byte, name string, attr byte, cluster uint16, size uint32) {
	copy(dst[0:11], name)
	dst[11] = attr
	binary.LittleEndian.PutUint16(dst[14:], fatTime) // created
	binary.LittleEndian.PutUint16(dst[16:], fatDate)
	binary.LittleEndian.PutUint16(dst[18:], fatDate) // accessed
	binary.LittleEndian.PutUint16(dst[22:], fatTime) // written
	binary.LittleEndian.PutUint16(dst[24:], fatDate)
	binary.LittleEndian.PutUint16(dst[26:], cluster)
	binary.LittleEndian.PutUint32(dst[28:], size)
}

// putCHS encodes an LBA as the cylinder/head/sector triple an MBR entry
// carries beside it, for a 255-head, 63-sector geometry.
func putCHS(dst []byte, lba int) {
	const heads, sectorsPerTrack = 255, 63
	cylinder := lba / (heads * sectorsPerTrack)
	head := (lba / sectorsPerTrack) % heads
	sector := lba%sectorsPerTrack + 1
	dst[0] = byte(head)
	dst[1] = byte(sector) | byte(cylinder>>8&0x03)<<6
	dst[2] = byte(cylinder)
}
