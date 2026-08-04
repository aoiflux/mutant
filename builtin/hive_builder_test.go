package builtin

import (
	"encoding/binary"
	"unicode/utf16"
)

// A minimal registry-hive (regf) builder for tests: assemble a tree of keys with
// REG_SZ / REG_DWORD values into a valid hive the parser can read. Post-order
// allocation ensures child/value cells exist before the parent nk references them.

type hiveKV struct {
	name    string
	str     string
	dword   uint32
	isDword bool
	bin     []byte
	isBin   bool
}

type hiveNode struct {
	name     string
	values   []hiveKV
	children []*hiveNode
}

type hiveBuilder struct {
	buf      []byte
	cursor   uint32 // next free offset (relative to 0x1000)
	filetime uint64
}

func newHiveBuilder(filetime uint64) *hiveBuilder {
	b := &hiveBuilder{buf: make([]byte, 0x10000), cursor: 0x20, filetime: filetime}
	copy(b.buf[0:4], "regf")
	copy(b.buf[0x1000:0x1004], "hbin")
	return b
}

func (b *hiveBuilder) alloc(data []byte) uint32 {
	rel := b.cursor
	total := len(data) + 4
	if total%8 != 0 {
		total += 8 - total%8
	}
	abs := 0x1000 + int(rel)
	binary.LittleEndian.PutUint32(b.buf[abs:abs+4], uint32(int32(-total))) // negative => allocated
	copy(b.buf[abs+4:abs+4+len(data)], data)
	b.cursor += uint32(total)
	return rel
}

func (b *hiveBuilder) buildVKString(name, value string) uint32 {
	u16 := utf16.Encode([]rune(value + "\x00"))
	data := make([]byte, len(u16)*2)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(data[i*2:], c)
	}
	dataRel := b.alloc(data)

	nb := []byte(name)
	d := make([]byte, 0x14+len(nb))
	copy(d[0:2], "vk")
	binary.LittleEndian.PutUint16(d[0x02:0x04], uint16(len(nb)))
	binary.LittleEndian.PutUint32(d[0x04:0x08], uint32(len(data))) // size (referenced, not inline)
	binary.LittleEndian.PutUint32(d[0x08:0x0C], dataRel)
	binary.LittleEndian.PutUint32(d[0x0C:0x10], 1)     // REG_SZ
	binary.LittleEndian.PutUint16(d[0x10:0x12], 0x0001) // ASCII name
	copy(d[0x14:], nb)
	return b.alloc(d)
}

func (b *hiveBuilder) buildVKBinary(name string, data []byte) uint32 {
	dataRel := b.alloc(data)
	nb := []byte(name)
	d := make([]byte, 0x14+len(nb))
	copy(d[0:2], "vk")
	binary.LittleEndian.PutUint16(d[0x02:0x04], uint16(len(nb)))
	binary.LittleEndian.PutUint32(d[0x04:0x08], uint32(len(data))) // size (referenced, not inline)
	binary.LittleEndian.PutUint32(d[0x08:0x0C], dataRel)
	binary.LittleEndian.PutUint32(d[0x0C:0x10], 3)     // REG_BINARY
	binary.LittleEndian.PutUint16(d[0x10:0x12], 0x0001) // ASCII name
	copy(d[0x14:], nb)
	return b.alloc(d)
}

func (b *hiveBuilder) buildKey(node *hiveNode) uint32 {
	childOffsets := make([]uint32, 0, len(node.children))
	for _, c := range node.children {
		childOffsets = append(childOffsets, b.buildKey(c))
	}

	subListRel := uint32(0xFFFFFFFF)
	if len(childOffsets) > 0 {
		lf := make([]byte, 4+len(childOffsets)*8)
		copy(lf[0:2], "lf")
		binary.LittleEndian.PutUint16(lf[2:4], uint16(len(childOffsets)))
		for i, off := range childOffsets {
			binary.LittleEndian.PutUint32(lf[4+i*8:], off) // hash field left 0
		}
		subListRel = b.alloc(lf)
	}

	valListRel := uint32(0xFFFFFFFF)
	if len(node.values) > 0 {
		vkOffsets := make([]uint32, 0, len(node.values))
		for _, v := range node.values {
			switch {
			case v.isDword:
				vkOffsets = append(vkOffsets, b.alloc(makeVKDword(v.name, v.dword)))
			case v.isBin:
				vkOffsets = append(vkOffsets, b.buildVKBinary(v.name, v.bin))
			default:
				vkOffsets = append(vkOffsets, b.buildVKString(v.name, v.str))
			}
		}
		vlist := make([]byte, len(vkOffsets)*4)
		for i, off := range vkOffsets {
			binary.LittleEndian.PutUint32(vlist[i*4:], off)
		}
		valListRel = b.alloc(vlist)
	}

	nk := makeNK(node.name, b.filetime, uint32(len(childOffsets)), subListRel, uint32(len(node.values)), valListRel)
	return b.alloc(nk)
}

func (b *hiveBuilder) finish(root *hiveNode) []byte {
	rootRel := b.buildKey(root)
	binary.LittleEndian.PutUint32(b.buf[0x24:0x28], rootRel)
	return b.buf
}
