//go:build windows

package builtin

import (
	"bytes"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These tests validate the pure-Go Xpress-Huffman decompressor byte-for-byte
// against the operating system's own compressor (ntdll RtlCompressBuffer /
// RtlDecompressBufferEx) — the same engine Windows uses to produce MAM-compressed
// prefetch files. They only run on Windows; the cross-platform path is covered by
// the embedded MAM vector in prefetch_builtins_test.go.

const (
	ntCompressXpressHuffman = 0x0004
	ntCompressEngineMax     = 0x0100
)

func ntCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	getWS := ntdll.NewProc("RtlGetCompressionWorkSpaceSize")
	compress := ntdll.NewProc("RtlCompressBuffer")

	format := uintptr(ntCompressXpressHuffman | ntCompressEngineMax)
	var bufWS, fragWS uint32
	if r, _, _ := getWS.Call(format, uintptr(unsafe.Pointer(&bufWS)), uintptr(unsafe.Pointer(&fragWS))); r != 0 {
		t.Skipf("RtlGetCompressionWorkSpaceSize unavailable (status 0x%x)", r)
	}
	ws := make([]byte, bufWS)
	out := make([]byte, len(data)*2+512)
	var final uint32
	r, _, _ := compress.Call(format,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)),
		uintptr(4096), uintptr(unsafe.Pointer(&final)), uintptr(unsafe.Pointer(&ws[0])))
	if r != 0 {
		t.Skipf("RtlCompressBuffer unavailable (status 0x%x)", r)
	}
	return out[:final]
}

func TestXpressHuffmanAgainstNtdll(t *testing.T) {
	lcg := func(n int) []byte {
		b := make([]byte, n)
		s := uint64(0x1234567)
		for i := range b {
			s = s*6364136223846793005 + 1442695040888963407
			b[i] = byte(s >> 33)
		}
		return b
	}
	cases := map[string][]byte{
		"tiny":                  []byte("hello hello hello world world"),
		"text":                  bytes.Repeat([]byte("The quick brown fox. "), 40),
		"compressible-1block":   bytes.Repeat([]byte("ABCDEFG"), 30000),  // single giant match
		"incompressible-1block": lcg(60000),                             // < 65536
		"incompressible-2block": lcg(70000),                             // crosses a 65536 boundary
		"incompressible-3block": lcg(150000),                            // multiple blocks
	}
	for name, plain := range cases {
		t.Run(name, func(t *testing.T) {
			comp := ntCompress(t, plain)
			got, err := xpressHuffmanDecompress(comp, len(plain))
			if err != nil {
				t.Fatalf("decompress err: %v", err)
			}
			if !bytes.Equal(got, plain) {
				n := 0
				for n < len(got) && n < len(plain) && got[n] == plain[n] {
					n++
				}
				t.Fatalf("mismatch at byte %d (got %d bytes, want %d)", n, len(got), len(plain))
			}
		})
	}
}
