package builtin

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// lnkWithTruncatedLinkInfo builds a 95-byte shell link whose LinkInfo says a
// LocalBasePath follows and then ends one byte before the four that would say
// where it is.
//
// The figures are what make the defect reachable. parseLnkLinkInfo established
// start+16 -- 92 bytes -- and then read the offset at [start+16:start+20],
// which needs 96. Bytes 92, 93 and 94 are the link's own and are set to 12,
// which would point the path at offset 88; byte 95 is past the end, and the
// string "SLACK" sits at 88 so that a read which should not happen produces
// something nameable rather than an empty string that proves nothing.
func lnkWithTruncatedLinkInfo() []byte {
	const size = 95
	blob := make([]byte, size)
	binary.LittleEndian.PutUint32(blob[0:4], 0x0000004C) // HeaderSize
	binary.LittleEndian.PutUint32(blob[20:24], 0x02)     // LinkFlags: HasLinkInfo only
	binary.LittleEndian.PutUint32(blob[24:28], 0x20)     // FileAttributes (archive)
	binary.LittleEndian.PutUint64(blob[44:52], uint64((1700000000+filetimeEpochDeltaSec)*10_000_000))
	binary.LittleEndian.PutUint32(blob[52:56], 4096) // FileSize

	// LinkInfo at 76. The declared size runs past the end of the link, which is
	// ordinary for a truncated one and is clamped to the length.
	binary.LittleEndian.PutUint32(blob[76:80], 1000) // LinkInfoSize
	binary.LittleEndian.PutUint32(blob[84:88], 0x01) // VolumeIDAndLocalBasePath
	copy(blob[88:], "SLACK\x00")
	blob[92] = 12 // the low byte of a LocalBasePathOffset of 12, pointing at 88
	return blob
}

// TestATruncatedLinkInfoIsNotReadPastTheEndOfTheLink is M26-ART-011.
//
// One input, two outcomes, and which one happened was decided by the allocator
// rather than by the file: a slice expression may reach past the length as far
// as the capacity, so where there was slack the parser read it and reported it
// as local_base_path -- a file path shown to an examiner that was never in the
// link -- and where there was none it panicked. os.ReadFile leaves slack;
// make([]byte, size), which is how jumplist_parse reads a stream, does not.
//
// Both are checked here, because fixing only the panic would leave the wrong
// answer, and fixing only the bounds check would leave the rest of the parser
// able to do the same thing somewhere else. The capacity is cut to the length
// once, for the whole parser.
func TestATruncatedLinkInfoIsNotReadPastTheEndOfTheLink(t *testing.T) {
	blob := lnkWithTruncatedLinkInfo()

	// Spare capacity, which is what reading a file gives: the old parser
	// answered "SLACK".
	roomy := make([]byte, 200)
	copy(roomy, blob)
	roomy = roomy[:len(blob)]
	if cap(roomy) <= len(roomy) {
		t.Fatalf("this case needs spare capacity, got cap %d len %d", cap(roomy), len(roomy))
	}

	// Exact capacity, which is what reading a jump list stream gives: the old
	// parser panicked.
	exact := make([]byte, len(blob))
	copy(exact, blob)

	for _, c := range []struct {
		name string
		data []byte
	}{
		{"spare capacity", roomy},
		{"exact capacity", exact},
	} {
		t.Run(c.name, func(t *testing.T) {
			fields, damaged, err := parseLnkFields(c.data)
			if err != nil {
				t.Fatalf("a link whose LinkInfo is cut short is still a link: err = %v", err)
			}
			if damaged {
				t.Errorf("nothing came apart here; the link simply has no path in it")
			}
			if got := fields["local_base_path"].(*object.String).Value; got != "" {
				t.Errorf("local_base_path = %q, want empty: there is no offset in the link to "+
					"read it from, and anything else was read from past its end", got)
			}
			// The header was read before the LinkInfo and is the half an
			// examiner still has.
			if got := fields["write_time"].(*object.Integer).Value; got != 1700000000 {
				t.Errorf("write_time = %d, want the header field that was read before the "+
					"LinkInfo ran out", got)
			}
		})
	}
}

// TestLnkParseReportsADamagedLinkAsOneRatherThanAsAPanic checks what reaches the
// caller. The recover used to be the one wrapping the whole builtin, so the
// message was the runtime's description of a slice -- "slice bounds out of range
// [:604] with capacity 601" -- which says nothing about the file.
func TestLnkParseReportsADamagedLinkAsOneRatherThanAsAPanic(t *testing.T) {
	blob := lnkWithTruncatedLinkInfo()
	path := filepath.Join(t.TempDir(), "truncated.lnk")
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatal(err)
	}

	value, errObj := unwrapPair(t, LnkParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("lnk_parse of a link with a cut-short LinkInfo: error = %s", errObj.Inspect())
	}
	h := value.(*object.Hash)
	if hStr(t, h, "local_base_path") != "" {
		t.Errorf("local_base_path = %q, want empty", hStr(t, h, "local_base_path"))
	}
	if hInt(t, h, "write_time") != 1700000000 {
		t.Errorf("write_time = %d, want the header timestamps kept", hInt(t, h, "write_time"))
	}
}

// breakLinkOn substitutes a link parser that panics when the bytes it is given
// contain marker, and parses normally otherwise.
//
// There is no crafted link that panics any more, which is what M26-ART-011
// fixed, so this is how the recover and the counts that depend on it are
// driven. A recover nothing exercises is a recover nobody knows works.
func breakLinkOn(t *testing.T, marker string) {
	t.Helper()
	original := parseLnkBody
	t.Cleanup(func() { parseLnkBody = original })
	parseLnkBody = func(data []byte) (map[string]object.Object, error) {
		if bytes.Contains(data, []byte(marker)) {
			panic("a field reached past the end of the link")
		}
		return original(data)
	}
}

// damagedThenGood builds a custom jump list whose first link carries the marker
// and whose second is sound.
//
// The order is forced. This format has no directory: the links are found by
// scanning for their signature, and each attempt is handed the rest of the file,
// so a marker placed after the good link would be inside the good link's slice
// as well and both would fail.
func damagedThenGood(marker string) []byte {
	damaged := make([]byte, 80)
	copy(damaged[0:20], lnkHeaderSig) // HeaderSize + LinkCLSID, which is what the scan matches
	copy(damaged[64:], marker)
	return append(damaged, craftLnk(`..\good.exe`)...)
}

// TestOneDamagedLinkDoesNotCostTheWholeJumpList is the other half of M26-ART-011.
//
// The panic escaped parseLnkBytes to whichever builtin's recover was outermost,
// which for a jump list was the one wrapping the whole parse: one damaged stream
// out of twenty, and the DestList and the other nineteen links went with it. The
// recover now sits in the link parser, which is the only place that knows the
// failure is one link's and not the file's.
func TestOneDamagedLinkDoesNotCostTheWholeJumpList(t *testing.T) {
	const marker = "BREAKHERE"
	breakLinkOn(t, marker)

	path := filepath.Join(t.TempDir(), "run.customDestinations-ms")
	if err := os.WriteFile(path, damagedThenGood(marker), 0o644); err != nil {
		t.Fatal(err)
	}

	value, errObj := unwrapPair(t, JumplistParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("one damaged link must not cost the file: error = %s", errObj.Inspect())
	}
	h := value.(*object.Hash)
	entries := h.Pairs[(&object.String{Value: "entries"}).HashKey()].Value.(*object.Array)
	if len(entries.Elements) != 1 {
		t.Fatalf("the sound link is still a destination, got %d entries: %s",
			len(entries.Elements), h.Inspect())
	}
	if !strings.Contains(entries.Elements[0].Inspect(), "good.exe") {
		t.Errorf("the surviving entry should be the sound link, got %s",
			entries.Elements[0].Inspect())
	}
}

// TestADamagedLinkIsReportedAsOneRatherThanAsARuntimeMessage checks what a
// recovered panic becomes. It used to be the runtime's description of a slice --
// "slice bounds out of range [:604] with capacity 601" -- reported by whichever
// builtin's recover caught it, which says nothing about the file.
func TestADamagedLinkIsReportedAsOneRatherThanAsARuntimeMessage(t *testing.T) {
	const marker = "BREAKHERE"
	breakLinkOn(t, marker)

	broken := make([]byte, 80)
	copy(broken[0:20], lnkHeaderSig)
	copy(broken[64:], marker)

	fields, damaged, err := parseLnkFields(broken)
	if err == nil {
		t.Fatal("a link that came apart is an error, not an answer")
	}
	if fields != nil {
		t.Errorf("no half-built fields escape a damaged link, got %v", fields)
	}
	if !damaged {
		t.Error("the caller has to be able to tell this from bytes that were never a link")
	}
	if !strings.Contains(err.Error(), "the shell link is damaged") {
		t.Errorf("err = %q, want a sentence about the link", err)
	}
}

// TestAJumpListSaysHowManyEntriesItCouldNotRead covers the silent drop this fix
// would otherwise have widened.
//
// A stream the parser could not read was skipped and nothing said so, and
// turning panics into errors sends more streams down that path. A short answer
// that does not say it is short is worth less than an error, because nothing
// downstream can tell it from a complete one.
//
// Only a link that came apart is counted on this format. The links here are
// found by scanning for a signature, so a failure is usually bytes that were
// never a link -- counting those would report losses that did not happen.
func TestAJumpListSaysHowManyEntriesItCouldNotRead(t *testing.T) {
	read := func(t *testing.T, blob []byte) *object.Hash {
		t.Helper()
		path := filepath.Join(t.TempDir(), "run.customDestinations-ms")
		if err := os.WriteFile(path, blob, 0o644); err != nil {
			t.Fatal(err)
		}
		value, errObj := unwrapPair(t, JumplistParse(stringObj(path)))
		if errObj != nil {
			t.Fatalf("jumplist_parse: %s", errObj.Inspect())
		}
		return value.(*object.Hash)
	}

	good := craftLnk(`..\good.exe`)

	t.Run("nothing lost", func(t *testing.T) {
		if got := hInt(t, read(t, good), "unreadable_entries"); got != 0 {
			t.Errorf("a jump list of one sound link lost nothing, got %d", got)
		}
	})

	t.Run("a signature that was never a link is not a loss", func(t *testing.T) {
		// A signature with nothing behind it: the scan finds it, the parser
		// refuses it for being shorter than a header, and nobody lost a
		// destination. It has to be the whole 20-byte signature, or the scan
		// does not find it and the case proves nothing.
		notALink := append(append([]byte{}, good...), lnkHeaderSig...)
		if got := hInt(t, read(t, notALink), "unreadable_entries"); got != 0 {
			t.Errorf("unreadable_entries = %d, want 0", got)
		}
	})

	t.Run("a link that came apart is a loss", func(t *testing.T) {
		const marker = "BREAKHERE"
		breakLinkOn(t, marker)
		h := read(t, damagedThenGood(marker))
		if got := hInt(t, h, "unreadable_entries"); got != 1 {
			t.Errorf("unreadable_entries = %d, want 1: the damaged link is not in the "+
				"entries and the answer has to say so", got)
		}
		if got := hInt(t, h, "entry_count"); got != 1 {
			t.Errorf("entry_count = %d, want 1: the count is of what is there", got)
		}
	})
}
