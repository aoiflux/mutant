package builtin

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// M26-NET-027. net_pcap_analyze and net_os_fingerprint read every record a
// capture holds, and pcapgo decompresses a gzipped capture transparently, so
// the length of the loop was a number the file's own size did not disclose.
// Measured before the fix: a 31 KiB .pcap.gz of two million sixteen-byte record
// headers read for 2.3 seconds in net_pcap_analyze, and 200,000 records each
// carrying a distinct flow left 224 MiB of live heap behind -- linear in a count
// nothing bounded, so a larger file is an out-of-memory rather than a slow read.
//
// Two bounds answer it and both are tested here: the record cap net_capture_raw
// already had, now shared by all three readers, and a cap on the DECOMPRESSED
// byte count. The second is the one that is easy to get wrong, because the
// obvious place to put it -- an io.LimitedReader around the file -- bounds the
// compressed bytes, and the smallness of those is the attack. The test that
// pins it is TestTheStreamCapCountsDecompressedBytesAndNotCompressedOnes, and
// it fails on that implementation: its fixture is two kilobytes on disk and
// would never reach a 64 KiB bound placed on the file.
//
// The caps are reached through pcapRecordsAllowed and pcapStreamBytesAllowed so
// that these tests can lower them. Counting to a million records costs about a
// second per builtin and the allocation differential takes twenty reads, and the
// stream cap is 1.4 GiB, which no test could reach at all.

// pcapRecordsFixture writes a capture of n records and returns its path.
//
// A SYN record is a minimal Ethernet/IPv4/TCP frame, identical in every record,
// which matters twice: each one is a SYN so net_os_fingerprint's syn_packets
// counts the records it read, and identical bytes compress far enough that the
// gzipped fixture is smaller than any byte cap worth testing, which is what
// separates a bound on the decompressed stream from a bound on the file.
//
// distinctFlows varies the source address instead, giving one flow and one
// fingerprint per record: that is the shape that costs memory, and the shape the
// allocation differential measures.
func pcapRecordsFixture(t *testing.T, name string, n int, syn bool, distinctFlows bool, compress bool) string {
	t.Helper()

	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4) // magicMicroseconds
	binary.LittleEndian.PutUint16(header[4:6], 2)          // version major
	binary.LittleEndian.PutUint16(header[6:8], 4)          // version minor
	binary.LittleEndian.PutUint32(header[16:20], 262144)   // libpcap's MAXIMUM_SNAPLEN
	binary.LittleEndian.PutUint32(header[20:24], 1)        // Ethernet

	frame := []byte(nil)
	if syn {
		frame = make([]byte, 54)
		binary.BigEndian.PutUint16(frame[12:14], 0x0800) // IPv4
		frame[14] = 0x45                                 // version 4, 5 words of header
		binary.BigEndian.PutUint16(frame[16:18], 40)     // total length
		frame[22] = 64                                   // TTL
		frame[23] = 6                                    // TCP
		copy(frame[26:30], []byte{10, 0, 0, 1})          // source
		copy(frame[30:34], []byte{10, 0, 0, 2})          // destination
		binary.BigEndian.PutUint16(frame[34:36], 40000)  // source port
		binary.BigEndian.PutUint16(frame[36:38], 80)     // destination port
		frame[46] = 0x50                                 // 5 words of TCP header
		frame[47] = 0x02                                 // SYN
	}

	record := make([]byte, 16)
	binary.LittleEndian.PutUint32(record[8:12], uint32(len(frame)))  // incl_len
	binary.LittleEndian.PutUint32(record[12:16], uint32(len(frame))) // orig_len

	var capture bytes.Buffer
	capture.Write(header)
	for i := 0; i < n; i++ {
		if distinctFlows && len(frame) > 0 {
			copy(frame[26:30], []byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		}
		capture.Write(record)
		capture.Write(frame)
	}

	body := capture.Bytes()
	if compress {
		body = gzipped(t, body)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// gzipped is one gzip layer over the bytes given.
func gzipped(t *testing.T, body []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return out.Bytes()
}

// withPcapCaps lowers one or both caps for the test that calls it and puts them
// back afterwards, as useTestAuditChain does with the clock. A zero leaves that
// cap at its real value, so a test can state which bound it is measuring and
// leave the other one unable to interfere.
func withPcapCaps(t *testing.T, records int64, streamBytes int64) {
	t.Helper()
	previousRecords, previousBytes := pcapRecordsAllowed, pcapStreamBytesAllowed
	if records > 0 {
		pcapRecordsAllowed = func() int64 { return records }
	}
	if streamBytes > 0 {
		pcapStreamBytesAllowed = func() int64 { return streamBytes }
	}
	t.Cleanup(func() {
		pcapRecordsAllowed, pcapStreamBytesAllowed = previousRecords, previousBytes
	})
}

// pcapRecordsRead is the field in each reader's result that counts the records
// it got through. They are different words for the same number, which is why
// they are listed here rather than asserted one builtin at a time: the point of
// every test below is that this number stops where the cap is.
var pcapRecordsRead = map[string]string{
	"net_capture_raw":    "count",
	"net_pcap_analyze":   "packet_count",
	"net_os_fingerprint": "syn_packets",
}

// readCapture calls one reader and returns its result hash, failing the test on
// a refusal.
func readCapture(t *testing.T, reader struct {
	name string
	call func(path string) object.Object
}, path string) *object.Hash {
	t.Helper()
	value, errObj := unwrapPair(t, reader.call(path))
	if errObj != nil {
		t.Fatalf("%s(%s): %s", reader.name, filepath.Base(path), errObj.Message)
	}
	hash, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("%s returned %T, want a HASH", reader.name, value)
	}
	return hash
}

// TestEveryPcapReaderHasACountedRecordsField holds the table above to the set of
// readers net_bounds_test.go lists. A fourth reader added without a record count
// in its result is a reader this row cannot be tested on, and finding that out
// here is better than finding it out in a lookup that silently returns "".
func TestEveryPcapReaderHasACountedRecordsField(t *testing.T) {
	for _, reader := range pcapReaders() {
		if pcapRecordsRead[reader.name] == "" {
			t.Errorf("%s reads pcap records and no field of its result says how many", reader.name)
		}
	}
	if len(pcapRecordsRead) != len(pcapReaders()) {
		t.Errorf("%d readers, %d counted-record fields", len(pcapReaders()), len(pcapRecordsRead))
	}
}

// TestEveryPcapReaderStopsAtTheRecordCapAndSaysSo is the first half of
// M26-NET-027. Before it, net_pcap_analyze and net_os_fingerprint had no cap at
// all: they read every record in the file and grew a map entry per flow and per
// fingerprint while doing it.
//
// The count is asserted and not only the flag. A cap that set truncated and
// carried on reading would be no fix -- the loop is the cost -- and it would
// pass a test that looked at truncated alone.
func TestEveryPcapReaderStopsAtTheRecordCapAndSaysSo(t *testing.T) {
	const allowed = 64
	const held = 500

	withPcapCaps(t, allowed, 0)
	path := pcapRecordsFixture(t, "many.pcap.gz", held, true, false, true)

	for _, reader := range pcapReaders() {
		hash := readCapture(t, reader, path)
		if !hashBool(t, hash, "truncated") {
			t.Errorf("%s read %d of %d records and did not report truncated",
				reader.name, allowed, held)
		}
		if got := hashInt(t, hash, pcapRecordsRead[reader.name]); got != allowed {
			t.Errorf("%s reports %s=%d over a %d-record capture, want %d: the cap has to stop "+
				"the loop and not merely be mentioned in the result",
				reader.name, pcapRecordsRead[reader.name], got, held, allowed)
		}
	}
}

// TestACappedPcapReadCostsNoMoreForMoreRecords is the growth bound, and it is
// what makes the test above a regression test rather than a field check.
//
// The two fixtures differ only in how many records they hold -- one just past
// the cap, one twenty times past it -- and each record carries its own flow, so
// an uncapped read pays for every one of them. Measured on the unfixed tree at
// 541 bytes of allocation per record, so the larger fixture cost about 21 MB
// more than the smaller; a capped read stops at the same record in both and the
// difference is noise. See allocation_gap_test.go for why this is a difference
// and not an absolute figure.
func TestACappedPcapReadCostsNoMoreForMoreRecords(t *testing.T) {
	const allowed = 2000

	withPcapCaps(t, allowed, 0)
	small := pcapRecordsFixture(t, "small.pcap.gz", allowed+1, true, true, true)
	huge := pcapRecordsFixture(t, "huge.pcap.gz", 20*(allowed+1), true, true, true)

	for _, reader := range pcapReaders() {
		name := reader.name
		call := reader.call
		var smallHash, hugeHash *object.Hash
		requireNoAllocationGap(t, name+" reading twenty times as many records past its cap",
			func() { smallHash = pcapResultHash(t, name, call(small)) },
			func() { hugeHash = pcapResultHash(t, name, call(huge)) })

		// Both reads have to have been capped for the difference to be the cost
		// of the record count alone, which is the same guard
		// TestACraftedPcapCannotSizeItsOwnAllocation applies to its refusal.
		for label, hash := range map[string]*object.Hash{"the smaller": smallHash, "the larger": hugeHash} {
			if !hashBool(t, hash, "truncated") {
				t.Fatalf("%s did not report truncated on %s capture, so the two measurements "+
					"are not of the same capped read", name, label)
			}
			if got := hashInt(t, hash, pcapRecordsRead[name]); got != allowed {
				t.Fatalf("%s read %d records of %s capture, want the cap of %d",
					name, got, label, allowed)
			}
		}
	}
}

// pcapResultHash is readCapture without the path, for the two closures above.
func pcapResultHash(t *testing.T, name string, result object.Object) *object.Hash {
	t.Helper()
	value, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("%s: %s", name, errObj.Message)
	}
	hash, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("%s returned %T, want a HASH", name, value)
	}
	return hash
}

// TestTheStreamCapCountsDecompressedBytesAndNotCompressedOnes is the second
// half of M26-NET-027, and the half an obvious fix gets wrong.
//
// pcapgo recognises the gzip magic and wraps the file in a decompressor itself,
// so a bound handed to pcapgo.NewReader -- an io.LimitedReader around the file,
// say -- counts the bytes on disk. Those are the wrong bytes: this fixture is a
// couple of kilobytes on disk and over two megabytes once expanded, so a 64 KiB
// bound on the file is never reached and the whole capture is read. The same
// 64 KiB on the decompressed stream stops it after about a thousand records.
//
// The second half of the test is what keeps the cap honest in the other
// direction: the identical capture, uncompressed, is 2 MB on disk and is read to
// its last record under the same 64 KiB cap, because there the file's own length
// is the bound and a constant of ours could only refuse something real.
func TestTheStreamCapCountsDecompressedBytesAndNotCompressedOnes(t *testing.T) {
	const held = 30000
	const streamBytes = 64 << 10

	withPcapCaps(t, 0, streamBytes)

	compressed := pcapRecordsFixture(t, "bomb.pcap.gz", held, true, false, true)
	plain := pcapRecordsFixture(t, "bomb.pcap", held, true, false, false)

	compressedSize := fileSize(t, compressed)
	plainSize := fileSize(t, plain)
	if compressedSize >= streamBytes {
		t.Fatalf("the compressed fixture is %d bytes, which is not under the %d-byte cap: "+
			"this test can only tell the two bounds apart while it is", compressedSize, streamBytes)
	}
	if plainSize <= streamBytes {
		t.Fatalf("the uncompressed fixture is %d bytes, which is not over the %d-byte cap: "+
			"this test can only show the cap is not applied to a file while it is",
			plainSize, streamBytes)
	}

	for _, reader := range pcapReaders() {
		field := pcapRecordsRead[reader.name]

		hash := readCapture(t, reader, compressed)
		if !hashBool(t, hash, "truncated") {
			t.Errorf("%s read a %d-byte capture expanding to %d bytes under a %d-byte stream "+
				"cap and did not report truncated: the cap is counting the compressed bytes",
				reader.name, compressedSize, plainSize, streamBytes)
		}
		read := hashInt(t, hash, field)
		if read == 0 {
			t.Errorf("%s read no records at all from the compressed capture", reader.name)
		}
		if read >= held/2 {
			t.Errorf("%s read %s=%d of %d records under a %d-byte stream cap: the bound is not "+
				"on the decompressed stream", reader.name, field, read, held, streamBytes)
		}

		whole := readCapture(t, reader, plain)
		if hashBool(t, whole, "truncated") {
			t.Errorf("%s reported truncated on a %d-byte uncompressed capture: the stream cap "+
				"applies where the file's length says nothing, and nowhere else",
				reader.name, plainSize)
		}
		if got := hashInt(t, whole, field); got != held {
			t.Errorf("%s reports %s=%d for an uncompressed capture of %d records, want %d",
				reader.name, field, got, held, held)
		}
	}
}

// fileSize is the size on disk, which both halves of the test above assert
// about rather than assume.
func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Size()
}

// TestACaptureGzippedMoreThanOnceIsRefused closes the door the fix would
// otherwise open.
//
// Opening the gzip layer ourselves is what puts the cap on the decompressed
// side of it, but it also means pcapgo now sees a stream it would decompress
// again if that stream began with the gzip magic -- and a decompressor outside
// the cap is the unbounded expansion all over again, one layer in. So a capture
// gzipped twice is refused. Nothing readable is lost: pcapgo unwraps exactly one
// layer, so such a file failed its header check before this fix too.
func TestACaptureGzippedMoreThanOnceIsRefused(t *testing.T) {
	plain := pcapRecordsFixture(t, "once.pcap", 4, true, false, false)
	body, err := os.ReadFile(plain)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	twice := filepath.Join(t.TempDir(), "twice.pcap.gz")
	if err := os.WriteFile(twice, gzipped(t, gzipped(t, body)), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	for _, reader := range pcapReaders() {
		value, errObj := unwrapPair(t, reader.call(twice))
		if errObj == nil {
			t.Errorf("%s accepted a capture gzipped twice and returned %T", reader.name, value)
			continue
		}
		if !strings.Contains(errObj.Message, "gzipped more than once") {
			t.Errorf("%s: expected the nested-gzip refusal, got %q", reader.name, errObj.Message)
		}
	}
}

// TestAnOrdinaryCaptureIsUnchangedByTheCaps is the false-refusal guard. A bound
// is only correct if what it refuses is unreal, so the capture every reader is
// actually given -- a handful of packets, compressed or not -- has to come back
// whole, with truncated false, and has to come back the same either way.
func TestAnOrdinaryCaptureIsUnchangedByTheCaps(t *testing.T) {
	const held = 5

	plain := pcapRecordsFixture(t, "ordinary.pcap", held, true, true, false)
	compressed := pcapRecordsFixture(t, "ordinary.pcap.gz", held, true, true, true)

	for _, reader := range pcapReaders() {
		field := pcapRecordsRead[reader.name]
		for _, tc := range []struct {
			what string
			path string
		}{{"uncompressed", plain}, {"gzipped", compressed}} {
			hash := readCapture(t, reader, tc.path)
			if hashBool(t, hash, "truncated") {
				t.Errorf("%s reported truncated on a %s capture of %d packets",
					reader.name, tc.what, held)
			}
			if got := hashInt(t, hash, field); got != held {
				t.Errorf("%s reports %s=%d for a %s capture of %d packets, want %d",
					reader.name, field, got, tc.what, held, held)
			}
		}
	}

	// The flow rows and the fingerprint rows are the part a cap could quietly
	// shorten without moving any count, so they are compared across the two
	// encodings of the same bytes.
	plainFlows := flowRowCount(t, NetPCAPAnalyze(stringObj(plain)))
	gzipFlows := flowRowCount(t, NetPCAPAnalyze(stringObj(compressed)))
	if plainFlows != held || gzipFlows != held {
		t.Errorf("net_pcap_analyze found %d flows uncompressed and %d gzipped, want %d in both",
			plainFlows, gzipFlows, held)
	}
}

// flowRowCount is how many flow rows net_pcap_analyze returned.
func flowRowCount(t *testing.T, result object.Object) int {
	t.Helper()
	hash := pcapResultHash(t, "net_pcap_analyze", result)
	value, ok := hashValueByStringKey(hash, "flows")
	if !ok {
		t.Fatalf("net_pcap_analyze returned no flows field")
	}
	array, ok := value.(*object.Array)
	if !ok {
		t.Fatalf("net_pcap_analyze flows is %T, want an ARRAY", value)
	}
	return len(array.Elements)
}
