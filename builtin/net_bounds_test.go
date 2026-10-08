package builtin

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// TestNetBannerKeepsTheGreetingOfAServerThatHoldsTheConnection is M26-NET-001.
// SSH, SMTP and FTP each write their greeting and then wait for the client, so
// the read ends at the deadline and not at an EOF. io.ReadAll reports that as
// an error while still returning the bytes it read, and the old code answered
// ok:false with an empty banner -- throwing away the banner of every service
// that behaves this way, which is most of the ones worth fingerprinting.
//
// The two tests that existed before this one both close the connection
// straight after writing (TestNetBannerLocalServer here, and the one in
// network_forensics_test.go), so neither could see it.
func TestNetBannerKeepsTheGreetingOfAServerThatHoldsTheConnection(t *testing.T) {
	const greeting = "220 smtp.example ESMTP ready" + "\r\n"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	held := make(chan struct{})
	defer close(held)
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte(greeting))
		// Hold it open past net_banner's timeout, which is what a real mail
		// or SSH server does while it waits for a command.
		<-held
	}()

	h := netHash(t, NetBanner(stringObj(ln.Addr().String()), intObj(400)))
	if !netHashBool(t, h, "ok") {
		t.Fatalf("a banner was written, so net_banner should be ok: %s", h.Inspect())
	}
	if got := hashStr(t, h, "banner"); !strings.Contains(got, "220 smtp.example ESMTP ready") {
		t.Fatalf("the banner did not survive the read deadline: %q", got)
	}
	if got := hashStr(t, h, "error"); got != "" {
		t.Fatalf("a deadline is how a banner ends, so error should stay empty: %q", got)
	}
}

// TestNetBannerStillFailsWhenNothingWasWritten holds the other half of
// M26-NET-001. The bytes read decide the answer, so a deadline that expires
// having read none of them is still a failure and must not be reported as a
// successful empty banner -- which is the bug M26-NET-002 was, one builtin over.
func TestNetBannerStillFailsWhenNothingWasWritten(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	held := make(chan struct{})
	defer close(held)
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer c.Close()
		// Accept and say nothing at all.
		<-held
	}()

	h := netHash(t, NetBanner(stringObj(ln.Addr().String()), intObj(300)))
	if netHashBool(t, h, "ok") {
		t.Fatalf("nothing was written, so net_banner should not be ok: %s", h.Inspect())
	}
	if got := hashStr(t, h, "banner"); got != "" {
		t.Fatalf("banner should be empty: %q", got)
	}
	if got := hashStr(t, h, "error"); got == "" {
		t.Fatal("a failed banner read should say why")
	}
}

// bannerServer answers one connection, writes n bytes and holds the socket
// open until the test is done with it -- which is what a real SSH or SMTP
// server does while it waits for a command, and what makes the read end at
// net_banner's deadline rather than at an EOF.
func bannerServer(t *testing.T, n int) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	held := make(chan struct{})
	t.Cleanup(func() { close(held) })
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write(bytes.Repeat([]byte("A"), n))
		<-held
	}()
	return ln.Addr().String()
}

// TestAGreetingPastTheCapIsRefusedAndOneAtTheCapIsNot is M26-NET-026, and it is
// the same bug as M26-NET-031 one builtin over: io.LimitReader returns EOF at
// its bound and io.ReadAll turns EOF into nil, so a read bounded at exactly the
// cap reported the prefix of a longer stream as a complete greeting -- ok:true,
// the first 4096 bytes, and an empty error field.
//
// The boundary is both halves of one test on purpose. A refusal at the cap and
// a refusal one byte below it are the same code with different arithmetic, and
// only the pair says which one shipped.
func TestAGreetingPastTheCapIsRefusedAndOneAtTheCapIsNot(t *testing.T) {
	// bannerCap is maxBannerBytes, spelled out so that this file still compiles
	// at bare HEAD, where that constant does not exist yet -- which is what
	// lets the other detectors here fail with their own messages instead of
	// disappearing into a build error. It cannot drift unnoticed: a larger cap
	// stops the first subtest seeing a refusal, a smaller one stops the second
	// seeing a whole greeting.
	const bannerCap = 4096

	t.Run("one byte past the cap is refused", func(t *testing.T) {
		h := netHash(t, NetBanner(stringObj(bannerServer(t, bannerCap+1)), intObj(400)))
		if netHashBool(t, h, "ok") {
			t.Fatalf("a greeting past the cap must not be reported as a banner: %s", h.Inspect())
		}
		if got := hashStr(t, h, "banner"); got != "" {
			t.Fatalf("a refused greeting must not carry its prefix: %d bytes", len(got))
		}
		if got := hashStr(t, h, "error"); !strings.Contains(got, "exceeds") {
			t.Fatalf("the refusal should name the cap: %q", got)
		}
	})

	t.Run("a greeting at exactly the cap still arrives whole", func(t *testing.T) {
		h := netHash(t, NetBanner(stringObj(bannerServer(t, bannerCap)), intObj(400)))
		if !netHashBool(t, h, "ok") {
			t.Fatalf("a greeting of exactly the cap is a banner: %s", h.Inspect())
		}
		if got := hashStr(t, h, "banner"); len(got) != bannerCap {
			t.Fatalf("the whole greeting should arrive: got %d bytes, want %d",
				len(got), bannerCap)
		}
		if got := hashStr(t, h, "error"); got != "" {
			t.Fatalf("a greeting at the cap is not an error: %q", got)
		}
	})
}

// craftedPcap writes a pcap whose header lies. It declares the largest
// possible snapshot length and then one record claiming inclLen bytes, while
// the file itself is forty bytes long: a 24-byte file header and a 16-byte
// record header, with no packet data behind them at all.
//
// The magic and the version are the ones pcapgo's own writer emits, so the
// file is well formed right up to the point where it asks for the allocation.
func craftedPcap(t *testing.T, inclLen uint32) string {
	t.Helper()

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4) // magicMicroseconds
	binary.LittleEndian.PutUint16(hdr[4:6], 2)          // version major
	binary.LittleEndian.PutUint16(hdr[6:8], 4)          // version minor
	binary.LittleEndian.PutUint32(hdr[16:20], 0xffffffff)
	binary.LittleEndian.PutUint32(hdr[20:24], 1) // Ethernet

	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:12], inclLen)  // incl_len
	binary.LittleEndian.PutUint32(rec[12:16], inclLen) // orig_len

	path := filepath.Join(t.TempDir(), "crafted.pcap")
	if err := os.WriteFile(path, append(hdr, rec...), 0o600); err != nil {
		t.Fatalf("write crafted pcap: %v", err)
	}
	return path
}

// pcapReaders is the three builtins that open a capture file with
// pcapgo.NewReader. They are listed once so a fourth cannot be added without
// deciding whether it belongs here.
func pcapReaders() []struct {
	name string
	call func(path string) object.Object
} {
	return []struct {
		name string
		call func(path string) object.Object
	}{
		{"net_capture_raw", func(p string) object.Object {
			return NetCaptureRaw(stringObj(p))
		}},
		{"net_pcap_analyze", func(p string) object.Object {
			return NetPCAPAnalyze(stringObj(p))
		}},
		{"net_os_fingerprint", func(p string) object.Object {
			return NetOSFingerprint(stringObj(p))
		}},
	}
}

// TestACraftedPcapCannotSizeItsOwnAllocation is M26-NET-009. gopacket takes the
// snapshot length out of the file header and then refuses any record longer
// than it, so a file declaring a snaplen of 0xffffffff was declaring its own
// bound -- and a forty-byte file drew a 16 MiB allocation out of each of the
// three builtins that read one.
//
// Holding the reader to maxPcapPacketBytes turns that record into an error
// before anything is allocated for it. The growth bound is what makes this a
// regression test rather than a message check: an error returned after the
// allocation would read the same and would fix nothing.
func TestACraftedPcapCannotSizeItsOwnAllocation(t *testing.T) {
	// The file is forty bytes, and capPcapSnaplen lowers the snaplen to the
	// file's own length, so a record claiming sixty-four bytes is already
	// refused -- by the same check and with the same message as one claiming
	// 16 MiB. That makes the two comparable, and their difference the cost of
	// the number alone. See allocation_gap_test.go for why the absolute figure
	// this asserted until 2026-10-06 could not survive a full run of this
	// package.
	const overTheFile = 64
	const inclLen = 16 << 20

	honestPath := craftedPcap(t, overTheFile)
	claimedPath := craftedPcap(t, inclLen)

	for _, tc := range pcapReaders() {
		var honestErr, errObj *object.Error
		requireNoAllocationGap(t, tc.name+" reading a 40-byte file claiming a 16 MiB packet",
			func() { _, honestErr = unwrapPair(t, tc.call(honestPath)) },
			func() { _, errObj = unwrapPair(t, tc.call(claimedPath)) })

		if honestErr == nil {
			t.Fatalf("%s accepted a 40-byte file claiming a %d byte packet, so the two "+
				"measurements are not of the same refusal", tc.name, overTheFile)
		}
		if errObj == nil {
			t.Fatalf("%s accepted a 40-byte file claiming a %d byte packet", tc.name, inclLen)
		}
		for _, failure := range []*object.Error{honestErr, errObj} {
			if !strings.Contains(failure.Message, "snap length") {
				t.Fatalf("%s: expected the snaplen refusal, got %q", tc.name, failure.Message)
			}
		}
	}
}

// TestAPcapWithAnHonestSnaplenIsStillRead is the false-refusal guard for
// M26-NET-009. Capping the snaplen is only correct if a capture the standard
// tools could have written still reads, so this one declares the snaplen
// tcpdump uses and carries a real, if tiny, Ethernet frame.
func TestAPcapWithAnHonestSnaplenIsStillRead(t *testing.T) {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144) // libpcap's MAXIMUM_SNAPLEN
	binary.LittleEndian.PutUint32(hdr[20:24], 1)

	frame := make([]byte, 64)
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(rec[12:16], uint32(len(frame)))

	body := append(append(hdr, rec...), frame...)
	path := filepath.Join(t.TempDir(), "honest.pcap")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write honest pcap: %v", err)
	}

	for _, tc := range pcapReaders() {
		if _, errObj := unwrapPair(t, tc.call(path)); errObj != nil {
			t.Fatalf("%s refused a capture written at tcpdump's own snaplen: %s",
				tc.name, errObj.Message)
		}
	}
}

// TestALargeRecordThatTheFileReallyHoldsIsStillRead is the second
// false-refusal guard for M26-NET-009, and it is the reason the bound is the
// file's own length and not a constant.
//
// A flat cap at libpcap's MAXIMUM_SNAPLEN of 262144 looked safe and was not.
// USBPcap declares a snapshot length of 128 MiB and writes records in the
// megabytes, and EBHSCR records run to 32 MiB; both read correctly today,
// because a record's index, timestamp and length come out of its sixteen-byte
// header and need no decoder at all. gopacket not knowing link type 249 costs
// the empty src, dst and protocol fields and nothing else. Capping the snaplen
// below what such a file declares would have refused the whole capture and
// taken a working one away from an examiner.
//
// The file's own length is the honest bound: no record can be longer than the
// file that holds it, so a header that over-declares is still read up to what
// the file actually carries, and the crafted forty-byte file above is still
// refused.
func TestALargeRecordThatTheFileReallyHoldsIsStillRead(t *testing.T) {
	const payload = 1 << 20
	const usbpcapLinkType = 249    // LINKTYPE_USBPCAP
	const usbpcapSnaplen = 1 << 27 // 128 MiB, what USBPcap writes into the header

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], usbpcapSnaplen)
	binary.LittleEndian.PutUint32(hdr[20:24], usbpcapLinkType)

	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:12], payload)
	binary.LittleEndian.PutUint32(rec[12:16], payload)

	body := append(append(hdr, rec...), make([]byte, payload)...)
	path := filepath.Join(t.TempDir(), "usbpcap.pcap")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write usbpcap-shaped capture: %v", err)
	}

	for _, tc := range pcapReaders() {
		if _, errObj := unwrapPair(t, tc.call(path)); errObj != nil {
			t.Fatalf("%s refused a %d-byte record that the file really holds: %s",
				tc.name, payload, errObj.Message)
		}
	}

	// And the record arrived whole rather than being skipped: net_capture_raw
	// counts what it read, and a refusal inside pcapgo would have come back as
	// an error from the builtin rather than a short count.
	h := netHash(t, NetCaptureRaw(stringObj(path)))
	if got := hashInt(t, h, "count"); got != 1 {
		t.Fatalf("expected the one record to be read, got count=%d", got)
	}
	if hashStr(t, h, "link_type") == "" {
		t.Fatal("link_type should still be reported for a link type gopacket cannot decode")
	}
}
