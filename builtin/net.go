package builtin

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"mutant/object"
)

// maxBannerBytes is the most a service's greeting may be. A banner is one line
// naming a product and a version -- "SSH-2.0-OpenSSH_9.6", "220 smtp.example
// ESMTP ready" -- and what a peer sends past four kibibytes of it is not a
// banner any more. The read is bounded because the peer decides when to stop
// talking: uncapped, a service that answers a connection with an endless stream
// would be recorded in full, into a VM variable that is re-encrypted on every
// store. A greeting that reaches the cap is refused rather than clipped,
// because the first four kibibytes of a longer stream reported as a whole
// banner is a wrong answer and nothing in the result could say so.
//
//mutant:limit bytes
const maxBannerBytes = 4096

// maxPcapPacketBytes is the ceiling on one pcap record, for the single case
// where the file's own size is no guide to it: pcapgo decompresses a gzipped
// capture transparently, and a compressed file's length bounds nothing inside
// it.
//
// The value is the largest single record Wireshark itself will read --
// WTAP_MAX_PACKET_SIZE_USBPCAP -- so a record these builtins refuse is one
// Wireshark would refuse too. It is deliberately far above any link MTU,
// because real captures exceed one: USBPcap writes megabyte bulk transfers and
// EBHSCR records run to 32 MiB, and both read correctly here today. A record's
// index, timestamp and length come straight out of its sixteen-byte header and
// need no decoder, so "gopacket cannot decode that link type" is not a reason
// to refuse the file -- a cap at some Ethernet-shaped figure would have thrown
// away captures that work.
//
//mutant:limit bytes
const maxPcapPacketBytes = 128 << 20

// maxPcapPackets is how many records net_capture_raw returns before it stops
// and marks the result truncated. Each record becomes a hash in a VM variable,
// so the cost is per packet rather than per byte, and a capture of a busy link
// holds far more packets than anyone reads at once. Past the cap the result
// says so, which is the difference between a short answer and a wrong one.
//
//mutant:limit count
const maxPcapPackets = 1_000_000

// capPcapSnaplen bounds what one record of a capture may be trusted to ask for.
//
// pcapgo reads the snapshot length out of the file header and then refuses any
// record longer than it, so until now the file stated its own bound: forty
// bytes declaring a snaplen of 0xffffffff drew a 16 MiB allocation out of a
// record header with nothing at all behind it.
//
// The bound that matters is the file's own length, because a record's data has
// to BE in the file. No honest capture holds a record longer than itself, so
// this bound can refuse nothing real -- which a figure chosen from the shape of
// a network cannot promise. Where the length says nothing, which is a gzipped
// capture, maxPcapPacketBytes applies instead.
//
// It only ever lowers, and that matters as much as the bound does. A capture
// written at tcpdump's -s 1500 keeps its 1500, so a record whose incl_len has
// been corrupted upward still fails pcapgo's own check and the examiner is told
// the file is damaged. Raising a snaplen to a cap would instead accept the
// corrupt length, read the following record headers as that packet's payload,
// and carry on from a misaligned offset -- turning a reported error into a
// flow summary that is quietly wrong.
func capPcapSnaplen(reader *pcapgo.Reader, file *os.File) {
	bound := uint32(maxPcapPacketBytes)
	if size, ok := pcapUncompressedSize(file); ok && size < int64(bound) {
		bound = uint32(size)
	}
	if reader.Snaplen() > bound {
		reader.SetSnaplen(bound)
	}
}

// pcapUncompressedSize reports the file's length when that length bounds a
// record, which is when the capture is not compressed. pcapgo recognises gzip
// by its two magic bytes and wraps the reader in a decompressor, and the length
// of a compressed file is no bound on what comes out of it.
//
// ReadAt is used rather than a seek because the reader already holds this file
// and has consumed its header; ReadAt does not move the shared offset.
func pcapUncompressedSize(file *os.File) (int64, bool) {
	compressed, known := pcapIsGzip(file)
	if !known || compressed {
		return 0, false
	}
	info, err := file.Stat()
	if err != nil {
		return 0, false
	}
	return info.Size(), true
}

// pcapIsGzip reports whether the capture is gzipped, and whether that could
// be read at all.
//
// Two answers rather than one, because they lead to different places: a file
// whose first two bytes cannot be read is not known to be uncompressed, and
// reading "could not tell" as "not compressed" would bound a decompressor's
// output by the length of the file it came out of.
//
// The test is the one pcapgo's own readHeader makes -- the two gzip magic
// bytes -- and it is written once because two copies of a magic number drift.
// ReadAt leaves the shared offset alone, as above.
func pcapIsGzip(file *os.File) (bool, bool) {
	var magic [2]byte
	if _, err := file.ReadAt(magic[:], 0); err != nil {
		return false, false
	}
	return magic[0] == 0x1f && magic[1] == 0x8b, true
}

// maxPcapStreamBytes is the most a compressed capture may expand to while one
// of the three pcap builtins reads it.
//
// pcapgo opens the decompressor itself: readHeader peeks two bytes and, on the
// gzip magic, replaces its own reader with a gzip.Reader. A bound handed to
// pcapgo.NewReader therefore counts the bytes on disk, and those are the wrong
// number -- a capture's smallness when compressed is the whole of the attack.
// Measured here: a 31 KiB .pcap.gz of two million sixteen-byte record headers
// read for 2.3 seconds, and 200,000 records carrying a distinct flow each left
// 224 MiB of live heap behind. So the bound sits on the decompressed side of
// the gzip layer, which is why pcapRecordStream opens that layer rather than
// leaving it to pcapgo.
//
// The figure is derived and not chosen. A million records -- the record cap --
// each a record header and a whole Ethernet frame, is the largest stream that
// cap can honestly ask for, so no capture this bound stops short of its end is
// one the record cap would have read whole. It lands within half a gibibyte of
// maxDecompressedBytes, the ceiling builtin/archive.go puts on a single
// decompression, which is this tree's existing figure for the most a
// compressed stream may produce.
//
// Where the capture is NOT compressed, no bound of ours applies: the file's
// own length bounds the stream, the operating system enforces it, and a
// constant here could only refuse a capture the file cannot hold. That is
// capPcapSnaplen's reasoning one level up -- the real figure wherever there is
// one, a constant only where there is not.
//
//mutant:limit bytes
const maxPcapStreamBytes = maxPcapPackets * (pcapRecordHeaderBytes + pcapEthernetFrameBytes)

// pcapRecordHeaderBytes is a pcap record header: ts_sec, ts_usec, incl_len and
// orig_len, four 32-bit fields ahead of every record in the file. A format
// fact, not a limit.
const pcapRecordHeaderBytes = 16

// pcapEthernetFrameBytes is a whole Ethernet frame as a capture stores one:
// the 14-byte header and the 1500-byte MTU, with no VLAN tag and no frame
// check sequence. A format fact, not a limit; it is named because
// maxPcapStreamBytes is derived from it rather than typed out.
const pcapEthernetFrameBytes = 1514

// errPcapStreamFull is what a read past the stream cap returns.
//
// It is returned unwrapped and the readers compare it with ==: this package's
// macro-purity guard forbids errors.Is from an allowlisted builtin, and an
// unwrapped sentinel is what that comparison needs anyway.
var errPcapStreamFull = errors.New("the capture expands past the decompressed-stream cap")

// errPcapNestedGzip refuses a capture that is gzipped more than once.
//
// Nothing readable is lost by it. pcapgo unwraps exactly one layer, so a
// doubly gzipped capture fails its header check today with "Unknown magic";
// accepting one here would put a second decompressor BEYOND the cap below,
// defeating the bound pcapRecordStream exists to impose with the same trick
// one layer in.
var errPcapNestedGzip = errors.New("the capture is gzipped more than once, and the " +
	"decompressor inside the cap would itself be read through another one outside it; " +
	"gunzip it once and read the result")

// pcapCappedReader bounds the bytes drawn through it, and says so when it
// stops rather than looking like the end of the file.
//
// io.LimitedReader is the wrong tool here, and the reason is this row itself:
// it returns EOF at its bound, and EOF is how a capture ends, so a read cut
// off at the cap would be indistinguishable from one that finished -- a silent
// drop handed back as a whole answer. Reaching the bound is an error the three
// readers recognise, and what they report for it is truncated.
type pcapCappedReader struct {
	r         io.Reader
	remaining int64
}

func (c *pcapCappedReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, errPcapStreamFull
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	return n, err
}

// pcapRecordStream is the stream a pcapgo.Reader should read a capture from.
//
// An uncompressed capture is handed to pcapgo exactly as it was before this
// existed. A gzipped one is decompressed here instead, with the cap on the
// decompressed side of it, and pcapgo is then given a stream that no longer
// begins with the gzip magic -- so it attaches no decompressor of its own, and
// every byte it reads has been counted.
func pcapRecordStream(file *os.File) (io.Reader, error) {
	compressed, known := pcapIsGzip(file)
	if !known || !compressed {
		return file, nil
	}
	decompressed, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	stream := bufio.NewReader(&pcapCappedReader{r: decompressed, remaining: pcapStreamBytesAllowed()})
	magic, err := stream.Peek(2)
	if err != nil {
		return nil, err
	}
	if magic[0] == 0x1f && magic[1] == 0x8b {
		return nil, errPcapNestedGzip
	}
	return stream, nil
}

// pcapRecordsAllowed and pcapStreamBytesAllowed are the two caps, indirected
// so that a test can lower them, as auditNow indirects the clock.
//
// The indirection is what makes the bounds testable rather than merely
// asserted, and both halves of this row need it. A million records is about a
// second of reading per builtin, and the test that holds the record cap
// measures the difference between two reads five times over, which is twenty
// reads; the stream cap is 1.4 GiB and could not be reached in a test at all.
// Lowering a cap lets a test prove that the loop stops and that the flag is
// set, which is the property. A test that checked the wording of a refusal
// would prove neither.
var (
	pcapRecordsAllowed     = func() int64 { return maxPcapPackets }
	pcapStreamBytesAllowed = func() int64 { return maxPcapStreamBytes }
)

type netFlowSummary struct {
	src     string
	dst     string
	sport   int64
	dport   int64
	proto   string
	packets int64
	bytes   int64
}

func NetResolve(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	host, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `net_resolve` must be STRING, got %s", args[0].Type()))
	}
	addrs, err := net.LookupHost(host.Value)
	if err != nil {
		return resultAndError(nil, newError("net_resolve: %s", err.Error()))
	}
	elements := make([]object.Object, 0, len(addrs))
	for _, addr := range addrs {
		elements = append(elements, stringObj(addr))
	}
	return resultAndError(&object.Array{Elements: elements}, nil)
}

func NetDial(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	addr, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_dial` must be STRING, got %s", args[0].Type()))
	}
	timeoutMs, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_dial` must be INTEGER, got %s", args[1].Type()))
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr.Value, time.Duration(timeoutMs.Value)*time.Millisecond)
	elapsed := time.Since(start).Milliseconds()

	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	} else {
		conn.Close()
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"ok":         boolObj(err == nil),
		"latency_ms": intObj(elapsed),
		"error":      stringObj(errMsg),
	}), nil)
}

// NetConnectScan scans a TCP port range with full connect() probes (net.Dial).
// It is deliberately NOT a half-open SYN scan: real SYN scanning needs raw
// sockets and elevated privileges and is OS-restricted, which conflicts with the
// pure-Go, unprivileged design. The name is truthful; `net_syn_scan` remains as a
// deprecated alias for backward compatibility.
func NetConnectScan(args ...object.Object) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}

	host, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_connect_scan` must be STRING, got %s", args[0].Type()))
	}
	startPort, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_connect_scan` must be INTEGER, got %s", args[1].Type()))
	}
	endPort, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `net_connect_scan` must be INTEGER, got %s", args[2].Type()))
	}
	timeoutMs, ok := args[3].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 4 to `net_connect_scan` must be INTEGER, got %s", args[3].Type()))
	}
	if errObj := validatePortRange(BuiltinNameNetConnectScan, startPort.Value, endPort.Value); errObj != nil {
		return resultAndError(nil, errObj)
	}

	timeout := time.Duration(timeoutMs.Value) * time.Millisecond
	start := time.Now()
	openPorts := make([]object.Object, 0)
	for port := startPort.Value; port <= endPort.Value; port++ {
		addr := net.JoinHostPort(host.Value, strconv.FormatInt(port, 10))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			openPorts = append(openPorts, intObj(port))
			_ = conn.Close()
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"host":        stringObj(host.Value),
		"start_port":  intObj(startPort.Value),
		"end_port":    intObj(endPort.Value),
		"scanned":     intObj(endPort.Value - startPort.Value + 1),
		"open_ports":  &object.Array{Elements: openPorts},
		"duration_ms": intObj(time.Since(start).Milliseconds()),
	}), nil)
}

func NetUDPScan(args ...object.Object) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}

	host, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_udp_scan` must be STRING, got %s", args[0].Type()))
	}
	startPort, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_udp_scan` must be INTEGER, got %s", args[1].Type()))
	}
	endPort, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `net_udp_scan` must be INTEGER, got %s", args[2].Type()))
	}
	timeoutMs, ok := args[3].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 4 to `net_udp_scan` must be INTEGER, got %s", args[3].Type()))
	}
	if errObj := validatePortRange(BuiltinNameNetUdpScan, startPort.Value, endPort.Value); errObj != nil {
		return resultAndError(nil, errObj)
	}

	timeout := time.Duration(timeoutMs.Value) * time.Millisecond
	start := time.Now()
	responsive := make([]object.Object, 0)
	for port := startPort.Value; port <= endPort.Value; port++ {
		addr := net.JoinHostPort(host.Value, strconv.FormatInt(port, 10))
		conn, err := net.DialTimeout("udp", addr, timeout)
		if err != nil {
			continue
		}

		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, _ = conn.Write([]byte("mutant-probe"))
		buf := make([]byte, 64)
		n, readErr := conn.Read(buf)
		_ = conn.Close()
		if readErr == nil && n > 0 {
			responsive = append(responsive, intObj(port))
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"host":             stringObj(host.Value),
		"start_port":       intObj(startPort.Value),
		"end_port":         intObj(endPort.Value),
		"scanned":          intObj(endPort.Value - startPort.Value + 1),
		"responsive_ports": &object.Array{Elements: responsive},
		"duration_ms":      intObj(time.Since(start).Milliseconds()),
	}), nil)
}

func NetBanner(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	addr, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_banner` must be STRING, got %s", args[0].Type()))
	}
	timeoutMs, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_banner` must be INTEGER, got %s", args[1].Type()))
	}

	timeout := time.Duration(timeoutMs.Value) * time.Millisecond
	conn, err := net.DialTimeout("tcp", addr.Value, timeout)
	if err != nil {
		return resultAndError(makeHashObject(map[string]object.Object{
			"ok":     boolObj(false),
			"banner": stringObj(""),
			"error":  stringObj(err.Error()),
		}), nil)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	// One byte past the cap is read so that reaching it can be told apart from
	// the peer stopping on its own. io.LimitReader returns EOF at its bound and
	// io.ReadAll turns EOF into nil, so a read bounded at exactly
	// maxBannerBytes handed back the prefix of a longer stream with no error at
	// all -- indistinguishable from a complete greeting of that length
	// (M26-NET-026).
	banner, readErr := io.ReadAll(io.LimitReader(conn, maxBannerBytes+1))
	if len(banner) > maxBannerBytes {
		return resultAndError(makeHashObject(map[string]object.Object{
			"ok":     boolObj(false),
			"banner": stringObj(""),
			"error":  stringObj(fmt.Sprintf("the greeting exceeds %d bytes", maxBannerBytes)),
		}), nil)
	}

	// A read deadline is how a banner normally ends, not a failure. SSH, SMTP
	// and FTP each write their greeting and then wait for the client, so the
	// socket stays open and io.ReadAll reports the deadline instead of an EOF
	// -- with the greeting already in hand, because ReadAll returns what it
	// read alongside the error. Reporting that as ok:false with an empty
	// banner threw the answer away for exactly the services this builtin
	// exists to identify. What was read decides: any bytes are a banner, and
	// a read that ended with none is still a failure.
	if readErr != nil && len(banner) == 0 {
		return resultAndError(makeHashObject(map[string]object.Object{
			"ok":     boolObj(false),
			"banner": stringObj(""),
			"error":  stringObj(readErr.Error()),
		}), nil)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"ok":     boolObj(true),
		"banner": stringObj(string(banner)),
		"error":  stringObj(""),
	}), nil)
}

func NetTLSFingerprint(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	addr, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_tls_fingerprint` must be STRING, got %s", args[0].Type()))
	}
	timeoutMs, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_tls_fingerprint` must be INTEGER, got %s", args[1].Type()))
	}

	host, _, err := net.SplitHostPort(addr.Value)
	if err != nil {
		host = addr.Value
	}
	dialer := &net.Dialer{Timeout: time.Duration(timeoutMs.Value) * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr.Value, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return resultAndError(makeHashObject(map[string]object.Object{
			"ok":    boolObj(false),
			"error": stringObj(err.Error()),
		}), nil)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	sha := ""
	subject := ""
	issuer := ""
	notBefore := ""
	notAfter := ""
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		digest := sha256.Sum256(cert.Raw)
		sha = hex.EncodeToString(digest[:])
		subject = cert.Subject.String()
		issuer = cert.Issuer.String()
		notBefore = cert.NotBefore.UTC().Format(time.RFC3339)
		notAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	}

	alpn := ""
	if state.NegotiatedProtocol != "" {
		alpn = state.NegotiatedProtocol
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"ok":               boolObj(true),
		"version":          stringObj(tlsVersionToString(state.Version)),
		"cipher":           stringObj(tls.CipherSuiteName(state.CipherSuite)),
		"alpn":             stringObj(alpn),
		"peer_cert_sha256": stringObj(sha),
		"subject":          stringObj(subject),
		"issuer":           stringObj(issuer),
		"not_before":       stringObj(notBefore),
		"not_after":        stringObj(notAfter),
		"error":            stringObj(""),
	}), nil)
}

func NetDNSQuery(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	name, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_dns_query` must be STRING, got %s", args[0].Type()))
	}
	typeObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_dns_query` must be STRING, got %s", args[1].Type()))
	}

	qType := strings.ToUpper(strings.TrimSpace(typeObj.Value))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch qType {
	case "A", "AAAA", "IP":
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", name.Value)
		if err != nil {
			return resultAndError(nil, newError("net_dns_query: %s", err.Error()))
		}
		items := make([]object.Object, 0, len(ips))
		for _, ip := range ips {
			if qType == "A" && ip.To4() == nil {
				continue
			}
			if qType == "AAAA" && ip.To4() != nil {
				continue
			}
			items = append(items, stringObj(ip.String()))
		}
		return resultAndError(&object.Array{Elements: items}, nil)
	case "CNAME":
		cname, err := net.DefaultResolver.LookupCNAME(ctx, name.Value)
		if err != nil {
			return resultAndError(nil, newError("net_dns_query: %s", err.Error()))
		}
		return resultAndError(stringObj(cname), nil)
	case "MX":
		records, err := net.DefaultResolver.LookupMX(ctx, name.Value)
		if err != nil {
			return resultAndError(nil, newError("net_dns_query: %s", err.Error()))
		}
		items := make([]object.Object, 0, len(records))
		for _, rec := range records {
			items = append(items, makeHashObject(map[string]object.Object{
				"host": stringObj(rec.Host),
				"pref": intObj(int64(rec.Pref)),
			}))
		}
		return resultAndError(&object.Array{Elements: items}, nil)
	case "TXT":
		txts, err := net.DefaultResolver.LookupTXT(ctx, name.Value)
		if err != nil {
			return resultAndError(nil, newError("net_dns_query: %s", err.Error()))
		}
		items := make([]object.Object, 0, len(txts))
		for _, txt := range txts {
			items = append(items, stringObj(txt))
		}
		return resultAndError(&object.Array{Elements: items}, nil)
	case "NS":
		nsRecords, err := net.DefaultResolver.LookupNS(ctx, name.Value)
		if err != nil {
			return resultAndError(nil, newError("net_dns_query: %s", err.Error()))
		}
		items := make([]object.Object, 0, len(nsRecords))
		for _, rec := range nsRecords {
			items = append(items, stringObj(rec.Host))
		}
		return resultAndError(&object.Array{Elements: items}, nil)
	case "PTR":
		ptrRecords, err := net.DefaultResolver.LookupAddr(ctx, name.Value)
		if err != nil {
			return resultAndError(nil, newError("net_dns_query: %s", err.Error()))
		}
		items := make([]object.Object, 0, len(ptrRecords))
		for _, rec := range ptrRecords {
			items = append(items, stringObj(rec))
		}
		return resultAndError(&object.Array{Elements: items}, nil)
	default:
		return resultAndError(nil, newError("argument 2 to `net_dns_query` must be one of A, AAAA, IP, CNAME, MX, TXT, NS, PTR; got %q", typeObj.Value))
	}
}

// NetCaptureRaw reads raw packets from an offline pcap file and returns a
// per-packet listing. (Live capture needs cgo/privileged raw sockets, which are
// off the table; this is the honest offline counterpart — net_pcap_analyze gives
// the flow summary, this gives the packets.) Capped at 1,000,000 packets, and
// a compressed capture at maxPcapStreamBytes of decompressed stream; past
// either, the result says truncated.
func NetCaptureRaw(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_capture_raw` must be STRING, got %s", args[0].Type()))
	}

	file, err := os.Open(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("net_capture_raw: %s", err.Error()))
	}
	defer file.Close()

	stream, err := pcapRecordStream(file)
	if err != nil {
		return resultAndError(nil, newError("net_capture_raw: %s", err.Error()))
	}
	reader, err := pcapgo.NewReader(stream)
	if err != nil {
		return resultAndError(nil, newError("net_capture_raw: %s", err.Error()))
	}
	capPcapSnaplen(reader, file)
	linkType := reader.LinkType()
	recordsAllowed := pcapRecordsAllowed()
	packets := make([]object.Object, 0)
	truncated := false
	index := int64(0)
	for {
		data, ci, readErr := reader.ReadPacketData()
		if readErr == io.EOF {
			break
		}
		// The stream cap is a short answer and not a failure, so it ends the
		// read with truncated set rather than throwing away the packets already
		// in hand. Compared with == and not errors.Is: the cap returns the
		// sentinel unwrapped, and this package's macro-purity guard forbids
		// errors.Is from an allowlisted builtin.
		if readErr == errPcapStreamFull {
			truncated = true
			break
		}
		if readErr != nil {
			return resultAndError(nil, newError("net_capture_raw: %s", readErr.Error()))
		}
		if int64(len(packets)) >= recordsAllowed {
			truncated = true
			break
		}

		src, dst, proto, sport, dport := pcapPacketFields(gopacket.NewPacket(data, linkType, gopacket.NoCopy))
		ts := int64(0)
		iso := ""
		if !ci.Timestamp.IsZero() {
			ts = ci.Timestamp.Unix()
			iso = ci.Timestamp.UTC().Format(time.RFC3339Nano)
		}
		packets = append(packets, makeHashObject(map[string]object.Object{
			"index":     intObj(index),
			"ts":        intObj(ts),
			"timestamp": stringObj(iso),
			"length":    intObj(int64(len(data))),
			"src":       stringObj(src),
			"dst":       stringObj(dst),
			"protocol":  stringObj(proto),
			"sport":     intObj(sport),
			"dport":     intObj(dport),
		}))
		index++
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"file":      stringObj(pathObj.Value),
		"link_type": stringObj(linkType.String()),
		"count":     intObj(int64(len(packets))),
		"truncated": boolObj(truncated),
		"packets":   &object.Array{Elements: packets},
	}), nil)
}

// pcapPacketFields extracts the L3/L4 addressing from a decoded packet.
func pcapPacketFields(packet gopacket.Packet) (src, dst, proto string, sport, dport int64) {
	proto = "OTHER"
	if l := packet.Layer(layers.LayerTypeIPv4); l != nil {
		if ip, ok := l.(*layers.IPv4); ok {
			src, dst = ip.SrcIP.String(), ip.DstIP.String()
		}
	} else if l := packet.Layer(layers.LayerTypeIPv6); l != nil {
		if ip, ok := l.(*layers.IPv6); ok {
			src, dst = ip.SrcIP.String(), ip.DstIP.String()
		}
	}
	if l := packet.Layer(layers.LayerTypeTCP); l != nil {
		proto = "TCP"
		if t, ok := l.(*layers.TCP); ok {
			sport, dport = int64(t.SrcPort), int64(t.DstPort)
		}
	} else if l := packet.Layer(layers.LayerTypeUDP); l != nil {
		proto = "UDP"
		if u, ok := l.(*layers.UDP); ok {
			sport, dport = int64(u.SrcPort), int64(u.DstPort)
		}
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
		proto = "ICMP"
	}
	return
}

// NetPCAPAnalyze summarises an offline capture: the per-protocol counts, the
// time span, and one row per flow.
//
// It reads at most maxPcapPackets records, and at most maxPcapStreamBytes out
// of a compressed capture, because the file holds one map entry's worth of
// cost per record and a gzipped capture's size on disk bounds neither. A read
// that stopped at either bound returns truncated, and then every count here
// and every flow row covers only the records that were read.
func NetPCAPAnalyze(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_pcap_analyze` must be STRING, got %s", args[0].Type()))
	}

	file, err := os.Open(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("net_pcap_analyze: %s", err.Error()))
	}
	defer file.Close()

	stream, err := pcapRecordStream(file)
	if err != nil {
		return resultAndError(nil, newError("net_pcap_analyze: %s", err.Error()))
	}
	reader, err := pcapgo.NewReader(stream)
	if err != nil {
		return resultAndError(nil, newError("net_pcap_analyze: %s", err.Error()))
	}
	capPcapSnaplen(reader, file)

	linkType := reader.LinkType()
	flows := map[string]*netFlowSummary{}

	packetCount := int64(0)
	bytesTotal := int64(0)
	ipv4Count := int64(0)
	ipv6Count := int64(0)
	tcpCount := int64(0)
	udpCount := int64(0)
	icmpCount := int64(0)
	otherCount := int64(0)

	firstTs := time.Time{}
	lastTs := time.Time{}

	recordsAllowed := pcapRecordsAllowed()
	truncated := false

	for {
		data, ci, readErr := reader.ReadPacketData()
		if readErr == io.EOF {
			break
		}
		// A capped read is a partial summary and not a failure, so it ends the
		// loop with truncated set. == and not errors.Is, as in net_capture_raw.
		if readErr == errPcapStreamFull {
			truncated = true
			break
		}
		if readErr != nil {
			return resultAndError(nil, newError("net_pcap_analyze: %s", readErr.Error()))
		}
		// One map entry per flow and one hash per entry, so the length of this
		// loop is what the flow map costs: the record cap is the map cap. It is
		// checked before the record is accounted for, so packet_count never
		// reports more records than were read.
		if packetCount >= recordsAllowed {
			truncated = true
			break
		}

		packetCount++
		bytesTotal += int64(len(data))

		if firstTs.IsZero() || ci.Timestamp.Before(firstTs) {
			firstTs = ci.Timestamp
		}
		if lastTs.IsZero() || ci.Timestamp.After(lastTs) {
			lastTs = ci.Timestamp
		}

		packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)

		src := ""
		dst := ""
		sport := int64(0)
		dport := int64(0)
		proto := "OTHER"

		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ipv4Count++
			if ip4, ok := ip4Layer.(*layers.IPv4); ok {
				src = ip4.SrcIP.String()
				dst = ip4.DstIP.String()
			}
		} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ipv6Count++
			if ip6, ok := ip6Layer.(*layers.IPv6); ok {
				src = ip6.SrcIP.String()
				dst = ip6.DstIP.String()
			}
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcpCount++
			proto = "TCP"
			if tcp, ok := tcpLayer.(*layers.TCP); ok {
				sport = int64(tcp.SrcPort)
				dport = int64(tcp.DstPort)
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udpCount++
			proto = "UDP"
			if udp, ok := udpLayer.(*layers.UDP); ok {
				sport = int64(udp.SrcPort)
				dport = int64(udp.DstPort)
			}
		} else if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
			icmpCount++
			proto = "ICMP"
		} else {
			otherCount++
		}

		if src != "" && dst != "" {
			k1 := fmt.Sprintf("%s|%s|%d|%s|%d", proto, src, sport, dst, dport)
			k2 := fmt.Sprintf("%s|%s|%d|%s|%d", proto, dst, dport, src, sport)
			key := k1
			if _, ok := flows[key]; !ok {
				if _, ok := flows[k2]; ok {
					key = k2
				}
			}

			summary, ok := flows[key]
			if !ok {
				summary = &netFlowSummary{src: src, dst: dst, sport: sport, dport: dport, proto: proto}
				flows[key] = summary
			}
			summary.packets++
			summary.bytes += int64(len(data))
		}
	}

	flowKeys := make([]string, 0, len(flows))
	for k := range flows {
		flowKeys = append(flowKeys, k)
	}
	sort.Strings(flowKeys)

	flowObjects := make([]object.Object, 0, len(flowKeys))
	for _, key := range flowKeys {
		summary := flows[key]
		flowObjects = append(flowObjects, makeHashObject(map[string]object.Object{
			"src":     stringObj(summary.src),
			"dst":     stringObj(summary.dst),
			"sport":   intObj(summary.sport),
			"dport":   intObj(summary.dport),
			"proto":   stringObj(summary.proto),
			"packets": intObj(summary.packets),
			"bytes":   intObj(summary.bytes),
		}))
	}

	durationMs := int64(0)
	if !firstTs.IsZero() && !lastTs.IsZero() && lastTs.After(firstTs) {
		durationMs = lastTs.Sub(firstTs).Milliseconds()
	}

	firstTS := ""
	if !firstTs.IsZero() {
		firstTS = firstTs.UTC().Format(time.RFC3339Nano)
	}
	lastTS := ""
	if !lastTs.IsZero() {
		lastTS = lastTs.UTC().Format(time.RFC3339Nano)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"file":          stringObj(pathObj.Value),
		"link_type":     stringObj(linkType.String()),
		"packet_count":  intObj(packetCount),
		"truncated":     boolObj(truncated),
		"bytes_total":   intObj(bytesTotal),
		"ipv4_packets":  intObj(ipv4Count),
		"ipv6_packets":  intObj(ipv6Count),
		"tcp_packets":   intObj(tcpCount),
		"udp_packets":   intObj(udpCount),
		"icmp_packets":  intObj(icmpCount),
		"other_packets": intObj(otherCount),
		"first_ts":      stringObj(firstTS),
		"last_ts":       stringObj(lastTS),
		"duration_ms":   intObj(durationMs),
		"flows":         &object.Array{Elements: flowObjects},
	}), nil)
}

func NetFlowReconstruct(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	packetsObj, ok := args[0].(*object.Array)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_flow_reconstruct` must be ARRAY, got %s", args[0].Type()))
	}

	flows := map[string]*netFlowSummary{}
	for idx, packetObj := range packetsObj.Elements {
		packet, ok := packetObj.(*object.Hash)
		if !ok {
			return resultAndError(nil, newError("packet at index %d must be HASH", idx))
		}

		src, err := hashStringField(packet, "src")
		if err != nil {
			return resultAndError(nil, newError("packet at index %d: %s", idx, err.Error()))
		}
		dst, err := hashStringField(packet, "dst")
		if err != nil {
			return resultAndError(nil, newError("packet at index %d: %s", idx, err.Error()))
		}
		sport, err := hashIntField(packet, "sport")
		if err != nil {
			return resultAndError(nil, newError("packet at index %d: %s", idx, err.Error()))
		}
		dport, err := hashIntField(packet, "dport")
		if err != nil {
			return resultAndError(nil, newError("packet at index %d: %s", idx, err.Error()))
		}
		proto, err := hashStringField(packet, "proto")
		if err != nil {
			return resultAndError(nil, newError("packet at index %d: %s", idx, err.Error()))
		}
		pktBytes, err := hashIntField(packet, "bytes")
		if err != nil {
			return resultAndError(nil, newError("packet at index %d: %s", idx, err.Error()))
		}

		k1 := fmt.Sprintf("%s|%s|%d|%s|%d", strings.ToUpper(proto), src, sport, dst, dport)
		k2 := fmt.Sprintf("%s|%s|%d|%s|%d", strings.ToUpper(proto), dst, dport, src, sport)
		key := k1
		if _, ok := flows[key]; !ok {
			if _, ok := flows[k2]; ok {
				key = k2
			}
		}

		summary, ok := flows[key]
		if !ok {
			summary = &netFlowSummary{src: src, dst: dst, sport: sport, dport: dport, proto: strings.ToUpper(proto)}
			flows[key] = summary
		}
		summary.packets++
		summary.bytes += pktBytes
	}

	keys := make([]string, 0, len(flows))
	for k := range flows {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	results := make([]object.Object, 0, len(keys))
	for _, key := range keys {
		summary := flows[key]
		results = append(results, makeHashObject(map[string]object.Object{
			"src":     stringObj(summary.src),
			"dst":     stringObj(summary.dst),
			"sport":   intObj(summary.sport),
			"dport":   intObj(summary.dport),
			"proto":   stringObj(summary.proto),
			"packets": intObj(summary.packets),
			"bytes":   intObj(summary.bytes),
		}))
	}

	return resultAndError(&object.Array{Elements: results}, nil)
}

// osFingerprint holds the passive TCP/IP fingerprint derived from a single SYN
// (or SYN-ACK) packet, in the spirit of p0f.
type osFingerprint struct {
	ip          string
	ipVersion   int
	packetType  string // "SYN" or "SYN-ACK"
	observedTTL int
	initialTTL  int
	hops        int
	window      int
	df          bool
	mss         int
	windowScale int // -1 when the option is absent
	sackPerm    bool
	timestamps  bool
	optLayout   string
	osGuess     string
	confidence  string
}

func (fp *osFingerprint) signature() string {
	df := 0
	if fp.df {
		df = 1
	}
	// initialTTL:hops:DF:window:mss:option-layout — a compact, p0f-like signature.
	return fmt.Sprintf("%d:%d:%d:%d:%d:%s", fp.initialTTL, fp.hops, df, fp.window, fp.mss, fp.optLayout)
}

// NetOSFingerprint performs passive OS fingerprinting from an offline pcap file.
// It inspects TCP SYN / SYN-ACK packets and derives an OS family guess from the
// IP TTL, the DF bit, the TCP window, and the TCP option layout. This is a
// heuristic (like p0f) — it identifies an OS *family*, not a definitive OS — and
// runs entirely offline in pure Go, so it needs no privileges or capture backend.
//
// It reads at most maxPcapPackets records, and at most maxPcapStreamBytes out
// of a compressed capture: every record costs a decoded packet whether it
// carries a SYN or not, and one fingerprint is kept per host and packet type.
// A read that stopped at either bound returns truncated, and then the hosts
// listed are only those seen in the records that were read.
func NetOSFingerprint(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_os_fingerprint` must be STRING pcap path, got %s", args[0].Type()))
	}

	file, err := os.Open(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("net_os_fingerprint: %s", err.Error()))
	}
	defer file.Close()

	stream, err := pcapRecordStream(file)
	if err != nil {
		return resultAndError(nil, newError("net_os_fingerprint: %s", err.Error()))
	}
	reader, err := pcapgo.NewReader(stream)
	if err != nil {
		return resultAndError(nil, newError("net_os_fingerprint: %s", err.Error()))
	}
	capPcapSnaplen(reader, file)
	linkType := reader.LinkType()

	prints := map[string]*osFingerprint{}
	keys := make([]string, 0)
	synCount := int64(0)
	records := int64(0)
	recordsAllowed := pcapRecordsAllowed()
	truncated := false

	for {
		data, _, readErr := reader.ReadPacketData()
		if readErr == io.EOF {
			break
		}
		// As in the two readers above: the cap ends the read with truncated
		// set, and the sentinel is compared with ==.
		if readErr == errPcapStreamFull {
			truncated = true
			break
		}
		if readErr != nil {
			return resultAndError(nil, newError("net_os_fingerprint: %s", readErr.Error()))
		}
		// Counted per record and not per SYN. A record that carries no SYN is
		// skipped a few lines below, but it has already cost a decoded packet,
		// and the record is the thing a file can hold an unbounded number of.
		if records >= recordsAllowed {
			truncated = true
			break
		}
		records++

		packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok || !tcp.SYN {
			continue
		}

		var srcIP string
		var observedTTL, ipVersion int
		df := false
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ip4 := ip4Layer.(*layers.IPv4)
			srcIP = ip4.SrcIP.String()
			observedTTL = int(ip4.TTL)
			df = ip4.Flags&layers.IPv4DontFragment != 0
			ipVersion = 4
		} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ip6 := ip6Layer.(*layers.IPv6)
			srcIP = ip6.SrcIP.String()
			observedTTL = int(ip6.HopLimit)
			ipVersion = 6
		} else {
			continue
		}

		packetType := "SYN"
		if tcp.ACK {
			packetType = "SYN-ACK"
		}

		synCount++
		key := srcIP + "/" + packetType
		if _, exists := prints[key]; exists {
			continue // first packet per host+type wins, keeping output deterministic
		}

		mss, wscale, sackPerm, timestamps, layout := parseTCPOptionLayout(tcp.Options)
		initialTTL := guessInitialTTL(observedTTL)
		osGuess, confidence := guessOSFamily(initialTTL, wscale, sackPerm, timestamps)

		fp := &osFingerprint{
			ip:          srcIP,
			ipVersion:   ipVersion,
			packetType:  packetType,
			observedTTL: observedTTL,
			initialTTL:  initialTTL,
			hops:        initialTTL - observedTTL,
			window:      int(tcp.Window),
			df:          df,
			mss:         mss,
			windowScale: wscale,
			sackPerm:    sackPerm,
			timestamps:  timestamps,
			optLayout:   layout,
			osGuess:     osGuess,
			confidence:  confidence,
		}
		prints[key] = fp
		keys = append(keys, key)
	}

	sort.Strings(keys)
	hosts := make([]object.Object, 0, len(keys))
	for _, key := range keys {
		fp := prints[key]
		hosts = append(hosts, makeHashObject(map[string]object.Object{
			"ip":             stringObj(fp.ip),
			"ip_version":     intObj(int64(fp.ipVersion)),
			"packet_type":    stringObj(fp.packetType),
			"os_guess":       stringObj(fp.osGuess),
			"confidence":     stringObj(fp.confidence),
			"observed_ttl":   intObj(int64(fp.observedTTL)),
			"initial_ttl":    intObj(int64(fp.initialTTL)),
			"hops":           intObj(int64(fp.hops)),
			"window":         intObj(int64(fp.window)),
			"df":             boolObj(fp.df),
			"mss":            intObj(int64(fp.mss)),
			"window_scale":   intObj(int64(fp.windowScale)),
			"sack_permitted": boolObj(fp.sackPerm),
			"timestamps":     boolObj(fp.timestamps),
			"tcp_options":    stringObj(fp.optLayout),
			"signature":      stringObj(fp.signature()),
		}))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"file":        stringObj(pathObj.Value),
		"link_type":   stringObj(linkType.String()),
		"syn_packets": intObj(synCount),
		"truncated":   boolObj(truncated),
		"hosts":       &object.Array{Elements: hosts},
	}), nil)
}

// parseTCPOptionLayout extracts the MSS, window scale (-1 if absent), SACK-permitted
// and timestamp flags, plus a compact option-order layout string (e.g. "M,N,W,N,N,S").
func parseTCPOptionLayout(opts []layers.TCPOption) (mss int, wscale int, sackPerm bool, timestamps bool, layout string) {
	wscale = -1
	parts := make([]string, 0, len(opts))
	for _, opt := range opts {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) >= 2 {
				mss = int(binary.BigEndian.Uint16(opt.OptionData))
			}
			parts = append(parts, "M")
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) >= 1 {
				wscale = int(opt.OptionData[0])
			}
			parts = append(parts, "W")
		case layers.TCPOptionKindSACKPermitted:
			sackPerm = true
			parts = append(parts, "S")
		case layers.TCPOptionKindTimestamps:
			timestamps = true
			parts = append(parts, "T")
		case layers.TCPOptionKindNop:
			parts = append(parts, "N")
		case layers.TCPOptionKindEndList:
			parts = append(parts, "E")
		default:
			parts = append(parts, "?")
		}
	}
	return mss, wscale, sackPerm, timestamps, strings.Join(parts, ",")
}

// guessInitialTTL rounds an observed TTL up to the nearest common initial TTL
// ({32, 64, 128, 255}). The difference is the estimated hop count.
func guessInitialTTL(observed int) int {
	switch {
	case observed <= 0:
		return 0
	case observed <= 32:
		return 32
	case observed <= 64:
		return 64
	case observed <= 128:
		return 128
	default:
		return 255
	}
}

// guessOSFamily maps an initial TTL plus TCP option signals to an OS family. It
// is deliberately conservative: TTL is the strongest passive signal, and the
// option presence only adjusts confidence, never fabricates a specific version.
func guessOSFamily(initialTTL, wscale int, sackPerm, timestamps bool) (string, string) {
	switch initialTTL {
	case 32, 128:
		confidence := "medium"
		if wscale >= 0 && sackPerm {
			confidence = "high"
		}
		return "Windows", confidence
	case 64:
		confidence := "medium"
		if timestamps && sackPerm && wscale >= 0 {
			confidence = "high"
		}
		return "Linux/Unix (incl. macOS, Android, BSD)", confidence
	case 255:
		return "Network device / Solaris / legacy Unix", "low"
	default:
		return "unknown", "low"
	}
}

func validatePortRange(opName string, startPort int64, endPort int64) *object.Error {
	if startPort < 1 || startPort > 65535 {
		return newError("argument 2 to `%s` must be a valid port in range 1-65535, got %d", opName, startPort)
	}
	if endPort < 1 || endPort > 65535 {
		return newError("argument 3 to `%s` must be a valid port in range 1-65535, got %d", opName, endPort)
	}
	if startPort > endPort {
		return newError("`%s` requires start_port <= end_port", opName)
	}
	return nil
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return "unknown"
	}
}

func hashStringField(hash *object.Hash, key string) (string, error) {
	value, ok := hashValueByStringKey(hash, key)
	if !ok {
		return "", fmt.Errorf("missing key %q", key)
	}
	str, ok := value.(*object.String)
	if !ok {
		return "", fmt.Errorf("key %q must be STRING", key)
	}
	return str.Value, nil
}

func hashIntField(hash *object.Hash, key string) (int64, error) {
	value, ok := hashValueByStringKey(hash, key)
	if !ok {
		return 0, fmt.Errorf("missing key %q", key)
	}
	intValue, ok := value.(*object.Integer)
	if !ok {
		return 0, fmt.Errorf("key %q must be INTEGER", key)
	}
	return intValue.Value, nil
}
