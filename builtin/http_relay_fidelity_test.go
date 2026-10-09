package builtin

// Three defects, one subject: a message was not relayed as it arrived, or not
// sent as it was asked for.
//
//   - M26-NET-017 ws_read_frame dropped the RSV bits and ws_write_frame forced
//     FIN on, so the documented use of the pair -- read one frame, rewrite it,
//     write it to the other side -- could not reproduce the frame it had just
//     read. A permessage-deflate frame, which is what Chrome and Firefox
//     negotiate by default, went out flagged uncompressed; the first fragment
//     of a message went out as a whole message.
//   - M26-NET-023 a caller's Host header never reached the server, because
//     net/http's client sends req.Host and ignores the header field.
//   - M26-NET-039 neither response reader could read the answer to a HEAD
//     request, because only the request's method says that a Content-Length
//     there describes a representation rather than a body that follows.
//
// And three found while measuring those: an opcode outside the four bits a
// frame has for it was masked into a different kind of frame, a control frame
// RFC 6455 forbids was written anyway, and a Content-Length or a
// Transfer-Encoding a caller put in http_request's headers was silently
// replaced by net/http's own framing.
//
// Every expectation here is a literal, a count the test does itself, or what
// the far end of a real connection observed. None is read from the code under
// test: the frame bytes are written out byte by byte, the header values are
// literals, and the lengths come from Go's own len.

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mutant/object"
)

// ------------------------------------------------------------------ the frames

// wsFrameIn puts one frame on an in-memory connection and reads it with
// ws_read_frame. net.Pipe rather than a listener: registerConn takes any
// net.Conn, the pipe honours a deadline, and nothing can flake on a port.
func wsFrameIn(t *testing.T, frame []byte) *object.Hash {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		_, _ = server.Write(frame)
	}()
	return fidelityHash(t, WSReadFrame(intObj(registerConn(client, false)), intObj(2000)))
}

// wsFrameOut writes one frame with ws_write_frame and returns the bytes that
// reached the peer, or the refusal message if it refused.
//
// It waits for exactly want bytes, so a frame that is wrong in its first byte
// cannot pass by arriving as a short prefix of a right one.
func wsFrameOut(t *testing.T, want int, args ...object.Object) ([]byte, string) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, want)
		n, _ := io.ReadFull(server, buf)
		got <- buf[:n]
	}()

	call := append([]object.Object{intObj(registerConn(client, false))}, args...)
	if _, errObj := unwrapPairNoFatal(WSWriteFrame(call...)); errObj != nil {
		return nil, errObj.Message
	}
	select {
	case wire := <-got:
		return wire, ""
	case <-time.After(5 * time.Second):
		t.Fatal("ws_write_frame reported success and nothing reached the peer")
		return nil, ""
	}
}

// relayFrame is the whole point of the pair: read a frame, hand the hash back.
func relayFrame(t *testing.T, want int, read *object.Hash, payload object.Object) ([]byte, string) {
	t.Helper()
	return wsFrameOut(t, want, hashValueByKey(read, "opcode"), payload, boolObj(false), read)
}

// TestAFrameIsRelayedWithItsOwnHeaderByte is the row's regression test. The
// expectation is the byte that was put on the wire, which the test wrote
// itself; nothing is read out of the implementation.
func TestAFrameIsRelayedWithItsOwnHeaderByte(t *testing.T) {
	for _, first := range []byte{
		0x81, // FIN, text: the ordinary case
		0xC1, // FIN + RSV1, text: permessage-deflate (RFC 7692)
		0x01, // FIN clear, text: the first fragment of a message
		0x80, // FIN, continuation: the last fragment
		0xB1, // FIN + RSV2 + RSV3
		0xF2, // FIN and all three RSV bits, binary
	} {
		read := wsFrameIn(t, []byte{first, 0x02, 'h', 'i'})
		wire, refusal := relayFrame(t, 4, read, hashValueByKey(read, "payload"))
		if refusal != "" {
			t.Fatalf("relaying 0x%02X was refused: %s", first, refusal)
		}
		if wire[0] != first {
			t.Errorf("0x%02X was relayed as 0x%02X", first, wire[0])
		}
	}
}

// TestTheBitsAreReportedOneByOne. The relay above would also pass if read and
// write happened to agree on something wrong, so the four bits are checked
// against the byte they came from, one at a time.
func TestTheBitsAreReportedOneByOne(t *testing.T) {
	cases := []struct {
		first                 byte
		fin, rsv1, rsv2, rsv3 bool
	}{
		{0x81, true, false, false, false},
		{0x01, false, false, false, false},
		{0xC1, true, true, false, false},
		{0xA1, true, false, true, false},
		{0x91, true, false, false, true},
		{0x71, false, true, true, true},
	}
	for _, c := range cases {
		read := wsFrameIn(t, []byte{c.first, 0x00})
		for _, bit := range []struct {
			key  string
			want bool
		}{
			{"fin", c.fin}, {"rsv1", c.rsv1}, {"rsv2", c.rsv2}, {"rsv3", c.rsv3},
		} {
			got, ok := hashValueByKey(read, bit.key).(*object.Boolean)
			if !ok {
				t.Fatalf("0x%02X: %s is not a BOOLEAN", c.first, bit.key)
			}
			if got.Value != bit.want {
				t.Errorf("0x%02X: %s read as %v, want %v", c.first, bit.key, got.Value, bit.want)
			}
		}
	}
}

// TestARewrittenPayloadKeepsTheFramesBits. Rewriting the payload is the other
// half of the documented use, and the header bits must survive it.
func TestARewrittenPayloadKeepsTheFramesBits(t *testing.T) {
	read := wsFrameIn(t, []byte{0xC1, 0x02, 'h', 'i'})
	wire, refusal := relayFrame(t, 5, read, stringObj("HI!"))
	if refusal != "" {
		t.Fatalf("refused: %s", refusal)
	}
	if wire[0] != 0xC1 {
		t.Errorf("first byte 0x%02X, want 0xC1", wire[0])
	}
	if wire[1] != 0x03 {
		t.Errorf("second byte 0x%02X, want 0x03 (unmasked, three bytes)", wire[1])
	}
	if got := string(wire[2:]); got != "HI!" {
		t.Errorf("payload %q, want %q", got, "HI!")
	}
}

// TestMaskingIsNotTakenFromTheFrame. A client masks and a server must not (RFC
// 6455 section 5.3), so masking belongs to the direction a frame is written in
// and not to the frame that was read. The flags hash carries a masked field --
// it is the hash ws_read_frame returned -- and it must be ignored.
func TestMaskingIsNotTakenFromTheFrame(t *testing.T) {
	// A masked client frame: FIN+text, mask bit set, length 2, key, payload.
	key := []byte{0x0A, 0x0B, 0x0C, 0x0D}
	frame := []byte{0x81, 0x82, key[0], key[1], key[2], key[3], 'h' ^ key[0], 'i' ^ key[1]}
	read := wsFrameIn(t, frame)

	if got := hStr(t, read, "payload"); got != "hi" {
		t.Fatalf("a masked frame unmasked to %q, want %q", got, "hi")
	}
	masked, ok := hashValueByKey(read, "masked").(*object.Boolean)
	if !ok || !masked.Value {
		t.Fatalf("a masked frame was not reported as masked")
	}

	wire, refusal := relayFrame(t, 4, read, hashValueByKey(read, "payload"))
	if refusal != "" {
		t.Fatalf("refused: %s", refusal)
	}
	if wire[1]&0x80 != 0 {
		t.Errorf("the frame went out masked although mask=false was passed: % x", wire)
	}
	if got := string(wire[2:]); got != "hi" {
		t.Errorf("payload on the wire %q, want %q", got, "hi")
	}
}

// TestAFrameWithNoFlagsIsFinAndUnflagged. Every call written before the flags
// existed passes four or five arguments, and must get exactly what it got
// before: FIN set, no RSV bit.
func TestAFrameWithNoFlagsIsFinAndUnflagged(t *testing.T) {
	for _, args := range [][]object.Object{
		{intObj(0x1), stringObj("hi"), boolObj(false)},
		{intObj(0x1), stringObj("hi"), boolObj(false), intObj(2000)},
	} {
		wire, refusal := wsFrameOut(t, 4, args...)
		if refusal != "" {
			t.Fatalf("refused: %s", refusal)
		}
		if wire[0] != 0x81 {
			t.Errorf("first byte 0x%02X, want 0x81 (FIN, text, no RSV)", wire[0])
		}
	}
}

// TestTheDeadlineTravelsEitherWay. The fifth argument used to be the write
// deadline alone, and it still is; it can also arrive inside the flags, so that
// naming a bit does not cost the default timeout. Both are measured against a
// peer that never reads, where a deadline is the only thing that ends the call.
func TestTheDeadlineTravelsEitherWay(t *testing.T) {
	for _, fifth := range []object.Object{
		intObj(50),
		makeHashObject(map[string]object.Object{"timeout_ms": intObj(50)}),
		makeHashObject(map[string]object.Object{"rsv1": boolObj(true), "timeout_ms": intObj(50)}),
	} {
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		h := registerConn(client, false)
		_, errObj := unwrapPairNoFatal(WSWriteFrame(
			intObj(h), intObj(0x1), stringObj("blocked-forever"), boolObj(false), fifth))
		if errObj == nil {
			t.Errorf("a write to an unread peer with %s succeeded", fifth.Inspect())
		}
	}
}

// TestAMistypedFlagIsRefused. A flag that is present and of the wrong type is
// refused rather than ignored: "fin": 0 silently meaning fin true is the same
// class of defect as the dropped bits the flags exist to fix.
func TestAMistypedFlagIsRefused(t *testing.T) {
	cases := []struct {
		what  string
		fifth object.Object
	}{
		{"fin as an integer", makeHashObject(map[string]object.Object{"fin": intObj(0)})},
		{"rsv1 as a string", makeHashObject(map[string]object.Object{"rsv1": stringObj("yes")})},
		{"timeout_ms as a string", makeHashObject(map[string]object.Object{"timeout_ms": stringObj("soon")})},
		{"the whole argument a string", stringObj("flags")},
	}
	for _, c := range cases {
		_, refusal := wsFrameOut(t, 4, intObj(0x1), stringObj("hi"), boolObj(false), c.fifth)
		if refusal == "" {
			t.Errorf("%s was accepted", c.what)
		}
	}
}

// TestAnOpcodeOutsideFourBitsIsRefused. The opcode field is four bits (RFC 6455
// section 5.2) and the builtin used to mask with 0x0f, so 16 went out as opcode
// 0 -- a continuation frame, which is a different kind of frame than the caller
// named, and one that a peer with no message open fails the connection over.
func TestAnOpcodeOutsideFourBitsIsRefused(t *testing.T) {
	for _, opcode := range []int64{16, 17, 31, 255, -1} {
		_, refusal := wsFrameOut(t, 4, intObj(opcode), stringObj("hi"), boolObj(false))
		if refusal == "" {
			t.Errorf("opcode %d was accepted", opcode)
			continue
		}
		if !strings.Contains(refusal, fmt.Sprintf("%d", opcode)) {
			t.Errorf("the refusal for opcode %d does not name it: %s", opcode, refusal)
		}
	}

	// Every opcode a frame can carry is still written, reserved ones included:
	// this is an inspection tool, and a reserved opcode on the wire is a thing
	// an examiner may need to reproduce.
	for opcode := int64(0); opcode <= 15; opcode++ {
		wire, refusal := wsFrameOut(t, 4, intObj(opcode), stringObj("hi"), boolObj(false))
		if refusal != "" {
			t.Errorf("opcode %d was refused: %s", opcode, refusal)
			continue
		}
		if wire[0] != byte(0x80|opcode) {
			t.Errorf("opcode %d went out as first byte 0x%02X", opcode, wire[0])
		}
	}
}

// TestAnOversizedControlFrameIsRefused. RFC 6455 section 5.5: a control frame
// carries at most 125 bytes and a peer fails the connection on a longer one, so
// a close frame with a 200-byte reason was a dropped connection and not a close
// anybody read. Both sides of the boundary, because a cap tested from one side
// is a cap that could be off by any amount.
func TestAnOversizedControlFrameIsRefused(t *testing.T) {
	for _, opcode := range []int64{0x8, 0x9, 0xA} {
		wire, refusal := wsFrameOut(t, 127, intObj(opcode), stringObj(strings.Repeat("x", 125)), boolObj(false))
		if refusal != "" {
			t.Errorf("a %d-byte control frame (opcode %d) was refused: %s", 125, opcode, refusal)
		} else if len(wire) != 127 {
			t.Errorf("a 125-byte control frame went out as %d bytes", len(wire))
		}

		if _, refusal := wsFrameOut(t, 128, intObj(opcode), stringObj(strings.Repeat("x", 126)), boolObj(false)); refusal == "" {
			t.Errorf("a 126-byte control frame (opcode %d) was accepted", opcode)
		}
	}

	// A data frame of that size is not a control frame and is written. 4100 is
	// the whole frame: a four-byte header, because a length of 4096 needs the
	// 16-bit extension, and the payload. Waiting for all of it keeps the pipe
	// from blocking the write half-way.
	if _, refusal := wsFrameOut(t, 4100, intObj(0x2), stringObj(strings.Repeat("x", 4096)), boolObj(false)); refusal != "" {
		t.Errorf("a 4 KiB binary frame was refused: %s", refusal)
	}
}

// TestAFragmentedControlFrameIsRefused. The other half of RFC 6455 section
// 5.5: a control frame cannot be fragmented. It only became possible to ask for
// one when fin became settable, so the refusal arrives with the feature.
func TestAFragmentedControlFrameIsRefused(t *testing.T) {
	notFin := makeHashObject(map[string]object.Object{"fin": boolObj(false)})

	if _, refusal := wsFrameOut(t, 4, intObj(0x9), stringObj("hi"), boolObj(false), notFin); refusal == "" {
		t.Errorf("a fragmented ping was accepted")
	}

	// A data frame with fin false is exactly what the row was about.
	wire, refusal := wsFrameOut(t, 4, intObj(0x1), stringObj("hi"), boolObj(false), notFin)
	if refusal != "" {
		t.Fatalf("a first fragment was refused: %s", refusal)
	}
	if wire[0] != 0x01 {
		t.Errorf("a first fragment went out as 0x%02X, want 0x01", wire[0])
	}
}

// ------------------------------------------------------------- the sent headers

// requestSeen runs one http_request against a server that records what it got.
func requestSeen(t *testing.T, body string, headers *object.Hash) (*http.Request, string) {
	t.Helper()
	seen := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Clone(r.Context())
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	_, errObj := unwrapPairNoFatal(HttpRequest(
		stringObj("POST"), stringObj(srv.URL), stringObj(body), headers))
	if errObj != nil {
		return nil, errObj.Message
	}
	select {
	case got := <-seen:
		return got, ""
	case <-time.After(5 * time.Second):
		t.Fatal("http_request succeeded and the server saw nothing")
		return nil, ""
	}
}

// TestAHostHeaderReachesTheServer is the row's regression test: the server has
// to observe the host that was asked for, which is what virtual-host probing
// and a Host/SNI mismatch check are.
func TestAHostHeaderReachesTheServer(t *testing.T) {
	got, refusal := requestSeen(t, "", makeHashObject(map[string]object.Object{
		"Host":       stringObj("vhost.example"),
		"X-Ordinary": stringObj("kept"),
	}))
	if refusal != "" {
		t.Fatalf("refused: %s", refusal)
	}
	if got.Host != "vhost.example" {
		t.Errorf("the server saw Host %q, want %q", got.Host, "vhost.example")
	}
	if got.Header.Get("X-Ordinary") != "kept" {
		t.Errorf("an ordinary header did not survive: %v", got.Header)
	}
}

// TestALengthThatDisagreesWithTheBodyIsRefused. net/http writes the real length
// of the body it is given and ignores this header, so a caller who set it was
// measuring a connection that is not the one that was made. The same
// disagreement is refused by http_build_request (M26-NET-016).
func TestALengthThatDisagreesWithTheBodyIsRefused(t *testing.T) {
	body := "body-of-fourteen"
	_, refusal := requestSeen(t, body, makeHashObject(map[string]object.Object{
		"Content-Length": stringObj("999"),
	}))
	if refusal == "" {
		t.Fatalf("a Content-Length of 999 beside a %d-byte body was accepted", len(body))
	}
	for _, want := range []string{"999", fmt.Sprintf("%d", len(body))} {
		if !strings.Contains(refusal, want) {
			t.Errorf("the refusal does not name %s: %s", want, refusal)
		}
	}

	// One that agrees is already true, so it is dropped and the request is
	// sent: the server sees one Content-Length, and it is the body's.
	got, refusal := requestSeen(t, body, makeHashObject(map[string]object.Object{
		"Content-Length": stringObj(fmt.Sprintf("%d", len(body))),
	}))
	if refusal != "" {
		t.Fatalf("a Content-Length that agrees was refused: %s", refusal)
	}
	if got.ContentLength != int64(len(body)) {
		t.Errorf("the server saw Content-Length %d, want %d", got.ContentLength, len(body))
	}

	// And one that is not a number at all.
	if _, refusal := requestSeen(t, body, makeHashObject(map[string]object.Object{
		"Content-Length": stringObj("about sixteen"),
	})); refusal == "" {
		t.Errorf("a Content-Length that is not a number was accepted")
	}
}

// TestATransferEncodingIsRefused. net/http frames the body from the Request
// struct and not from this header, so asking for chunked got a Content-Length
// and no error -- measured. A request framed by hand is written with
// net_conn_write, which the refusal says.
func TestATransferEncodingIsRefused(t *testing.T) {
	_, refusal := requestSeen(t, "hi", makeHashObject(map[string]object.Object{
		"Transfer-Encoding": stringObj("chunked"),
	}))
	if refusal == "" {
		t.Fatalf("a Transfer-Encoding header was accepted")
	}
	if !strings.Contains(refusal, "net_conn_write") {
		t.Errorf("the refusal does not say what to use instead: %s", refusal)
	}
}

// TestTwoKeysForOneFieldAreRefused. net/http canonicalises a field name, so
// "X-Probe" and "x-probe" are one field with two values and only one of them
// was sent -- an order nothing in the language defines. The refusal is checked
// several times over, because a message that named a different field each time
// could not be acted on.
func TestTwoKeysForOneFieldAreRefused(t *testing.T) {
	first := ""
	for i := 0; i < 8; i++ {
		_, refusal := requestSeen(t, "", makeHashObject(map[string]object.Object{
			"X-Probe": stringObj("upper"),
			"x-probe": stringObj("lower"),
			"Host":    stringObj("vhost.one"),
			"host":    stringObj("vhost.two"),
		}))
		if refusal == "" {
			t.Fatalf("two keys naming one field were accepted")
		}
		if i == 0 {
			first = refusal
			if !strings.Contains(refusal, "Host") || !strings.Contains(refusal, "X-Probe") {
				t.Errorf("the refusal names neither duplicated field: %s", refusal)
			}
		} else if refusal != first {
			t.Errorf("the refusal changed between runs:\n%s\n%s", first, refusal)
		}
	}

	// Two different fields are not duplicates.
	if _, refusal := requestSeen(t, "", makeHashObject(map[string]object.Object{
		"X-One": stringObj("1"),
		"X-Two": stringObj("2"),
	})); refusal != "" {
		t.Errorf("two different fields were refused: %s", refusal)
	}
}

// ------------------------------------------------------- the response to a HEAD

// headResponse is a well-formed response to a HEAD request: the length of the
// representation that was asked about, and no body.
const headResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: 50000\r\n\r\n"

// TestAHeadResponseIsReadWhenTheMethodIsGiven is the row's regression test.
func TestAHeadResponseIsReadWhenTheMethodIsGiven(t *testing.T) {
	parsed := fidelityHash(t, HTTPParseResponse(stringObj(headResponse), stringObj("HEAD")))
	if got := hStr(t, parsed, "body"); got != "" {
		t.Errorf("a HEAD response parsed to a %d-byte body", len(got))
	}
	if got := hashStr(t, hashValueByKey(parsed, "headers"), "Content-Length"); got != "50000" {
		t.Errorf("the declared length is %q, want %q", got, "50000")
	}
}

// TestAHeadResponseIsStillRefusedWithoutTheMethod. The old behaviour is kept
// deliberately: with no method the body genuinely is unaccounted for, and
// guessing that it is a HEAD response would be the same silent framing in the
// other direction.
func TestAHeadResponseIsStillRefusedWithoutTheMethod(t *testing.T) {
	if _, errObj := unwrapPairNoFatal(HTTPParseResponse(stringObj(headResponse))); errObj == nil {
		t.Errorf("a HEAD response parsed with no method given")
	}
}

// TestTheMethodIsReadWhateverItsCase. net/http compares the method byte for
// byte -- "head" framed as a GET and failed, measured -- so it is upper-cased
// here, as http_request already upper-cases its own.
func TestTheMethodIsReadWhateverItsCase(t *testing.T) {
	for _, method := range []string{"HEAD", "head", "Head", " head "} {
		parsed := fidelityHash(t, HTTPParseResponse(stringObj(headResponse), stringObj(method)))
		if got := hStr(t, parsed, "body"); got != "" {
			t.Errorf("method %q: body is %d bytes", method, len(got))
		}
	}
}

// TestSomethingThatIsNotAMethodIsRefused. A whole request line, or a method
// with a space in it, is refused rather than quietly treated as a GET -- which
// is the silent framing this argument exists to end.
func TestSomethingThatIsNotAMethodIsRefused(t *testing.T) {
	for _, notAMethod := range []string{"GET /index.html", "", "HEAD\r\nX: y", "GET;HEAD"} {
		if _, errObj := unwrapPairNoFatal(HTTPParseResponse(
			stringObj(headResponse), stringObj(notAMethod))); errObj == nil {
			t.Errorf("%q was accepted as a method", notAMethod)
		}
	}
	if _, errObj := unwrapPairNoFatal(HTTPParseResponse(stringObj(headResponse), intObj(4))); errObj == nil {
		t.Errorf("an INTEGER was accepted as a method")
	}
}

// TestAChunkedHeadResponseIsRead. A HEAD response may declare chunked framing
// and still carry no body, which is the other shape the row's failure took.
func TestAChunkedHeadResponseIsRead(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	parsed := fidelityHash(t, HTTPParseResponse(stringObj(raw), stringObj("HEAD")))
	if got := hStr(t, parsed, "body"); got != "" {
		t.Errorf("a chunked HEAD response parsed to a %d-byte body", len(got))
	}
}

// TestAnOrdinaryResponseIsUnchangedByTheArgument. Passing a method that is not
// HEAD changes nothing, which is what keeps a relay free to pass the method it
// read on every response.
func TestAnOrdinaryResponseIsUnchangedByTheArgument(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	for _, args := range [][]object.Object{
		{stringObj(raw)},
		{stringObj(raw), stringObj("GET")},
		{stringObj(raw), stringObj("POST")},
	} {
		parsed := fidelityHash(t, HTTPParseResponse(args...))
		if got := hStr(t, parsed, "body"); got != "hello" {
			t.Errorf("%d argument(s): body %q, want %q", len(args), got, "hello")
		}
	}
}

// TestTheConnectionReaderTakesTheMethodToo. This is the builtin a relay
// actually uses: it read the request one call earlier, so it knows the method.
func TestTheConnectionReaderTakesTheMethodToo(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		_, _ = server.Write([]byte(headResponse))
	}()
	parsed := fidelityHash(t, HTTPConnReadResponse(
		intObj(registerConn(client, false)), intObj(2000), stringObj("HEAD")))
	if got := hStr(t, parsed, "body"); got != "" {
		t.Errorf("a HEAD response read off a connection carried a %d-byte body", len(got))
	}
	if got := hashStr(t, hashValueByKey(parsed, "headers"), "Content-Length"); got != "50000" {
		t.Errorf("the declared length is %q, want %q", got, "50000")
	}
}

// TestTheHeadReaderSaysNothingFollowsAfterAHead. content_length and chunked say
// what to read off the connection next, and after a response to HEAD that is
// nothing, however the headers read. The declared length stays in headers,
// which is where the evidence belongs -- and which is exactly how net/http
// already answers for a status that carries no body.
func TestTheHeadReaderSaysNothingFollowsAfterAHead(t *testing.T) {
	read := func(method ...object.Object) *object.Hash {
		t.Helper()
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		go func() {
			_, _ = server.Write([]byte(headResponse))
		}()
		args := append([]object.Object{intObj(registerConn(client, false)), intObj(2000)}, method...)
		return fidelityHash(t, HTTPConnReadResponseHead(args...))
	}

	head := read(stringObj("HEAD"))
	if got := hInt(t, head, "content_length"); got != 0 {
		t.Errorf("after a HEAD, content_length is %d, want 0", got)
	}
	if got := hashStr(t, hashValueByKey(head, "headers"), "Content-Length"); got != "50000" {
		t.Errorf("the declared length was lost: %q", got)
	}

	// The same bytes, answering a GET: 50000 bytes really are coming.
	get := read(stringObj("GET"))
	if got := hInt(t, get, "content_length"); got != 50000 {
		t.Errorf("after a GET, content_length is %d, want 50000", got)
	}
}

// TestAHeadExchangeRebuilds. Reading the response was only half of relaying it.
// The length check added for M26-NET-016 refuses a Content-Length that
// disagrees with the body, and a HEAD response declares 50000 beside no body at
// all -- so without the method the builder refused a message the reader had
// just read, and a HEAD exchange was still unrelayable. Measured, which is how
// this was found.
func TestAHeadExchangeRebuilds(t *testing.T) {
	parsed := fidelityHash(t, HTTPParseResponse(stringObj(headResponse), stringObj("HEAD")))

	wire := fidelityString(t, HTTPBuildResponse(parsed, stringObj("HEAD")))
	if !strings.Contains(wire, "Content-Length: 50000\r\n") {
		t.Errorf("the declared length did not survive the relay:\n%q", wire)
	}
	if got := strings.Count(wire, "Content-Length:"); got != 1 {
		t.Errorf("the rebuilt response carries %d Content-Length headers, want 1:\n%q", got, wire)
	}
	if !strings.HasSuffix(wire, "\r\n\r\n") {
		t.Errorf("something follows the head of a rebuilt HEAD response:\n%q", wire)
	}

	// Without the method it is refused, and that is not an oversight: the
	// builder is being handed a message whose length disagrees with its body,
	// and only the method says that is legitimate.
	if _, errObj := unwrapPairNoFatal(HTTPBuildResponse(parsed)); errObj == nil {
		t.Errorf("a HEAD response rebuilt with no method given, declaring 50000 bytes it does not carry")
	}

	// A body on a HEAD response is refused, for the reason a body on a 204 is:
	// bytes after it are read as the start of the next message.
	msg := fidelityRefusal(t, "a HEAD response with a body",
		HTTPBuildResponse(withBody(parsed, "body", stringObj("oops")), stringObj("HEAD")))
	if !strings.Contains(msg, "HEAD") {
		t.Errorf("the refusal does not name the method: %s", msg)
	}
}

// TestAnEmptyTwoHundredStillGetsALength. The HEAD case must not have widened
// into every empty 200: for a 200 answering a GET, an absent body is itself a
// fact that Content-Length: 0 states.
func TestAnEmptyTwoHundredStillGetsALength(t *testing.T) {
	parsed := fidelityHash(t, HTTPParseResponse(stringObj("HTTP/1.1 200 OK\r\n\r\n")))
	for _, args := range [][]object.Object{
		{parsed},
		{parsed, stringObj("GET")},
	} {
		wire := fidelityString(t, HTTPBuildResponse(args...))
		if !strings.Contains(wire, "Content-Length: 0\r\n") {
			t.Errorf("%d argument(s): an empty 200 lost its Content-Length: 0:\n%q", len(args), wire)
		}
	}
}
