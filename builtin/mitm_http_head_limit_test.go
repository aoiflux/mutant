package builtin

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"

	"mutant/object"
)

// headLimitConn returns a connected pair with the server end registered as a
// handle, which is what the http_conn_* builtins take.
func headLimitConn(t *testing.T) (client net.Conn, handle int64) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr == nil {
			accepted <- c
		}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	server := <-accepted
	t.Cleanup(func() { _ = server.Close() })

	return client, registerConn(server, false)
}

// readHeadWithPad sends one request whose X-Pad field is the bytes given, and
// returns what http_conn_read_request made of it.
//
// The pad is built by the caller rather than here, and that matters: a
// bytes.Repeat of 32 MiB used to run in this goroutine, which was started
// immediately before a measurement bounded at 8 MiB, so the test's own
// allocation raced into the figure it was asserting.
func readHeadWithPad(t *testing.T, pad []byte) *object.Error {
	t.Helper()

	client, handle := headLimitConn(t)
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1" + "\r\n" + "Host: x" + "\r\n" + "X-Pad: "))
		_, _ = client.Write(pad)
		_, _ = client.Write([]byte("\r\n" + "\r\n"))
	}()

	_, errObj := unwrapPair(t, HTTPConnReadRequest(intObj(handle), intObj(4000)))
	return errObj
}

// TestAnOversizedRequestHeadIsRefused is M26-NET-008. The body was capped by
// maxHTTPBodyBytes and the head was not, so a peer -- which on an intercepted
// connection is whatever is on the wire -- could send one header field of any
// length and have it read in full. A 32 MiB field grew the heap by 69 MiB and
// was accepted.
//
// The growth bound is the assertion that matters. An error on its own could be
// returned after the memory had already been taken.
//
// It is measured against the same read of a field of twice the header budget,
// which is refused for the same reason 32 MiB is. Both measurements are
// therefore of the same refusal, and the difference between them is what the
// extra 30 MiB on the wire cost -- which is the question, since a reader held
// to the budget stops in the same place either way. See allocation_gap_test.go
// for why the absolute figure this asserted until 2026-10-06 could not survive
// a full run of this package.
func TestAnOversizedRequestHeadIsRefused(t *testing.T) {
	const overBudget = maxHTTPHeaderBytes * 2
	const farOverBudget = 32 << 20

	overPad := bytes.Repeat([]byte("A"), overBudget)
	farOverPad := bytes.Repeat([]byte("A"), farOverBudget)

	var overErr, farOverErr *object.Error
	requireNoAllocationGap(t, "reading a 32 MiB header field rather than one of twice the budget",
		func() { overErr = readHeadWithPad(t, overPad) },
		func() { farOverErr = readHeadWithPad(t, farOverPad) })

	if overErr == nil {
		t.Fatalf("a %d byte header field should be refused, and until it is the two "+
			"measurements are not of the same refusal", overBudget)
	}
	if farOverErr == nil {
		t.Fatalf("a %d byte header field should be refused", farOverBudget)
	}
	for _, errObj := range []*object.Error{overErr, farOverErr} {
		if !strings.Contains(errObj.Message, "exceeds") {
			t.Fatalf("expected the head-too-large refusal, got %q", errObj.Message)
		}
	}
}

// TestABodyLargerThanTheHeaderBudgetStillArrives is the false-refusal guard,
// and the reason the bound is set on the socket and released rather than
// wrapped around the reader. The head is bounded by maxHTTPHeaderBytes; the
// body is bounded by maxHTTPBodyBytes, which is far larger. A body between the
// two sizes proves the header budget was let go of before the body was read --
// get that wrong and every ordinary upload through this builtin truncates.
func TestABodyLargerThanTheHeaderBudgetStillArrives(t *testing.T) {
	const bodyBytes = maxHTTPHeaderBytes * 2

	client, handle := headLimitConn(t)

	go func() {
		_, _ = client.Write([]byte("POST /upload HTTP/1.1" + "\r\n" +
			"Host: x" + "\r\n" +
			"Content-Length: " + strconv.Itoa(bodyBytes) + "\r\n" + "\r\n"))
		_, _ = client.Write(bytes.Repeat([]byte("b"), bodyBytes))
	}()

	result, errObj := unwrapPair(t, HTTPConnReadRequest(intObj(handle), intObj(8000)))
	if errObj != nil {
		t.Fatalf("a %d byte body is well inside maxHTTPBodyBytes: %s", bodyBytes, errObj.Message)
	}
	if got := len(hashStr(t, result, "body")); got != bodyBytes {
		t.Fatalf("body arrived as %d bytes, want %d", got, bodyBytes)
	}
}

// TestReadingOnlyTheHeadLeavesTheBodyUnbounded is the same guard for the
// streaming pair. http_conn_read_request_head deliberately leaves the body on
// the connection so net_conn_read can take it in pieces; if the head's budget
// outlived the head, that read would come back empty at EOF with nothing to
// say why.
func TestReadingOnlyTheHeadLeavesTheBodyUnbounded(t *testing.T) {
	const bodyBytes = maxHTTPHeaderBytes * 2

	client, handle := headLimitConn(t)

	go func() {
		_, _ = client.Write([]byte("POST /stream HTTP/1.1" + "\r\n" +
			"Host: x" + "\r\n" +
			"Content-Length: " + strconv.Itoa(bodyBytes) + "\r\n" + "\r\n"))
		_, _ = client.Write(bytes.Repeat([]byte("c"), bodyBytes))
	}()

	head, errObj := unwrapPair(t, HTTPConnReadRequestHead(intObj(handle), intObj(8000)))
	if errObj != nil {
		t.Fatalf("http_conn_read_request_head: %s", errObj.Message)
	}
	if got := hashInt(t, head, "content_length"); got != int64(bodyBytes) {
		t.Fatalf("content_length=%d, want %d", got, bodyBytes)
	}

	read := 0
	for read < bodyBytes {
		chunk, chunkErr := unwrapPair(t, NetConnRead(intObj(handle), intObj(64<<10), intObj(4000)))
		if chunkErr != nil {
			t.Fatalf("net_conn_read after %d bytes: %s", read, chunkErr.Message)
		}
		n := int(hashInt(t, chunk, "bytes"))
		if n == 0 {
			t.Fatalf("net_conn_read returned nothing after %d of %d body bytes; "+
				"the head's budget was not released", read, bodyBytes)
		}
		read += n
	}
}

// TestABodyPastTheCapIsRefusedAndOneAtTheCapIsNot is M26-NET-031.
//
// The body was read as io.ReadAll(io.LimitReader(body, maxHTTPBodyBytes)).
// io.LimitReader returns EOF once its budget is spent and io.ReadAll turns EOF
// into nil, so a body larger than the cap came back as exactly the cap with a
// nil error and no flag: the first 32 MiB of a bigger body, indistinguishable
// from the whole of a smaller one. "truncat" appeared nowhere in the file.
//
// Both halves are asserted because the second is what an off-by-one would
// break. The cap is inclusive: reading cap+1 is only how the overflow is
// observed, and a body of exactly maxHTTPBodyBytes is still a body that fits.
func TestABodyPastTheCapIsRefusedAndOneAtTheCapIsNot(t *testing.T) {
	send := func(t *testing.T, bodyLen int) (object.Object, *object.Error) {
		t.Helper()

		client, handle := headLimitConn(t)
		go func() {
			_, _ = client.Write([]byte("POST / HTTP/1.1" + "\r\n" +
				"Host: x" + "\r\n" +
				"Content-Length: " + strconv.Itoa(bodyLen) + "\r\n" + "\r\n"))
			// In chunks, because a single 32 MiB write to a socket nobody is
			// reading yet would block on the send buffer.
			chunk := bytes.Repeat([]byte("B"), 1<<20)
			for written := 0; written < bodyLen; {
				n := len(chunk)
				if remaining := bodyLen - written; remaining < n {
					n = remaining
				}
				if _, err := client.Write(chunk[:n]); err != nil {
					return
				}
				written += n
			}
		}()

		return unwrapPair(t, HTTPConnReadRequest(intObj(handle), intObj(30000)))
	}

	t.Run("one byte past the cap is refused", func(t *testing.T) {
		_, errObj := send(t, maxHTTPBodyBytes+1)
		if errObj == nil {
			t.Fatalf("a body of %d bytes must be refused, not cut to %d",
				maxHTTPBodyBytes+1, maxHTTPBodyBytes)
		}
		if !strings.Contains(errObj.Message, "body exceeds") {
			t.Fatalf("expected the body-too-large refusal, got %q", errObj.Message)
		}
	})

	t.Run("a body at exactly the cap still arrives whole", func(t *testing.T) {
		res, errObj := send(t, maxHTTPBodyBytes)
		if errObj != nil {
			t.Fatalf("a body of exactly %d bytes is within the cap: %s",
				maxHTTPBodyBytes, errObj.Message)
		}
		if got := len(hashStr(t, res, "body")); got != maxHTTPBodyBytes {
			t.Fatalf("body came back as %d bytes, want %d", got, maxHTTPBodyBytes)
		}
	})
}
