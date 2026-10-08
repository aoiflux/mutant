package builtin

import (
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"mutant/object"
)

// M26-NET-028: nothing bounded the number of fields in an HTTP message head, so
// 87,964 one-line fields fitted inside a 1 MiB head and became an 87,964-pair
// hash -- 33,246,576 bytes of heap for 1,044,485 bytes on the wire.
//
// The connection half of these tests uses net.Pipe rather than a listener and a
// port: registerConn takes any net.Conn, net.Pipe honours SetReadDeadline, and
// an in-memory pair cannot flake on a port or leave a socket in TIME_WAIT. It
// also keeps this file standing on HEAD alone, with no helper borrowed from a
// kit that has not landed.

// requestHeadWithFields builds a request head carrying `fields` numbered
// one-line header fields.
//
// The Host field is written and is not counted. net/http moves it to req.Host
// and deletes it from req.Header (net/http/request.go:1064 in go1.26.6), so it
// never reaches the hash the cap is protecting; a test that counted it would be
// off by one in the direction that hides an off-by-one in the fix.
func requestHeadWithFields(fields int) string {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1" + httpCRLF)
	b.WriteString("Host: x" + httpCRLF)
	for i := 0; i < fields; i++ {
		b.WriteString("X-F" + strconv.Itoa(i) + ": 1" + httpCRLF)
	}
	b.WriteString(httpCRLF)
	return b.String()
}

// responseHeadWithFields builds a response head carrying `fields` numbered
// one-line header fields. Nothing is removed from a response's header, so the
// count is exactly what was written.
func responseHeadWithFields(fields int) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK" + httpCRLF)
	for i := 0; i < fields; i++ {
		b.WriteString("X-F" + strconv.Itoa(i) + ": 1" + httpCRLF)
	}
	b.WriteString(httpCRLF)
	return b.String()
}

// httpCRLF is the line ending HTTP requires. It is a constant rather than a literal
// in each builder so that a reader can see at a glance that no line of these
// fixtures ends in a bare LF, which net/textproto tolerates and a real peer
// would not send.
const httpCRLF = "\r\n"

// fieldCapConn puts one whole message on a fresh in-memory connection, closes
// the writing end, and hands back the handle to read it from.
//
// The close is what ends a response carrying no Content-Length: net/http gives
// such a body no length and reads it to EOF, so without the close the body read
// of http_conn_read_response would wait for the deadline instead of returning.
// The write runs on its own goroutine because net.Pipe is unbuffered, so a
// write blocks until the reader takes it; the cleanup closes the connection,
// which unblocks that goroutine whether the test read the message or refused
// it.
func fieldCapConn(t *testing.T, raw string) int64 {
	t.Helper()

	client, server := net.Pipe()
	handle := registerConn(server, false)
	t.Cleanup(func() {
		_, _ = removeConn(handle)
		_ = server.Close()
		_ = client.Close()
	})
	go func() {
		_, _ = io.WriteString(client, raw)
		_ = client.Close()
	}()
	return handle
}

// TestAHeadAtTheFieldCapIsAcceptedAndOnePastItIsRefused is the off-by-one pair.
// Only the second half detects M26-NET-028; the first is what an inclusive cap
// written as `>=` would break, and getting that wrong turns every ordinary
// hundred-field message into an error.
func TestAHeadAtTheFieldCapIsAcceptedAndOnePastItIsRefused(t *testing.T) {
	t.Run("a head of exactly the cap is read whole", func(t *testing.T) {
		handle := fieldCapConn(t, requestHeadWithFields(maxHTTPHeaderFields))

		result, errObj := unwrapPair(t, HTTPConnReadRequest(intObj(handle), intObj(8000)))
		if errObj != nil {
			t.Fatalf("a head of exactly %d fields is within the cap: %s",
				maxHTTPHeaderFields, errObj.Message)
		}
		if got := len(headersFromResult(t, result)); got != maxHTTPHeaderFields {
			t.Fatalf("the headers hash holds %d pairs, want %d", got, maxHTTPHeaderFields)
		}
	})

	t.Run("one field past the cap is refused", func(t *testing.T) {
		handle := fieldCapConn(t, requestHeadWithFields(maxHTTPHeaderFields+1))

		_, errObj := unwrapPair(t, HTTPConnReadRequest(intObj(handle), intObj(8000)))
		if errObj == nil {
			t.Fatalf("a head of %d fields must be refused, not turned into a "+
				"%d-pair hash", maxHTTPHeaderFields+1, maxHTTPHeaderFields+1)
		}
		requireFieldRefusal(t, errObj, maxHTTPHeaderFields+1)
	})
}

// TestRepeatedFieldNamesCountTowardsTheFieldCap is why the cap counts values and
// not keys, and it is the test that separates the fix from the obvious wrong
// version of it.
//
// http.Header is a map[string][]string: a head that spells one field name 101
// times is a single map entry holding 101 values. A cap written as len(header)
// sees 1 and accepts, and headerToHash then joins all 101 values into one
// string -- the same amplification with a different shape. A cap that sums the
// slices sees 101 and refuses.
func TestRepeatedFieldNamesCountTowardsTheFieldCap(t *testing.T) {
	const repeats = maxHTTPHeaderFields + 1

	var b strings.Builder
	b.WriteString("GET / HTTP/1.1" + httpCRLF)
	b.WriteString("Host: x" + httpCRLF)
	for i := 0; i < repeats; i++ {
		b.WriteString("X-Same: " + strconv.Itoa(i) + httpCRLF)
	}
	b.WriteString(httpCRLF)

	handle := fieldCapConn(t, b.String())

	result, errObj := unwrapPair(t, HTTPConnReadRequest(intObj(handle), intObj(8000)))
	if errObj == nil {
		pairs := headersFromResult(t, result)
		t.Fatalf("%d repeats of one field name were accepted as %d header "+
			"name(s): the cap is counting keys, not the fields that arrived",
			repeats, len(pairs))
	}
	requireFieldRefusal(t, errObj, repeats)
}

// TestEveryHTTPHeadReaderAppliesTheFieldCap holds the cap to all six entry
// points that reach headerToHash, not just the two the row is filed against.
// They share one hash builder and one defect, and the two _head builtins are
// the documented way to read a message whose body is large -- leaving those
// uncapped would leave the cap one call away from being bypassed.
func TestEveryHTTPHeadReaderAppliesTheFieldCap(t *testing.T) {
	const over = maxHTTPHeaderFields + 1

	t.Run("http_parse_request", func(t *testing.T) {
		_, errObj := unwrapPair(t, HTTPParseRequest(stringObj(requestHeadWithFields(over))))
		requireRefused(t, errObj, over)
	})

	t.Run("http_parse_response", func(t *testing.T) {
		_, errObj := unwrapPair(t, HTTPParseResponse(stringObj(responseHeadWithFields(over))))
		requireRefused(t, errObj, over)
	})

	t.Run("http_conn_read_request", func(t *testing.T) {
		handle := fieldCapConn(t, requestHeadWithFields(over))
		_, errObj := unwrapPair(t, HTTPConnReadRequest(intObj(handle), intObj(8000)))
		requireRefused(t, errObj, over)
	})

	t.Run("http_conn_read_response", func(t *testing.T) {
		handle := fieldCapConn(t, responseHeadWithFields(over))
		_, errObj := unwrapPair(t, HTTPConnReadResponse(intObj(handle), intObj(8000)))
		requireRefused(t, errObj, over)
	})

	t.Run("http_conn_read_request_head", func(t *testing.T) {
		handle := fieldCapConn(t, requestHeadWithFields(over))
		_, errObj := unwrapPair(t, HTTPConnReadRequestHead(intObj(handle), intObj(8000)))
		requireRefused(t, errObj, over)
	})

	t.Run("http_conn_read_response_head", func(t *testing.T) {
		handle := fieldCapConn(t, responseHeadWithFields(over))
		_, errObj := unwrapPair(t, HTTPConnReadResponseHead(intObj(handle), intObj(8000)))
		requireRefused(t, errObj, over)
	})
}

// TestAnOrdinaryHeadKeepsEveryFieldItArrivedWith is the false-refusal guard. A
// cap that refuses real traffic is worse than the hole it closes, and the
// fields have to still be there afterwards: an implementation that counted
// correctly and then dropped the overflow would pass every test above.
func TestAnOrdinaryHeadKeepsEveryFieldItArrivedWith(t *testing.T) {
	const fields = 12

	handle := fieldCapConn(t, requestHeadWithFields(fields))

	result, errObj := unwrapPair(t, HTTPConnReadRequest(intObj(handle), intObj(8000)))
	if errObj != nil {
		t.Fatalf("a %d-field head is an ordinary request: %s", fields, errObj.Message)
	}
	pairs := headersFromResult(t, result)
	if len(pairs) != fields {
		t.Fatalf("the headers hash holds %d pairs, want %d", len(pairs), fields)
	}
	for i := 0; i < fields; i++ {
		name := "X-F" + strconv.Itoa(i)
		if _, ok := pairs[name]; !ok {
			t.Fatalf("%s is missing from the headers hash", name)
		}
	}
}

// TestARefusedHeadLeavesTheBodyUnread is the claim the fix makes about cost, as
// a test rather than as a sentence in a commit message. The check sits ahead of
// the body read, so a refused message must not also have cost a body: the peer
// writes a head past the cap and then declares a body it never sends, and the
// refusal has to come back rather than wait on bytes that are not coming.
//
// Without the check, http_conn_read_request blocks here until the deadline and
// then fails with a timeout -- a different error, arrived at expensively.
func TestARefusedHeadLeavesTheBodyUnread(t *testing.T) {
	const over = maxHTTPHeaderFields + 1

	var b strings.Builder
	b.WriteString("POST / HTTP/1.1" + httpCRLF)
	b.WriteString("Host: x" + httpCRLF)
	b.WriteString("Content-Length: 1048576" + httpCRLF)
	for i := 0; i < over; i++ {
		b.WriteString("X-F" + strconv.Itoa(i) + ": 1" + httpCRLF)
	}
	b.WriteString(httpCRLF)
	// and then nothing: the body is declared and never sent.

	client, server := net.Pipe()
	handle := registerConn(server, false)
	t.Cleanup(func() {
		_, _ = removeConn(handle)
		_ = server.Close()
		_ = client.Close()
	})
	head := b.String()
	go func() { _, _ = io.WriteString(client, head) }()

	_, errObj := unwrapPair(t, HTTPConnReadRequest(intObj(handle), intObj(8000)))
	if errObj == nil {
		t.Fatal("a head of more fields than the cap allows must be refused")
	}
	// Content-Length is one of the fields that arrived and net/http keeps it in
	// req.Header when it is present and the message is not chunked
	// (net/http/transfer.go:723-725 in go1.26.6), so the count in the refusal is
	// over+1. Host is the one field that is moved out and so not counted.
	requireFieldRefusal(t, errObj, over+1)
}

// requireFieldRefusal asserts that errObj is the field-count refusal and that it
// names how many fields arrived. The count is part of the contract: an examiner
// reading "more than the 100 allowed" with no number cannot tell a head of 101
// fields from one of 90,000, which is the difference between a peer with a
// verbose client and a peer attacking the proxy.
func requireFieldRefusal(t *testing.T, errObj *object.Error, fields int) {
	t.Helper()

	if !strings.Contains(errObj.Message, "header fields") {
		t.Fatalf("expected the field-count refusal, got %q", errObj.Message)
	}
	if !strings.Contains(errObj.Message, strconv.Itoa(fields)) {
		t.Fatalf("the refusal does not say how many fields arrived (%d): %q",
			fields, errObj.Message)
	}
	if !strings.Contains(errObj.Message, strconv.Itoa(maxHTTPHeaderFields)) {
		t.Fatalf("the refusal does not name the cap (%d): %q",
			maxHTTPHeaderFields, errObj.Message)
	}
}

// requireRefused is requireFieldRefusal plus the nil check, for the table above.
func requireRefused(t *testing.T, errObj *object.Error, fields int) {
	t.Helper()

	if errObj == nil {
		t.Fatalf("a head of %d fields must be refused", fields)
	}
	requireFieldRefusal(t, errObj, fields)
}

// headersFromResult returns the headers hash as a plain map, so a test can count
// what reached the script and look a field up by name.
func headersFromResult(t *testing.T, result object.Object) map[string]string {
	t.Helper()

	hash, ok := result.(*object.Hash)
	if !ok {
		t.Fatalf("result is not a HASH. got=%T", result)
	}
	var headers *object.Hash
	for _, pair := range hash.Pairs {
		key, ok := pair.Key.(*object.String)
		if !ok || key.Value != "headers" {
			continue
		}
		headers, ok = pair.Value.(*object.Hash)
		if !ok {
			t.Fatalf("the headers field is not a HASH. got=%T", pair.Value)
		}
	}
	if headers == nil {
		t.Fatal("the result has no headers field")
	}

	out := make(map[string]string, len(headers.Pairs))
	for _, pair := range headers.Pairs {
		key, ok := pair.Key.(*object.String)
		if !ok {
			t.Fatalf("a headers key is not a STRING. got=%T", pair.Key)
		}
		value, ok := pair.Value.(*object.String)
		if !ok {
			t.Fatalf("the value of %s is not a STRING. got=%T", key.Value, pair.Value)
		}
		out[key.Value] = value.Value
	}
	return out
}
