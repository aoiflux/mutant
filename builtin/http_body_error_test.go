package builtin

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"mutant/object"
)

// M26-NET-002. httpResponseOrError read the body with io.ReadAll and then threw
// the error away:
//
//	rawBody, readErr := io.ReadAll(resp.Body)
//	bodyStr := ""
//	if readErr == nil {
//		bodyStr = string(rawBody)
//	}
//	...
//	"error": stringObj(""),
//
// readErr was never looked at again and the hash's error field was a hard-coded
// empty string. httpResponseOrError2 decides whether to return a Go-level error
// by reading that very field, so the machinery to report this was already built
// and wired -- only the producer never filled it in. A response cut off mid-body
// therefore arrived as a successful response with an empty body: status 200,
// real headers, and no error anywhere. An IOC feed whose download was dropped
// read as a feed with no indicators in it.
//
// The body now carries whatever arrived before the stream broke, and the error
// field carries the reason, which makes the pair's error non-nil for all three
// builtins at once.
//
// The server is a raw listener rather than an httptest.Server because net/http
// will not send a Content-Length it then declines to honour. The lie has to be
// told at the socket.

// truncatingServer serves exactly one request: a 200 with the Content-Length it
// is told to declare, followed by `send` and then a close. It returns the base
// URL. Nothing is asserted about the request -- any of the three builtins may
// be the caller.
func truncatingServer(t *testing.T, declaredLength int, send string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return // the listener closed: the test is over
		}
		defer conn.Close()

		// Read the request and discard it. A GET arrives in one segment here,
		// and the response does not depend on it either way.
		_, _ = conn.Read(make([]byte, 4096))

		head := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/plain\r\n"+
			"Content-Length: %d\r\n"+
			"\r\n", declaredLength)
		_, _ = conn.Write([]byte(head + send))
	}()

	return "http://" + ln.Addr().String()
}

// TestHttpGetReportsABodyItCouldNotFinishReading is the row: 10 bytes of a
// declared 100 must not read as success.
func TestHttpGetReportsABodyItCouldNotFinishReading(t *testing.T) {
	url := truncatingServer(t, 100, "0123456789")

	result, errObj := unwrapPair(t, HttpGet(&object.String{Value: url}))
	if errObj == nil {
		t.Fatalf("a body cut off at 10 of 100 bytes returned no error; result=%s", result.Inspect())
	}
	if !strings.Contains(errObj.Message, "http_get") {
		t.Errorf("the error does not name the builtin, so a script cannot tell what failed: %s",
			errObj.Message)
	}

	hash, ok := result.(*object.Hash)
	if !ok {
		t.Fatalf("expected the response HASH beside the error, got=%T", result)
	}
	if got := hashStr(t, hash, "error"); got == "" {
		t.Error("the response's error field is empty, so a script that reads the hash " +
			"rather than the pair still cannot tell")
	}
	// The status line and the headers did arrive, and are not in doubt. Keeping
	// them is what lets a caller tell a truncated 200 from a failed connection,
	// which reports status 0.
	if got := hashFieldInt(t, hash, "status"); got != 200 {
		t.Errorf("status = %d, want 200: the response line arrived and is not what broke", got)
	}
}

// TestHttpGetKeepsTheBytesThatDidArrive states the other half of the decision.
// The alternative was to report the error and drop the partial body; these
// bytes are evidence, and a caller that honours the error loses nothing by
// being handed them.
func TestHttpGetKeepsTheBytesThatDidArrive(t *testing.T) {
	url := truncatingServer(t, 100, "0123456789")

	result, errObj := unwrapPair(t, HttpGet(&object.String{Value: url}))
	if errObj == nil {
		t.Fatal("a truncated body returned no error")
	}

	hash, ok := result.(*object.Hash)
	if !ok {
		t.Fatalf("expected a HASH, got=%T", result)
	}
	if got := hashStr(t, hash, "body"); got != "0123456789" {
		t.Errorf("body = %q, want the 10 bytes that arrived before the stream broke", got)
	}
}

// TestHttpGetOnAWholeBodyReportsNoError is the guard. A response that is not
// truncated must come back exactly as it did before, with an empty error field
// and a nil error -- otherwise the fix would have made every call fail.
func TestHttpGetOnAWholeBodyReportsNoError(t *testing.T) {
	const body = "0123456789"
	url := truncatingServer(t, len(body), body)

	result, errObj := unwrapPair(t, HttpGet(&object.String{Value: url}))
	if errObj != nil {
		t.Fatalf("a complete body reported an error: %s", errObj.Message)
	}

	hash, ok := result.(*object.Hash)
	if !ok {
		t.Fatalf("expected a HASH, got=%T", result)
	}
	if got := hashStr(t, hash, "error"); got != "" {
		t.Errorf("error field = %q on a complete body, want empty", got)
	}
	if got := hashStr(t, hash, "body"); got != body {
		t.Errorf("body = %q, want %q", got, body)
	}
	if got := hashFieldInt(t, hash, "status"); got != 200 {
		t.Errorf("status = %d, want 200", got)
	}
}

// TestHttpPostAndHttpRequestReportATruncatedBodyToo exists because the fix is
// in one shared helper and it would be easy to believe that without checking.
// All three builtins go through httpResponseOrError2, so all three must now
// report it.
func TestHttpPostAndHttpRequestReportATruncatedBodyToo(t *testing.T) {
	t.Run("http_post", func(t *testing.T) {
		url := truncatingServer(t, 100, "0123456789")
		result, errObj := unwrapPair(t, HttpPost(
			&object.String{Value: url},
			&object.String{Value: "payload"},
			&object.String{Value: "text/plain"},
		))
		if errObj == nil {
			t.Fatalf("http_post reported no error on a truncated body; result=%s", result.Inspect())
		}
	})

	t.Run("http_request", func(t *testing.T) {
		url := truncatingServer(t, 100, "0123456789")
		result, errObj := unwrapPair(t, HttpRequest(
			&object.String{Value: "GET"},
			&object.String{Value: url},
			&object.String{Value: ""},
			&object.Hash{Pairs: map[object.HashKey]object.HashPair{}},
		))
		if errObj == nil {
			t.Fatalf("http_request reported no error on a truncated body; result=%s", result.Inspect())
		}
	})
}

// TestHttpGetOnARefusedConnectionStillReportsStatusZero pins the pre-existing
// behaviour this fix sits next to, so the two error shapes stay distinguishable:
// a connection that never produced a response reports status 0 and an error,
// where a truncated one reports the real status and an error.
func TestHttpGetOnARefusedConnectionStillReportsStatusZero(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	url := "http://" + ln.Addr().String()
	// Close it before asking, so the port is almost certainly not listening.
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	result, errObj := unwrapPair(t, HttpGet(&object.String{Value: url}))
	if errObj == nil {
		t.Skip("the port was taken by something else between closing and asking")
	}

	hash, ok := result.(*object.Hash)
	if !ok {
		t.Fatalf("expected a HASH beside the error, got=%T", result)
	}
	if got := hashFieldInt(t, hash, "status"); got != 0 {
		t.Errorf("status = %d on a connection error, want 0", got)
	}
}
