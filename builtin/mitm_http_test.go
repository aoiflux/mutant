package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

func TestHTTPParseRequest(t *testing.T) {
	raw := "POST /submit?x=1 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 11\r\n" +
		"\r\n" +
		"{\"ok\":true}"

	result, errObj := unwrapPair(t, HTTPParseRequest(stringObj(raw)))
	if errObj != nil {
		t.Fatalf("http_parse_request: %s", errObj.Message)
	}
	if got := hashStr(t, result, "method"); got != "POST" {
		t.Fatalf("method=%q", got)
	}
	if got := hashStr(t, result, "path"); got != "/submit" {
		t.Fatalf("path=%q", got)
	}
	if got := hashStr(t, result, "query"); got != "x=1" {
		t.Fatalf("query=%q", got)
	}
	if got := hashStr(t, result, "host"); got != "example.com" {
		t.Fatalf("host=%q", got)
	}
	headers := hashField(t, result, "headers")
	if got := hashStr(t, headers, "Content-Type"); got != "application/json" {
		t.Fatalf("content-type=%q", got)
	}
	if got := hashStr(t, result, "body"); got != "{\"ok\":true}" {
		t.Fatalf("body=%q", got)
	}
}

func TestHTTPParseResponse(t *testing.T) {
	raw := "HTTP/1.1 404 Not Found\r\n" +
		"Content-Length: 9\r\n" +
		"X-Trace: abc\r\n" +
		"\r\n" +
		"not here!"

	result, errObj := unwrapPair(t, HTTPParseResponse(stringObj(raw)))
	if errObj != nil {
		t.Fatalf("http_parse_response: %s", errObj.Message)
	}
	if got := hashInt(t, result, "status"); got != 404 {
		t.Fatalf("status=%d", got)
	}
	if got := hashStr(t, result, "body"); got != "not here!" {
		t.Fatalf("body=%q", got)
	}
	headers := hashField(t, result, "headers")
	if got := hashStr(t, headers, "X-Trace"); got != "abc" {
		t.Fatalf("x-trace=%q", got)
	}
}

func TestHTTPBuildRequestRoundTrip(t *testing.T) {
	built, errObj := unwrapPair(t, HTTPBuildRequest(makeHashObject(map[string]object.Object{
		"method": stringObj("GET"),
		"path":   stringObj("/api/v1/status"),
		"host":   stringObj("svc.internal"),
		"headers": makeHashObject(map[string]object.Object{
			"Accept": stringObj("application/json"),
		}),
	})))
	if errObj != nil {
		t.Fatalf("http_build_request: %s", errObj.Message)
	}
	raw := built.(*object.String).Value
	if !strings.HasPrefix(raw, "GET /api/v1/status HTTP/1.1\r\n") {
		t.Fatalf("bad request line: %q", raw)
	}
	if !strings.Contains(raw, "Host: svc.internal\r\n") {
		t.Fatalf("missing Host header: %q", raw)
	}

	// Re-parse to confirm it is well-formed on the wire.
	parsed, errObj := unwrapPair(t, HTTPParseRequest(stringObj(raw)))
	if errObj != nil {
		t.Fatalf("re-parse failed: %s", errObj.Message)
	}
	if got := hashStr(t, parsed, "path"); got != "/api/v1/status" {
		t.Fatalf("re-parsed path=%q", got)
	}
}

func TestHTTPBuildResponseAddsContentLength(t *testing.T) {
	built, errObj := unwrapPair(t, HTTPBuildResponse(makeHashObject(map[string]object.Object{
		"status": intObj(200),
		"body":   stringObj("hello"),
	})))
	if errObj != nil {
		t.Fatalf("http_build_response: %s", errObj.Message)
	}
	raw := built.(*object.String).Value
	if !strings.HasPrefix(raw, "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("bad status line: %q", raw)
	}
	if !strings.Contains(raw, "Content-Length: 5\r\n") {
		t.Fatalf("missing Content-Length: %q", raw)
	}
	if !strings.HasSuffix(raw, "\r\n\r\nhello") {
		t.Fatalf("body not terminated correctly: %q", raw)
	}
}

// TestHTTPConnReadRequest drives an intercepted request off a live socket,
// the way a proxy loop would.
func TestHTTPConnReadRequest(t *testing.T) {
	lnResult, errObj := unwrapPair(t, NetListen(stringObj("127.0.0.1:0")))
	if errObj != nil {
		t.Fatalf("net_listen: %s", errObj.Message)
	}
	lnHandle := lnResult.(*object.Integer).Value
	defer NetListenClose(intObj(lnHandle))
	ml, _ := lookupListener(lnHandle)
	addr := ml.ln.Addr().String()

	go func() {
		conn, _ := unwrapPair(t, NetConnect(stringObj(addr), intObj(2000)))
		h := conn.(*object.Integer).Value
		NetConnWrite(intObj(h), stringObj("GET http://target.example/path HTTP/1.1\r\nHost: target.example\r\n\r\n"))
	}()

	acc, errObj := unwrapPair(t, NetAccept(intObj(lnHandle), intObj(2000)))
	if errObj != nil {
		t.Fatalf("net_accept: %s", errObj.Message)
	}
	connHandle := hashInt(t, acc, "handle")

	req, errObj := unwrapPair(t, HTTPConnReadRequest(intObj(connHandle), intObj(2000)))
	if errObj != nil {
		t.Fatalf("http_conn_read_request: %s", errObj.Message)
	}
	if got := hashStr(t, req, "method"); got != "GET" {
		t.Fatalf("method=%q", got)
	}
	if got := hashStr(t, req, "host"); got != "target.example" {
		t.Fatalf("host=%q", got)
	}
	NetConnClose(intObj(connHandle))
}
