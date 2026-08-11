package builtin

import (
	"net"
	"strings"
	"testing"

	"mutant/object"
)

// TestNetConnWriteDeadline verifies that net_conn_write applies a write deadline
// so a peer that never reads cannot hang the write forever. net.Pipe() gives an
// in-memory connection whose writes block until the other end reads; with no
// reader and a short timeout, the write must fail with a deadline error rather
// than blocking. It also checks the optional timeout arg is type-validated and
// that a normal write (with a reader draining the pipe) succeeds.
func TestNetConnWriteDeadline(t *testing.T) {
	// Stalled peer: nothing reads the other end, short timeout -> deadline error.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	h := registerConn(client, false)

	res := NetConnWrite(intObj(h), stringObj("blocked-forever"), intObj(50))
	if _, errObj := unwrapPairNoFatal(res); errObj == nil {
		t.Fatalf("expected a write-deadline error for an unread peer, got success")
	}

	// Type error on the optional timeout argument.
	if _, errObj := unwrapPairNoFatal(NetConnWrite(intObj(h), stringObj("x"), stringObj("nope"))); errObj == nil {
		t.Fatalf("expected type error for non-INTEGER timeout arg")
	}

	// Happy path: a reader drains the pipe, so the write completes.
	c2, s2 := net.Pipe()
	defer c2.Close()
	defer s2.Close()
	go func() {
		buf := make([]byte, 64)
		_, _ = s2.Read(buf)
	}()
	h2 := registerConn(c2, false)
	out, errObj := unwrapPair(t, NetConnWrite(intObj(h2), stringObj("ping"), intObj(1000)))
	if errObj != nil {
		t.Fatalf("unexpected error on drained write: %s", errObj.Message)
	}
	if n, ok := out.(*object.Integer); !ok || n.Value != int64(len("ping")) {
		t.Fatalf("expected 4 bytes written, got %v", out.Inspect())
	}
}

// TestWSWriteFrameDeadline verifies ws_write_frame honours a write deadline the
// same way (a server->client text frame to an unread peer times out).
func TestWSWriteFrameDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	h := registerConn(client, false)

	// opcode 0x1 = text, mask=false (server->client), 50ms deadline, no reader.
	res := WSWriteFrame(intObj(h), intObj(0x1), stringObj("hello"), boolObj(false), intObj(50))
	if _, errObj := unwrapPairNoFatal(res); errObj == nil {
		t.Fatalf("expected a write-deadline error for an unread peer, got success")
	}

	// Wrong arity is rejected (4 or 5 args only).
	if _, errObj := unwrapPairNoFatal(WSWriteFrame(intObj(h), intObj(0x1), stringObj("x"))); errObj == nil {
		t.Fatalf("expected arity error for 3-arg ws_write_frame")
	}
}

// TestHTTPBuildRequestContentLength verifies a Content-Length header is added
// when a body is present and the caller didn't supply one, and is not duplicated
// when the caller did, and is absent for a bodyless request.
func TestHTTPBuildRequestContentLength(t *testing.T) {
	body := "name=value&x=1"
	reqWithBody := makeHashObject(map[string]object.Object{
		"method": stringObj("POST"),
		"path":   stringObj("/submit"),
		"host":   stringObj("example.com"),
		"body":   stringObj(body),
	})
	out, errObj := unwrapPair(t, HTTPBuildRequest(reqWithBody))
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Message)
	}
	wire := out.(*object.String).Value
	wantCL := "Content-Length: " + itoa(int64(len(body)))
	if !strings.Contains(wire, wantCL) {
		t.Fatalf("expected %q in request, got:\n%s", wantCL, wire)
	}

	// Caller-supplied Content-Length must not be duplicated.
	reqExplicit := makeHashObject(map[string]object.Object{
		"method":  stringObj("POST"),
		"path":    stringObj("/submit"),
		"headers": makeHashObject(map[string]object.Object{"Content-Length": stringObj("99")}),
		"body":    stringObj(body),
	})
	out2, _ := unwrapPair(t, HTTPBuildRequest(reqExplicit))
	if got := strings.Count(out2.(*object.String).Value, "Content-Length:"); got != 1 {
		t.Fatalf("expected exactly one Content-Length header, got %d", got)
	}

	// A bodyless request gets no Content-Length.
	reqNoBody := makeHashObject(map[string]object.Object{
		"method": stringObj("GET"),
		"path":   stringObj("/"),
		"host":   stringObj("example.com"),
	})
	out3, _ := unwrapPair(t, HTTPBuildRequest(reqNoBody))
	if strings.Contains(out3.(*object.String).Value, "Content-Length:") {
		t.Fatalf("did not expect Content-Length for a bodyless GET, got:\n%s", out3.(*object.String).Value)
	}
}

// (itoa is defined in browser_builtins_test.go)

// TestNetSynScanAliasRegistered verifies the honesty rename: the truthful
// net_connect_scan name is registered, and the deprecated net_syn_scan alias is
// still registered (backward compatibility) — both resolvable by compiled code.
func TestNetSynScanAliasRegistered(t *testing.T) {
	var haveConnect, haveSyn bool
	for _, b := range Builtins {
		switch b.Name {
		case BuiltinNameNetConnectScan:
			haveConnect = true
		case BuiltinNameNetSynScan:
			haveSyn = true
		}
	}
	if !haveConnect {
		t.Errorf("net_connect_scan is not registered")
	}
	if !haveSyn {
		t.Errorf("net_syn_scan alias is no longer registered (breaks existing programs)")
	}
}

// (itoa is defined in browser_builtins_test.go)
