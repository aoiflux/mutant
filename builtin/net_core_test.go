package builtin

import (
	"net"
	"strings"
	"testing"

	"mutant/object"
)

func netHash(t *testing.T, res object.Object) *object.Hash {
	t.Helper()
	payload, errObj := unwrapPair(t, res)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}
	h, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH, got %T (%s)", payload, payload.Inspect())
	}
	return h
}

func netHashBool(t *testing.T, h *object.Hash, key string) bool {
	t.Helper()
	v, ok := h.Pairs[(&object.String{Value: key}).HashKey()]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	b, ok := v.Value.(*object.Boolean)
	if !ok {
		t.Fatalf("key %q is not BOOLEAN", key)
	}
	return b.Value
}

func TestNetResolveLocalhost(t *testing.T) {
	payload, errObj := unwrapPair(t, NetResolve(stringObj("localhost")))
	if errObj != nil {
		t.Fatalf("net_resolve error: %s", errObj.Inspect())
	}
	arr, ok := payload.(*object.Array)
	if !ok || len(arr.Elements) == 0 {
		t.Fatalf("net_resolve(localhost) should return addresses, got %T", payload)
	}
	// type error path.
	if _, errObj := unwrapPair(t, NetResolve(intObj(1))); errObj == nil {
		t.Fatal("net_resolve of non-string should error")
	}
}

func TestNetDialLocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	if !netHashBool(t, netHash(t, NetDial(stringObj(addr), intObj(1000))), "ok") {
		t.Fatal("net_dial to a live listener should be ok")
	}

	// Close the listener; dialing the now-dead address should not be ok.
	ln.Close()
	if netHashBool(t, netHash(t, NetDial(stringObj(addr), intObj(300))), "ok") {
		t.Fatal("net_dial to a closed listener should not be ok")
	}
}

func TestNetBannerLocalServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("MUTANT-BANNER-220\r\n"))
	}()

	h := netHash(t, NetBanner(stringObj(ln.Addr().String()), intObj(1500)))
	if !netHashBool(t, h, "ok") {
		t.Fatalf("net_banner should succeed: %s", h.Inspect())
	}
	banner := h.Pairs[(&object.String{Value: "banner"}).HashKey()].Value.(*object.String).Value
	if !strings.Contains(banner, "MUTANT-BANNER-220") {
		t.Fatalf("banner did not contain the server greeting: %q", banner)
	}
}

func TestNetCoreArgErrors(t *testing.T) {
	if _, errObj := unwrapPair(t, NetDial(stringObj("127.0.0.1:80"))); errObj == nil {
		t.Fatal("net_dial with wrong arg count should error")
	}
	if _, errObj := unwrapPair(t, NetBanner(intObj(1), intObj(1))); errObj == nil {
		t.Fatal("net_banner with non-string address should error")
	}
}
