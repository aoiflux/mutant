package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

func hashField(t *testing.T, obj object.Object, key string) object.Object {
	t.Helper()
	hash, ok := obj.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH, got %T", obj)
	}
	val, ok := hashValueByStringKey(hash, key)
	if !ok {
		t.Fatalf("hash missing key %q", key)
	}
	return val
}

func hashStr(t *testing.T, obj object.Object, key string) string {
	t.Helper()
	s, ok := hashField(t, obj, key).(*object.String)
	if !ok {
		t.Fatalf("key %q is not STRING", key)
	}
	return s.Value
}

func hashInt(t *testing.T, obj object.Object, key string) int64 {
	t.Helper()
	i, ok := hashField(t, obj, key).(*object.Integer)
	if !ok {
		t.Fatalf("key %q is not INTEGER", key)
	}
	return i.Value
}

func hashBool(t *testing.T, obj object.Object, key string) bool {
	t.Helper()
	b, ok := hashField(t, obj, key).(*object.Boolean)
	if !ok {
		t.Fatalf("key %q is not BOOLEAN", key)
	}
	return b.Value
}

// TestTLSCAAndLeafIssuance verifies the CA can sign a leaf and that a client
// trusting the CA can complete a full TLS handshake against a listener using
// that leaf — i.e. the mitmproxy cert path works end to end.
func TestTLSCAAndLeafIssuance(t *testing.T) {
	caOpts := &object.Hash{}
	caResult, errObj := unwrapPair(t, TLSGenerateCA(makeHashObject(map[string]object.Object{
		"common_name": stringObj("Mutant Test CA"),
	})))
	if errObj != nil {
		t.Fatalf("tls_generate_ca: %s", errObj.Message)
	}
	_ = caOpts
	caCertPEM := hashStr(t, caResult, "cert_pem")
	caKeyPEM := hashStr(t, caResult, "key_pem")
	if !strings.Contains(caCertPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("CA cert PEM malformed")
	}

	leafResult, errObj := unwrapPair(t, TLSSignCert(
		stringObj(caCertPEM),
		stringObj(caKeyPEM),
		makeHashObject(map[string]object.Object{
			"common_name": stringObj("localhost"),
			"dns_names":   &object.Array{Elements: []object.Object{stringObj("localhost")}},
			"ip_addresses": &object.Array{Elements: []object.Object{
				stringObj("127.0.0.1"),
			}},
		}),
	))
	if errObj != nil {
		t.Fatalf("tls_sign_cert: %s", errObj.Message)
	}
	leafCertPEM := hashStr(t, leafResult, "cert_pem")
	leafKeyPEM := hashStr(t, leafResult, "key_pem")

	// Start a TLS listener with the signed leaf.
	lnResult, errObj := unwrapPair(t, NetTLSListen(
		stringObj("127.0.0.1:0"),
		stringObj(leafCertPEM),
		stringObj(leafKeyPEM),
	))
	if errObj != nil {
		t.Fatalf("net_tls_listen: %s", errObj.Message)
	}
	lnHandle := lnResult.(*object.Integer).Value
	defer NetListenClose(intObj(lnHandle))

	// Discover the bound address.
	ml, ok := lookupListener(lnHandle)
	if !ok {
		t.Fatal("listener not registered")
	}
	addr := ml.ln.Addr().String()

	// Server goroutine: accept, read one line, echo it back, close.
	done := make(chan struct{})
	go func() {
		defer close(done)
		acc, errObj := unwrapPair(t, NetAccept(intObj(lnHandle), intObj(5000)))
		if errObj != nil {
			t.Errorf("net_accept: %s", errObj.Message)
			return
		}
		if !hashBool(t, acc, "ok") {
			t.Errorf("accept not ok: %s", hashStr(t, acc, "error"))
			return
		}
		connHandle := hashInt(t, acc, "handle")
		readResult, errObj := unwrapPair(t, NetConnRead(intObj(connHandle), intObj(1024), intObj(5000)))
		if errObj != nil {
			t.Errorf("server net_conn_read: %s", errObj.Message)
			return
		}
		got := hashStr(t, readResult, "data")
		NetConnWrite(intObj(connHandle), stringObj("echo:"+got))
		NetConnClose(intObj(connHandle))
	}()

	// Client: connect with the CA pinned as the only trusted root.
	connResult, errObj := unwrapPair(t, NetTLSConnect(
		stringObj(addr),
		intObj(5000),
		makeHashObject(map[string]object.Object{
			"server_name": stringObj("localhost"),
			"ca_cert":     stringObj(caCertPEM),
		}),
	))
	if errObj != nil {
		t.Fatalf("net_tls_connect (CA-pinned): %s", errObj.Message)
	}
	clientHandle := connResult.(*object.Integer).Value

	if _, errObj := unwrapPair(t, NetConnWrite(intObj(clientHandle), stringObj("ping"))); errObj != nil {
		t.Fatalf("client net_conn_write: %s", errObj.Message)
	}
	readResult, errObj := unwrapPair(t, NetConnRead(intObj(clientHandle), intObj(1024), intObj(5000)))
	if errObj != nil {
		t.Fatalf("client net_conn_read: %s", errObj.Message)
	}
	if got := hashStr(t, readResult, "data"); got != "echo:ping" {
		t.Fatalf("unexpected echo: got %q", got)
	}

	// Connection info should report TLS negotiation details.
	infoResult, errObj := unwrapPair(t, NetConnInfo(intObj(clientHandle)))
	if errObj != nil {
		t.Fatalf("net_conn_info: %s", errObj.Message)
	}
	if !hashBool(t, infoResult, "tls") {
		t.Fatalf("expected tls=true in conn info")
	}
	if v := hashStr(t, infoResult, "tls_version"); !strings.HasPrefix(v, "TLS1.") {
		t.Fatalf("unexpected tls_version %q", v)
	}

	NetConnClose(intObj(clientHandle))
	<-done
}

// TestTLSConnectRejectsUntrustedCert confirms verification is enforced by
// default: a client that does not trust the self-signed leaf must fail.
func TestTLSConnectRejectsUntrustedCert(t *testing.T) {
	leafResult, errObj := unwrapPair(t, TLSGenerateCert(makeHashObject(map[string]object.Object{
		"common_name": stringObj("localhost"),
		"ip_addresses": &object.Array{Elements: []object.Object{
			stringObj("127.0.0.1"),
		}},
	})))
	if errObj != nil {
		t.Fatalf("tls_generate_cert: %s", errObj.Message)
	}
	certPEM := hashStr(t, leafResult, "cert_pem")
	keyPEM := hashStr(t, leafResult, "key_pem")

	lnResult, errObj := unwrapPair(t, NetTLSListen(stringObj("127.0.0.1:0"), stringObj(certPEM), stringObj(keyPEM)))
	if errObj != nil {
		t.Fatalf("net_tls_listen: %s", errObj.Message)
	}
	lnHandle := lnResult.(*object.Integer).Value
	defer NetListenClose(intObj(lnHandle))
	ml, _ := lookupListener(lnHandle)
	addr := ml.ln.Addr().String()

	go func() {
		acc, errObj := unwrapPair(t, NetAccept(intObj(lnHandle), intObj(2000)))
		if errObj == nil && hashBool(t, acc, "ok") {
			// Trigger the handshake so the client side actually fails.
			connHandle := hashInt(t, acc, "handle")
			NetConnRead(intObj(connHandle), intObj(16), intObj(1000))
			NetConnClose(intObj(connHandle))
		}
	}()

	_, errObj = unwrapPair(t, NetTLSConnect(stringObj(addr), intObj(2000), makeHashObject(map[string]object.Object{
		"server_name": stringObj("localhost"),
	})))
	if errObj == nil {
		t.Fatal("expected TLS verification to fail against untrusted self-signed cert")
	}
}

// TestPlainListenerRoundTrip exercises the non-TLS socket path.
func TestPlainListenerRoundTrip(t *testing.T) {
	lnResult, errObj := unwrapPair(t, NetListen(stringObj("127.0.0.1:0")))
	if errObj != nil {
		t.Fatalf("net_listen: %s", errObj.Message)
	}
	lnHandle := lnResult.(*object.Integer).Value
	defer NetListenClose(intObj(lnHandle))
	ml, _ := lookupListener(lnHandle)
	addr := ml.ln.Addr().String()

	go func() {
		acc, _ := unwrapPair(t, NetAccept(intObj(lnHandle), intObj(2000)))
		connHandle := hashInt(t, acc, "handle")
		r, _ := unwrapPair(t, NetConnRead(intObj(connHandle), intObj(64), intObj(2000)))
		NetConnWrite(intObj(connHandle), stringObj("srv:"+hashStr(t, r, "data")))
		NetConnClose(intObj(connHandle))
	}()

	connResult, errObj := unwrapPair(t, NetConnect(stringObj(addr), intObj(2000)))
	if errObj != nil {
		t.Fatalf("net_connect: %s", errObj.Message)
	}
	h := connResult.(*object.Integer).Value
	NetConnWrite(intObj(h), stringObj("hi"))
	r, errObj := unwrapPair(t, NetConnRead(intObj(h), intObj(64), intObj(2000)))
	if errObj != nil {
		t.Fatalf("net_conn_read: %s", errObj.Message)
	}
	if got := hashStr(t, r, "data"); got != "srv:hi" {
		t.Fatalf("unexpected data %q", got)
	}
	NetConnClose(intObj(h))
}

// TestTLSUpgradeServerCONNECTFlow exercises the mitmproxy interception path:
// a plain socket is accepted, answered with 200, then upgraded to server-side
// TLS with a CA-signed leaf, and a CA-pinned client completes the handshake.
func TestTLSUpgradeServerCONNECTFlow(t *testing.T) {
	caResult, errObj := unwrapPair(t, TLSGenerateCA(makeHashObject(map[string]object.Object{
		"common_name": stringObj("Intercept CA"),
	})))
	if errObj != nil {
		t.Fatalf("tls_generate_ca: %s", errObj.Message)
	}
	caCertPEM := hashStr(t, caResult, "cert_pem")
	caKeyPEM := hashStr(t, caResult, "key_pem")

	leafResult, errObj := unwrapPair(t, TLSSignCert(stringObj(caCertPEM), stringObj(caKeyPEM), makeHashObject(map[string]object.Object{
		"common_name":  stringObj("localhost"),
		"dns_names":    &object.Array{Elements: []object.Object{stringObj("localhost")}},
		"ip_addresses": &object.Array{Elements: []object.Object{stringObj("127.0.0.1")}},
	})))
	if errObj != nil {
		t.Fatalf("tls_sign_cert: %s", errObj.Message)
	}
	leafCertPEM := hashStr(t, leafResult, "cert_pem")
	leafKeyPEM := hashStr(t, leafResult, "key_pem")

	lnResult, errObj := unwrapPair(t, NetListen(stringObj("127.0.0.1:0")))
	if errObj != nil {
		t.Fatalf("net_listen: %s", errObj.Message)
	}
	lnHandle := lnResult.(*object.Integer).Value
	defer NetListenClose(intObj(lnHandle))
	ml, _ := lookupListener(lnHandle)
	addr := ml.ln.Addr().String()

	done := make(chan struct{})
	go func() {
		defer close(done)
		acc, errObj := unwrapPair(t, NetAccept(intObj(lnHandle), intObj(5000)))
		if errObj != nil || !hashBool(t, acc, "ok") {
			t.Errorf("accept failed")
			return
		}
		connHandle := hashInt(t, acc, "handle")
		// Simulate answering CONNECT, then upgrade to TLS as the target host.
		NetConnWrite(intObj(connHandle), stringObj("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if _, errObj := unwrapPair(t, NetTLSUpgradeServer(intObj(connHandle), stringObj(leafCertPEM), stringObj(leafKeyPEM))); errObj != nil {
			t.Errorf("net_tls_upgrade_server: %s", errObj.Message)
			return
		}
		r, _ := unwrapPair(t, NetConnRead(intObj(connHandle), intObj(64), intObj(5000)))
		NetConnWrite(intObj(connHandle), stringObj("secure:"+hashStr(t, r, "data")))
		NetConnClose(intObj(connHandle))
	}()

	// Client side: open plain, read the 200 line, then upgrade to client TLS.
	connResult, errObj := unwrapPair(t, NetConnect(stringObj(addr), intObj(5000)))
	if errObj != nil {
		t.Fatalf("net_connect: %s", errObj.Message)
	}
	clientHandle := connResult.(*object.Integer).Value
	if _, errObj := unwrapPair(t, NetConnRead(intObj(clientHandle), intObj(128), intObj(5000))); errObj != nil {
		t.Fatalf("reading 200 line: %s", errObj.Message)
	}
	if _, errObj := unwrapPair(t, NetTLSUpgradeClient(intObj(clientHandle), makeHashObject(map[string]object.Object{
		"server_name": stringObj("localhost"),
		"ca_cert":     stringObj(caCertPEM),
	}))); errObj != nil {
		t.Fatalf("net_tls_upgrade_client: %s", errObj.Message)
	}

	NetConnWrite(intObj(clientHandle), stringObj("payload"))
	r, errObj := unwrapPair(t, NetConnRead(intObj(clientHandle), intObj(64), intObj(5000)))
	if errObj != nil {
		t.Fatalf("client read: %s", errObj.Message)
	}
	if got := hashStr(t, r, "data"); got != "secure:payload" {
		t.Fatalf("unexpected decrypted echo: %q", got)
	}
	NetConnClose(intObj(clientHandle))
	<-done
}

// TestNetAcceptTimeout confirms a poll-style accept returns cleanly on timeout.
func TestNetAcceptTimeout(t *testing.T) {
	lnResult, errObj := unwrapPair(t, NetListen(stringObj("127.0.0.1:0")))
	if errObj != nil {
		t.Fatalf("net_listen: %s", errObj.Message)
	}
	lnHandle := lnResult.(*object.Integer).Value
	defer NetListenClose(intObj(lnHandle))

	acc, errObj := unwrapPair(t, NetAccept(intObj(lnHandle), intObj(100)))
	if errObj != nil {
		t.Fatalf("net_accept unexpected hard error: %s", errObj.Message)
	}
	if hashBool(t, acc, "ok") {
		t.Fatal("expected accept to time out with no client")
	}
	if !hashBool(t, acc, "timeout") {
		t.Fatal("expected timeout=true")
	}
}
