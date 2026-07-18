package builtin

// Secure networking primitives for the Mutant language (dev-sec branch).
//
// These builtins expose stream sockets, TLS client/server connections,
// listeners, and an in-process X.509 certificate authority. Together they are
// enough to build interception proxies (mitmproxy-style) and mutually
// authenticated / encrypted channels entirely in Mutant source.
//
// Connections and listeners are reference-counted by an integer handle so a
// Mutant program can hold, pass around, and later close them explicitly.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"mutant/object"
)

// managedConn wraps a live connection. A single bufio.Reader is created lazily
// and reused so byte-level reads (net_conn_read) and HTTP-framed reads
// (http_conn_read_request/response) draw from the same buffered stream and
// never lose bytes to over-reads.
type managedConn struct {
	conn   net.Conn
	reader *bufio.Reader
	isTLS  bool
}

func (mc *managedConn) buffered() *bufio.Reader {
	if mc.reader == nil {
		mc.reader = bufio.NewReader(mc.conn)
	}
	return mc.reader
}

// managedListener keeps the raw *net.TCPListener alongside the (possibly
// TLS-wrapped) accept listener so accept deadlines can be applied.
type managedListener struct {
	ln    net.Listener
	raw   *net.TCPListener
	isTLS bool
}

var connRegistry = struct {
	sync.Mutex
	conns  map[int64]*managedConn
	nextID int64
}{conns: map[int64]*managedConn{}, nextID: 1}

var listenerRegistry = struct {
	sync.Mutex
	listeners map[int64]*managedListener
	nextID    int64
}{listeners: map[int64]*managedListener{}, nextID: 1}

func registerConn(conn net.Conn, isTLS bool) int64 {
	connRegistry.Lock()
	id := connRegistry.nextID
	connRegistry.nextID++
	connRegistry.conns[id] = &managedConn{conn: conn, isTLS: isTLS}
	connRegistry.Unlock()
	return id
}

func lookupConn(id int64) (*managedConn, bool) {
	connRegistry.Lock()
	mc, ok := connRegistry.conns[id]
	connRegistry.Unlock()
	return mc, ok
}

func removeConn(id int64) (*managedConn, bool) {
	connRegistry.Lock()
	mc, ok := connRegistry.conns[id]
	if ok {
		delete(connRegistry.conns, id)
	}
	connRegistry.Unlock()
	return mc, ok
}

func registerListener(ml *managedListener) int64 {
	listenerRegistry.Lock()
	id := listenerRegistry.nextID
	listenerRegistry.nextID++
	listenerRegistry.listeners[id] = ml
	listenerRegistry.Unlock()
	return id
}

func lookupListener(id int64) (*managedListener, bool) {
	listenerRegistry.Lock()
	ml, ok := listenerRegistry.listeners[id]
	listenerRegistry.Unlock()
	return ml, ok
}

func removeListener(id int64) (*managedListener, bool) {
	listenerRegistry.Lock()
	ml, ok := listenerRegistry.listeners[id]
	if ok {
		delete(listenerRegistry.listeners, id)
	}
	listenerRegistry.Unlock()
	return ml, ok
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

// NetConnect opens a plain TCP connection and returns a connection handle.
// net_connect(addr STRING, timeout_ms INTEGER) -> INTEGER handle
func NetConnect(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	addr, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_connect` must be STRING, got %s", args[0].Type()))
	}
	timeoutMs, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_connect` must be INTEGER, got %s", args[1].Type()))
	}

	conn, err := net.DialTimeout("tcp", addr.Value, time.Duration(timeoutMs.Value)*time.Millisecond)
	if err != nil {
		return resultAndError(nil, newError("net_connect: %s", err.Error()))
	}
	return resultAndError(intObj(registerConn(conn, false)), nil)
}

// NetTLSConnect opens a TLS (secure) client connection and returns a handle.
// net_tls_connect(addr STRING, timeout_ms INTEGER, options HASH) -> INTEGER handle
//
// Recognised options: server_name, insecure (BOOL), alpn ([]STRING),
// min_version ("1.0".."1.3"), ca_cert (PEM roots), client_cert + client_key
// (PEM, for mutual TLS).
func NetTLSConnect(args ...object.Object) object.Object {
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	addr, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_tls_connect` must be STRING, got %s", args[0].Type()))
	}
	timeoutMs, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_tls_connect` must be INTEGER, got %s", args[1].Type()))
	}

	var options object.Object
	if len(args) == 3 {
		options = args[2]
	}

	host, _, err := net.SplitHostPort(addr.Value)
	if err != nil {
		host = addr.Value
	}

	cfg := &tls.Config{ServerName: host}
	if errObj := applyClientTLSOptions(cfg, options); errObj != nil {
		return resultAndError(nil, errObj)
	}

	dialer := &net.Dialer{Timeout: time.Duration(timeoutMs.Value) * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr.Value, cfg)
	if err != nil {
		return resultAndError(nil, newError("net_tls_connect: %s", err.Error()))
	}
	return resultAndError(intObj(registerConn(conn, true)), nil)
}

// NetConnWrite writes bytes to a connection. Returns the number written.
// net_conn_write(handle INTEGER, data STRING) -> INTEGER
func NetConnWrite(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_conn_write` must be INTEGER, got %s", args[0].Type()))
	}
	data, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_conn_write` must be STRING, got %s", args[1].Type()))
	}
	mc, ok := lookupConn(handle.Value)
	if !ok {
		return resultAndError(nil, newError("net_conn_write: unknown connection handle %d", handle.Value))
	}
	n, err := mc.conn.Write([]byte(data.Value))
	if err != nil {
		return resultAndError(intObj(int64(n)), newError("net_conn_write: %s", err.Error()))
	}
	return resultAndError(intObj(int64(n)), nil)
}

// NetConnRead reads up to max_bytes from a connection.
// net_conn_read(handle INTEGER, max_bytes INTEGER, timeout_ms INTEGER) -> HASH
// Result: {data, bytes, eof, error}. A timeout is reported as eof=false with a
// non-empty error string, letting proxy loops poll without aborting.
func NetConnRead(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_conn_read` must be INTEGER, got %s", args[0].Type()))
	}
	maxBytes, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_conn_read` must be INTEGER, got %s", args[1].Type()))
	}
	timeoutMs, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `net_conn_read` must be INTEGER, got %s", args[2].Type()))
	}
	if maxBytes.Value <= 0 {
		return resultAndError(nil, newError("argument 2 to `net_conn_read` must be > 0, got %d", maxBytes.Value))
	}
	mc, ok := lookupConn(handle.Value)
	if !ok {
		return resultAndError(nil, newError("net_conn_read: unknown connection handle %d", handle.Value))
	}

	if timeoutMs.Value > 0 {
		_ = mc.conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutMs.Value) * time.Millisecond))
	} else {
		_ = mc.conn.SetReadDeadline(time.Time{})
	}

	buf := make([]byte, maxBytes.Value)
	n, err := mc.buffered().Read(buf)

	eof := err == io.EOF
	errMsg := ""
	if err != nil && err != io.EOF {
		errMsg = err.Error()
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"data":  stringObj(string(buf[:n])),
		"bytes": intObj(int64(n)),
		"eof":   boolObj(eof),
		"error": stringObj(errMsg),
	}), nil)
}

// NetConnClose closes a connection and releases its handle.
// net_conn_close(handle INTEGER) -> BOOL
func NetConnClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_conn_close` must be INTEGER, got %s", args[0].Type()))
	}
	mc, ok := removeConn(handle.Value)
	if !ok {
		return resultAndError(boolObj(false), nil)
	}
	if err := mc.conn.Close(); err != nil {
		return resultAndError(boolObj(true), newError("net_conn_close: %s", err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

// NetConnInfo reports addressing and, for TLS, the negotiated session.
// net_conn_info(handle INTEGER) -> HASH
func NetConnInfo(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_conn_info` must be INTEGER, got %s", args[0].Type()))
	}
	mc, ok := lookupConn(handle.Value)
	if !ok {
		return resultAndError(nil, newError("net_conn_info: unknown connection handle %d", handle.Value))
	}

	fields := map[string]object.Object{
		"handle":      intObj(handle.Value),
		"tls":         boolObj(mc.isTLS),
		"local_addr":  stringObj(addrString(mc.conn.LocalAddr())),
		"remote_addr": stringObj(addrString(mc.conn.RemoteAddr())),
	}

	if tlsConn, ok := mc.conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		fields["tls_version"] = stringObj(tlsVersionToString(state.Version))
		fields["cipher"] = stringObj(tls.CipherSuiteName(state.CipherSuite))
		fields["alpn"] = stringObj(state.NegotiatedProtocol)
		fields["server_name"] = stringObj(state.ServerName)
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			fields["peer_subject"] = stringObj(cert.Subject.String())
			fields["peer_issuer"] = stringObj(cert.Issuer.String())
		}
	}

	return resultAndError(makeHashObject(fields), nil)
}

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

// NetListen opens a plain TCP listener.
// net_listen(addr STRING) -> INTEGER handle
func NetListen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	addr, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_listen` must be STRING, got %s", args[0].Type()))
	}
	raw, errObj := listenTCP("net_listen", addr.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	id := registerListener(&managedListener{ln: raw, raw: raw, isTLS: false})
	return resultAndError(intObj(id), nil)
}

// NetTLSListen opens a TLS-terminating listener from a PEM cert/key pair.
// net_tls_listen(addr STRING, cert_pem STRING, key_pem STRING, options HASH) -> INTEGER handle
// Recognised options: alpn ([]STRING), min_version, client_ca (PEM, requires
// and verifies client certificates for mutual TLS).
func NetTLSListen(args ...object.Object) object.Object {
	if len(args) < 3 || len(args) > 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3 or 4", len(args)))
	}
	addr, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_tls_listen` must be STRING, got %s", args[0].Type()))
	}
	certPEM, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_tls_listen` must be STRING, got %s", args[1].Type()))
	}
	keyPEM, ok := args[2].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `net_tls_listen` must be STRING, got %s", args[2].Type()))
	}
	var options object.Object
	if len(args) == 4 {
		options = args[3]
	}

	cert, err := tls.X509KeyPair([]byte(certPEM.Value), []byte(keyPEM.Value))
	if err != nil {
		return resultAndError(nil, newError("net_tls_listen: invalid cert/key pair: %s", err.Error()))
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if errObj := applyServerTLSOptions(cfg, options); errObj != nil {
		return resultAndError(nil, errObj)
	}

	raw, errObj := listenTCP("net_tls_listen", addr.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	tlsLn := tls.NewListener(raw, cfg)
	id := registerListener(&managedListener{ln: tlsLn, raw: raw, isTLS: true})
	return resultAndError(intObj(id), nil)
}

// NetAccept accepts one connection from a listener.
// net_accept(listener_handle INTEGER, timeout_ms INTEGER) -> HASH
// Result: {ok, handle, remote_addr, timeout, error}. timeout_ms <= 0 blocks
// indefinitely; on timeout ok=false and timeout=true.
func NetAccept(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_accept` must be INTEGER, got %s", args[0].Type()))
	}
	timeoutMs, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_accept` must be INTEGER, got %s", args[1].Type()))
	}
	ml, ok := lookupListener(handle.Value)
	if !ok {
		return resultAndError(nil, newError("net_accept: unknown listener handle %d", handle.Value))
	}

	if ml.raw != nil {
		if timeoutMs.Value > 0 {
			_ = ml.raw.SetDeadline(time.Now().Add(time.Duration(timeoutMs.Value) * time.Millisecond))
		} else {
			_ = ml.raw.SetDeadline(time.Time{})
		}
	}

	conn, err := ml.ln.Accept()
	if err != nil {
		if netErr, isNet := err.(net.Error); isNet && netErr.Timeout() {
			return resultAndError(makeHashObject(map[string]object.Object{
				"ok":      boolObj(false),
				"timeout": boolObj(true),
				"error":   stringObj(err.Error()),
			}), nil)
		}
		return resultAndError(makeHashObject(map[string]object.Object{
			"ok":      boolObj(false),
			"timeout": boolObj(false),
			"error":   stringObj(err.Error()),
		}), newError("net_accept: %s", err.Error()))
	}

	connID := registerConn(conn, ml.isTLS)
	return resultAndError(makeHashObject(map[string]object.Object{
		"ok":          boolObj(true),
		"timeout":     boolObj(false),
		"handle":      intObj(connID),
		"remote_addr": stringObj(addrString(conn.RemoteAddr())),
		"error":       stringObj(""),
	}), nil)
}

// NetListenClose closes a listener and releases its handle.
// net_listen_close(handle INTEGER) -> BOOL
func NetListenClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_listen_close` must be INTEGER, got %s", args[0].Type()))
	}
	ml, ok := removeListener(handle.Value)
	if !ok {
		return resultAndError(boolObj(false), nil)
	}
	if err := ml.ln.Close(); err != nil {
		return resultAndError(boolObj(true), newError("net_listen_close: %s", err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

// prefixedConn lets a TLS handshake consume any bytes already pulled into a
// buffered reader before the upgrade, then fall through to the raw socket.
type prefixedConn struct {
	net.Conn
	prefix *bufio.Reader
}

func (p *prefixedConn) Read(b []byte) (int, error) {
	if p.prefix != nil && p.prefix.Buffered() > 0 {
		return p.prefix.Read(b)
	}
	return p.Conn.Read(b)
}

// NetTLSUpgradeServer wraps an already-accepted connection in a server-side TLS
// session using a leaf cert/key. This completes an interception proxy's CONNECT
// tunnel: answer 200 to the client on the plain socket, then TLS-handshake as
// the requested host with a CA-signed certificate.
// net_tls_upgrade_server(handle INTEGER, cert_pem STRING, key_pem STRING, options HASH) -> HASH
func NetTLSUpgradeServer(args ...object.Object) object.Object {
	if len(args) < 3 || len(args) > 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3 or 4", len(args)))
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_tls_upgrade_server` must be INTEGER, got %s", args[0].Type()))
	}
	certPEM, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_tls_upgrade_server` must be STRING, got %s", args[1].Type()))
	}
	keyPEM, ok := args[2].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `net_tls_upgrade_server` must be STRING, got %s", args[2].Type()))
	}
	var options object.Object
	if len(args) == 4 {
		options = args[3]
	}

	mc, ok := lookupConn(handle.Value)
	if !ok {
		return resultAndError(nil, newError("net_tls_upgrade_server: unknown connection handle %d", handle.Value))
	}
	if mc.isTLS {
		return resultAndError(nil, newError("net_tls_upgrade_server: connection %d is already TLS", handle.Value))
	}

	cert, err := tls.X509KeyPair([]byte(certPEM.Value), []byte(keyPEM.Value))
	if err != nil {
		return resultAndError(nil, newError("net_tls_upgrade_server: invalid cert/key pair: %s", err.Error()))
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if errObj := applyServerTLSOptions(cfg, options); errObj != nil {
		return resultAndError(nil, errObj)
	}

	tlsConn := tls.Server(&prefixedConn{Conn: mc.conn, prefix: mc.reader}, cfg)
	if errObj := performHandshake("net_tls_upgrade_server", mc.conn, tlsConn, options); errObj != nil {
		return resultAndError(nil, errObj)
	}
	upgradeManagedConn(mc, tlsConn)
	return resultAndError(tlsHandshakeInfo(tlsConn), nil)
}

// NetTLSUpgradeClient wraps an already-open connection in a client-side TLS
// session (STARTTLS-style, or the upstream leg of an interception tunnel).
// net_tls_upgrade_client(handle INTEGER, options HASH) -> HASH
func NetTLSUpgradeClient(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_tls_upgrade_client` must be INTEGER, got %s", args[0].Type()))
	}
	var options object.Object
	if len(args) == 2 {
		options = args[1]
	}

	mc, ok := lookupConn(handle.Value)
	if !ok {
		return resultAndError(nil, newError("net_tls_upgrade_client: unknown connection handle %d", handle.Value))
	}
	if mc.isTLS {
		return resultAndError(nil, newError("net_tls_upgrade_client: connection %d is already TLS", handle.Value))
	}

	cfg := &tls.Config{}
	if errObj := applyClientTLSOptions(cfg, options); errObj != nil {
		return resultAndError(nil, errObj)
	}
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(addrString(mc.conn.RemoteAddr())); err == nil {
			cfg.ServerName = host
		}
	}

	tlsConn := tls.Client(&prefixedConn{Conn: mc.conn, prefix: mc.reader}, cfg)
	if errObj := performHandshake("net_tls_upgrade_client", mc.conn, tlsConn, options); errObj != nil {
		return resultAndError(nil, errObj)
	}
	upgradeManagedConn(mc, tlsConn)
	return resultAndError(tlsHandshakeInfo(tlsConn), nil)
}

func performHandshake(opName string, raw net.Conn, tlsConn *tls.Conn, options object.Object) *object.Error {
	timeoutMs := optInt(options, "handshake_timeout_ms", 15000)
	if timeoutMs > 0 {
		_ = raw.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
	}
	err := tlsConn.Handshake()
	_ = raw.SetDeadline(time.Time{})
	if err != nil {
		return newError("%s: handshake failed: %s", opName, err.Error())
	}
	return nil
}

func upgradeManagedConn(mc *managedConn, tlsConn *tls.Conn) {
	mc.conn = tlsConn
	mc.reader = nil
	mc.isTLS = true
}

func tlsHandshakeInfo(tlsConn *tls.Conn) *object.Hash {
	state := tlsConn.ConnectionState()
	fields := map[string]object.Object{
		"ok":          boolObj(true),
		"tls_version": stringObj(tlsVersionToString(state.Version)),
		"cipher":      stringObj(tls.CipherSuiteName(state.CipherSuite)),
		"alpn":        stringObj(state.NegotiatedProtocol),
		"server_name": stringObj(state.ServerName),
	}
	if len(state.PeerCertificates) > 0 {
		fields["peer_subject"] = stringObj(state.PeerCertificates[0].Subject.String())
	}
	return makeHashObject(fields)
}

// ---------------------------------------------------------------------------
// X.509 certificate authority (mitmproxy building blocks)
// ---------------------------------------------------------------------------

// TLSGenerateCA creates a self-signed CA certificate + private key (PEM).
// tls_generate_ca(options HASH) -> HASH {cert_pem, key_pem, serial}
// Options: common_name, organization, days (validity, default 3650).
func TLSGenerateCA(args ...object.Object) object.Object {
	options := optionsArg(args)
	commonName := optString(options, "common_name", "Mutant Dev CA")
	org := optString(options, "organization", "Mutant")
	days := optInt(options, "days", 3650)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return resultAndError(nil, newError("tls_generate_ca: key generation failed: %s", err.Error()))
	}
	serial, err := randomSerial()
	if err != nil {
		return resultAndError(nil, newError("tls_generate_ca: %s", err.Error()))
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{org}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, int(days)),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return resultAndError(nil, newError("tls_generate_ca: certificate creation failed: %s", err.Error()))
	}

	certPEM, keyPEM, errObj := encodeCertAndKey("tls_generate_ca", der, key)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"cert_pem": stringObj(certPEM),
		"key_pem":  stringObj(keyPEM),
		"serial":   stringObj(serial.String()),
	}), nil)
}

// TLSGenerateCert creates a self-signed leaf/server certificate + key (PEM).
// tls_generate_cert(options HASH) -> HASH {cert_pem, key_pem, serial}
// Options: common_name, organization, dns_names ([]STRING), ip_addresses
// ([]STRING), days (default 825).
func TLSGenerateCert(args ...object.Object) object.Object {
	options := optionsArg(args)
	template, errObj := leafTemplate("tls_generate_cert", options)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return resultAndError(nil, newError("tls_generate_cert: key generation failed: %s", err.Error()))
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return resultAndError(nil, newError("tls_generate_cert: certificate creation failed: %s", err.Error()))
	}

	certPEM, keyPEM, errObj := encodeCertAndKey("tls_generate_cert", der, key)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"cert_pem": stringObj(certPEM),
		"key_pem":  stringObj(keyPEM),
		"serial":   stringObj(template.SerialNumber.String()),
	}), nil)
}

// TLSSignCert issues a leaf certificate signed by a CA. This is the core of an
// interception proxy: mint a per-host certificate on demand, trusted because
// the client trusts the CA.
// tls_sign_cert(ca_cert_pem STRING, ca_key_pem STRING, options HASH) -> HASH {cert_pem, key_pem, serial}
// Options are identical to tls_generate_cert.
func TLSSignCert(args ...object.Object) object.Object {
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	caCertPEM, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `tls_sign_cert` must be STRING, got %s", args[0].Type()))
	}
	caKeyPEM, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `tls_sign_cert` must be STRING, got %s", args[1].Type()))
	}
	var options object.Object
	if len(args) == 3 {
		options = args[2]
	}

	caCert, err := parseCertPEM(caCertPEM.Value)
	if err != nil {
		return resultAndError(nil, newError("tls_sign_cert: invalid CA cert: %s", err.Error()))
	}
	caKey, err := parseECKeyPEM(caKeyPEM.Value)
	if err != nil {
		return resultAndError(nil, newError("tls_sign_cert: invalid CA key: %s", err.Error()))
	}

	template, errObj := leafTemplate("tls_sign_cert", options)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return resultAndError(nil, newError("tls_sign_cert: key generation failed: %s", err.Error()))
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return resultAndError(nil, newError("tls_sign_cert: certificate signing failed: %s", err.Error()))
	}

	certPEM, keyPEM, errObj := encodeCertAndKey("tls_sign_cert", der, leafKey)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"cert_pem": stringObj(certPEM),
		"key_pem":  stringObj(keyPEM),
		"serial":   stringObj(template.SerialNumber.String()),
	}), nil)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func listenTCP(opName string, addr string) (*net.TCPListener, *object.Error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, newError("%s: %s", opName, err.Error())
	}
	raw, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, newError("%s: %s", opName, err.Error())
	}
	return raw, nil
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func optionsArg(args []object.Object) object.Object {
	if len(args) >= 1 {
		return args[0]
	}
	return nil
}

func objField(obj object.Object, key string) (object.Object, bool) {
	switch v := obj.(type) {
	case *object.Hash:
		return hashValueByStringKey(v, key)
	case *object.Struct:
		val, ok := v.Fields[key]
		return val, ok
	}
	return nil, false
}

func optString(obj object.Object, key, fallback string) string {
	if val, ok := objField(obj, key); ok {
		if s, ok := val.(*object.String); ok {
			return s.Value
		}
	}
	return fallback
}

func optBool(obj object.Object, key string, fallback bool) bool {
	if val, ok := objField(obj, key); ok {
		if b, ok := val.(*object.Boolean); ok {
			return b.Value
		}
	}
	return fallback
}

func optInt(obj object.Object, key string, fallback int64) int64 {
	if val, ok := objField(obj, key); ok {
		if i, ok := val.(*object.Integer); ok {
			return i.Value
		}
	}
	return fallback
}

func optStringSlice(obj object.Object, key string) []string {
	val, ok := objField(obj, key)
	if !ok {
		return nil
	}
	arr, ok := val.(*object.Array)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr.Elements))
	for _, el := range arr.Elements {
		if s, ok := el.(*object.String); ok {
			out = append(out, s.Value)
		}
	}
	return out
}

func tlsVersionFromString(name string) (uint16, bool) {
	switch strings.TrimSpace(name) {
	case "1.0", "TLS1.0", "TLS1_0":
		return tls.VersionTLS10, true
	case "1.1", "TLS1.1", "TLS1_1":
		return tls.VersionTLS11, true
	case "1.2", "TLS1.2", "TLS1_2":
		return tls.VersionTLS12, true
	case "1.3", "TLS1.3", "TLS1_3":
		return tls.VersionTLS13, true
	default:
		return 0, false
	}
}

func applyClientTLSOptions(cfg *tls.Config, options object.Object) *object.Error {
	if options == nil {
		return nil
	}
	if sni := optString(options, "server_name", ""); sni != "" {
		cfg.ServerName = sni
	}
	cfg.InsecureSkipVerify = optBool(options, "insecure", false)
	if alpn := optStringSlice(options, "alpn"); len(alpn) > 0 {
		cfg.NextProtos = alpn
	}
	if mv := optString(options, "min_version", ""); mv != "" {
		version, ok := tlsVersionFromString(mv)
		if !ok {
			return newError("net_tls_connect: unknown min_version %q", mv)
		}
		cfg.MinVersion = version
	}
	if caPEM := optString(options, "ca_cert", ""); caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return newError("net_tls_connect: ca_cert did not contain a valid PEM certificate")
		}
		cfg.RootCAs = pool
	}
	clientCert := optString(options, "client_cert", "")
	clientKey := optString(options, "client_key", "")
	if clientCert != "" && clientKey != "" {
		cert, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		if err != nil {
			return newError("net_tls_connect: invalid client_cert/client_key: %s", err.Error())
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return nil
}

func applyServerTLSOptions(cfg *tls.Config, options object.Object) *object.Error {
	if options == nil {
		return nil
	}
	if alpn := optStringSlice(options, "alpn"); len(alpn) > 0 {
		cfg.NextProtos = alpn
	}
	if mv := optString(options, "min_version", ""); mv != "" {
		version, ok := tlsVersionFromString(mv)
		if !ok {
			return newError("net_tls_listen: unknown min_version %q", mv)
		}
		cfg.MinVersion = version
	}
	if clientCA := optString(options, "client_ca", ""); clientCA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(clientCA)) {
			return newError("net_tls_listen: client_ca did not contain a valid PEM certificate")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func leafTemplate(opName string, options object.Object) (*x509.Certificate, *object.Error) {
	commonName := optString(options, "common_name", "localhost")
	org := optString(options, "organization", "Mutant")
	days := optInt(options, "days", 825)

	serial, err := randomSerial()
	if err != nil {
		return nil, newError("%s: %s", opName, err.Error())
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{org}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, int(days)),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	dnsNames := optStringSlice(options, "dns_names")
	if len(dnsNames) == 0 && commonName != "" {
		dnsNames = []string{commonName}
	}
	template.DNSNames = dnsNames

	for _, ipStr := range optStringSlice(options, "ip_addresses") {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	return template, nil
}

func encodeCertAndKey(opName string, certDER []byte, key *ecdsa.PrivateKey) (string, string, *object.Error) {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", newError("%s: key encoding failed: %s", opName, err.Error())
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM), nil
}

func parseCertPEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errPEMNotFound
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseECKeyPEM(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errPEMNotFound
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

var errPEMNotFound = &pemError{}

type pemError struct{}

func (*pemError) Error() string { return "no PEM block found" }
