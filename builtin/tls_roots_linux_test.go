//go:build linux

package builtin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mutant/object"
)

// TestTheTLSClientsDoNotTrustTheCertificateVariables holds https requests,
// net_tls_connect and net_tls_upgrade_client to the system's certificate
// authorities. On Linux crypto/x509 takes the system's store from the file
// SSL_CERT_FILE names and the directories SSL_CERT_DIR names, when they are
// set, so whoever set the examiner's environment chose whom Mutant trusted
// (M26-NET-010).
//
// crypto/x509 reads the store once, the first time a certificate in the
// process is verified against it, so the handshakes below prove something
// only when this test runs before any other verification does -- on its own,
// or first. That the clients are handed a store of their own holds in any
// order.
func TestTheTLSClientsDoNotTrustTheCertificateVariables(t *testing.T) {
	if roots, err := clientRootCAs(); err != nil || roots == nil {
		t.Fatalf("the system's certificate authorities: %v, %v; want a store read from %v and %v",
			roots, err, linuxCertFiles, linuxCertDirectories)
	}
	client, err := httpClient()
	if err != nil {
		t.Fatalf("build the client: %v", err)
	}
	if transport, ok := client.Transport.(*http.Transport); !ok || transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.RootCAs == nil {
		t.Errorf("the http_* builtins' transport leaves the certificate authorities to crypto/x509")
	}

	authority, leaf := plantedAuthority(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "planted.pem"), authority, 0o600); err != nil {
		t.Fatal(err)
	}
	variables := map[string]string{"SSL_CERT_FILE": filepath.Join(dir, "planted.pem"), "SSL_CERT_DIR": dir}
	for name, value := range variables {
		t.Setenv(name, value)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "trusted-by-the-environment")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	addr := server.Listener.Addr().String()

	// The authority a script names is trusted, so a refusal below is the
	// environment's authority going unheard, not a server nothing would trust.
	named := makeHashObject(map[string]object.Object{"ca_cert": stringObj(string(authority))})
	handle, errObj := unwrapPairNoFatal(NetTLSConnect(stringObj(addr), intObj(5000), named))
	if errObj != nil {
		t.Fatalf("net_tls_connect with the authority named in ca_cert: %s", errObj.Inspect())
	}
	NetConnClose(handle)

	if result, errObj := unwrapPairNoFatal(HttpGet(stringObj(server.URL))); errObj == nil {
		t.Errorf("http_get trusted a certificate only the authority SSL_CERT_FILE names signed: %s", result.Inspect())
	}
	if handle, errObj := unwrapPairNoFatal(NetTLSConnect(stringObj(addr), intObj(5000))); errObj == nil {
		NetConnClose(handle)
		t.Errorf("net_tls_connect trusted a certificate only the authority SSL_CERT_FILE names signed")
	}
	conn, errObj := unwrapPairNoFatal(NetConnect(stringObj(addr), intObj(5000)))
	if errObj != nil {
		t.Fatalf("net_connect: %s", errObj.Inspect())
	}
	defer NetConnClose(conn)
	if _, errObj := unwrapPairNoFatal(NetTLSUpgradeClient(conn)); errObj == nil {
		t.Errorf("net_tls_upgrade_client trusted a certificate only the authority SSL_CERT_FILE names signed")
	}
}

// TestTheSystemStoreIsTheOneCryptoX509Reads holds clientRootCAs to crypto/x509's
// own reading of the system's store with neither variable set, on the machine
// the test runs on. TestTheLinuxCertificateLocationsAreGos holds the places
// read; this holds what is read from them.
func TestTheSystemStoreIsTheOneCryptoX509Reads(t *testing.T) {
	for _, name := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		t.Setenv(name, "")
	}
	system, err := x509.SystemCertPool()
	if err != nil {
		t.Fatalf("crypto/x509's store: %v", err)
	}
	ours, err := clientRootCAs()
	if err != nil {
		t.Fatalf("Mutant's store: %v", err)
	}
	if !ours.Equal(system) {
		t.Errorf("Mutant reads another store from %v and %v than crypto/x509 does", linuxCertFiles, linuxCertDirectories)
	}
}

// plantedAuthority makes a certificate authority, PEM-encoded, and a server
// certificate for 127.0.0.1 that it signed.
func plantedAuthority(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Planted by the environment"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}
