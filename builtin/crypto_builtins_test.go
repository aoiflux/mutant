package builtin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"mutant/object"
)

func makeTestCertPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(12345),
		Subject:               pkix.Name{CommonName: "mutant.test", Organization: []string{"MutantOrg"}},
		NotBefore:             time.Unix(1_700_000_000, 0),
		NotAfter:              time.Unix(1_900_000_000, 0),
		IsCA:                  true,
		DNSNames:              []string{"mutant.test", "www.mutant.test"},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestX509Parse(t *testing.T) {
	certPEM := makeTestCertPEM(t)
	payload, errObj := unwrapPair(t, X509Parse(stringObj(certPEM)))
	if errObj != nil {
		t.Fatalf("x509_parse error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)
	get := func(k string) object.Object { return h.Pairs[(&object.String{Value: k}).HashKey()].Value }

	if !get("is_ca").(*object.Boolean).Value {
		t.Fatal("expected is_ca true")
	}
	if get("serial").(*object.String).Value != "12345" {
		t.Fatalf("serial = %s", get("serial").(*object.String).Value)
	}
	dns := get("dns_names").(*object.Array)
	if len(dns.Elements) != 2 {
		t.Fatalf("dns_names = %s", dns.Inspect())
	}
	if len(get("sha256").(*object.String).Value) != 64 {
		t.Fatal("sha256 fingerprint wrong length")
	}
	if _, errObj := unwrapPair(t, X509Parse(stringObj("garbage"))); errObj == nil {
		t.Fatal("x509_parse of garbage should error")
	}
}

func TestAESRoundTrip(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef" // 32 bytes -> AES-256
	plaintext := "attack at dawn \x00\xff"

	ctPayload, errObj := unwrapPair(t, AESEncrypt(stringObj(key), stringObj(plaintext)))
	if errObj != nil {
		t.Fatalf("aes_encrypt error: %s", errObj.Inspect())
	}
	ct := ctPayload.(*object.String).Value

	ptPayload, errObj := unwrapPair(t, AESDecrypt(stringObj(key), stringObj(ct)))
	if errObj != nil {
		t.Fatalf("aes_decrypt error: %s", errObj.Inspect())
	}
	if ptPayload.(*object.String).Value != plaintext {
		t.Fatalf("round-trip mismatch: %q", ptPayload.(*object.String).Value)
	}

	// Wrong key fails authentication.
	if _, errObj := unwrapPair(t, AESDecrypt(stringObj("fedcba9876543210fedcba9876543210"), stringObj(ct))); errObj == nil {
		t.Fatal("aes_decrypt with wrong key should error")
	}
	// Bad key size errors.
	if _, errObj := unwrapPair(t, AESEncrypt(stringObj("shortkey"), stringObj("x"))); errObj == nil {
		t.Fatal("aes_encrypt with bad key size should error")
	}
}

func TestJWTDecode(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"Mutant","admin":true}`))
	token := header + "." + payload + ".fakesignature"

	res, errObj := unwrapPair(t, JWTDecode(stringObj(token)))
	if errObj != nil {
		t.Fatalf("jwt_decode error: %s", errObj.Inspect())
	}
	h := res.(*object.Hash)
	if h.Pairs[(&object.String{Value: "algorithm"}).HashKey()].Value.(*object.String).Value != "HS256" {
		t.Fatal("wrong algorithm")
	}
	if !h.Pairs[(&object.String{Value: "signature_present"}).HashKey()].Value.(*object.Boolean).Value {
		t.Fatal("signature should be present")
	}
	if h.Pairs[(&object.String{Value: "verified"}).HashKey()].Value.(*object.Boolean).Value {
		t.Fatal("verified must be false (we do not verify)")
	}
	claims := h.Pairs[(&object.String{Value: "claims"}).HashKey()].Value.(*object.Hash)
	if claims.Pairs[(&object.String{Value: "name"}).HashKey()].Value.(*object.String).Value != "Mutant" {
		t.Fatal("claims.name not decoded")
	}

	if _, errObj := unwrapPair(t, JWTDecode(stringObj("notajwt"))); errObj == nil {
		t.Fatal("jwt_decode of non-jwt should error")
	}
}

func TestPEMDecode(t *testing.T) {
	certPEM := makeTestCertPEM(t)
	res, errObj := unwrapPair(t, PEMDecode(stringObj(certPEM)))
	if errObj != nil {
		t.Fatalf("pem_decode error: %s", errObj.Inspect())
	}
	h := res.(*object.Hash)
	if h.Pairs[(&object.String{Value: "type"}).HashKey()].Value.(*object.String).Value != "CERTIFICATE" {
		t.Fatal("pem type should be CERTIFICATE")
	}
	if h.Pairs[(&object.String{Value: "size"}).HashKey()].Value.(*object.Integer).Value <= 0 {
		t.Fatal("pem der size should be > 0")
	}
	if _, errObj := unwrapPair(t, PEMDecode(stringObj("no pem here"))); errObj == nil {
		t.Fatal("pem_decode without a block should error")
	}
}
