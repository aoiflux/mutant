package builtin

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"

	"mutant/object"
)

func TestEmailParseAndHeaders(t *testing.T) {
	raw := testRawSimpleEmail()

	parsedPayload, errObj := unwrapPair(t, EmailParse(stringObj(raw)))
	if errObj != nil {
		t.Fatalf("email_parse error: %s", errObj.Inspect())
	}
	parsed := efMustHash(t, parsedPayload)
	if efMustHashString(t, parsed, "subject") != "Test message" {
		t.Fatalf("unexpected subject")
	}
	if !strings.Contains(efMustHashString(t, parsed, "text"), "Hello analyst") {
		t.Fatalf("missing text body")
	}

	headersPayload, errObj := unwrapPair(t, EmailHeaders(stringObj(raw)))
	if errObj != nil {
		t.Fatalf("email_headers error: %s", errObj.Inspect())
	}
	headers := efMustHash(t, headersPayload)
	fromObj := efMustHashValue(t, headers, "From")
	fromArr, ok := fromObj.(*object.Array)
	if !ok || len(fromArr.Elements) == 0 {
		t.Fatalf("From header missing or invalid")
	}
}

func TestEmailAttachments(t *testing.T) {
	raw := testRawMultipartEmailWithAttachment()

	payload, errObj := unwrapPair(t, EmailAttachments(stringObj(raw)))
	if errObj != nil {
		t.Fatalf("email_attachments error: %s", errObj.Inspect())
	}
	arr, ok := payload.(*object.Array)
	if !ok {
		t.Fatalf("attachments payload type: %T", payload)
	}
	if len(arr.Elements) != 1 {
		t.Fatalf("expected one attachment, got=%d", len(arr.Elements))
	}

	att, ok := arr.Elements[0].(*object.Hash)
	if !ok {
		t.Fatalf("attachment entry type: %T", arr.Elements[0])
	}
	if efMustHashString(t, att, "filename") != "ioc.txt" {
		t.Fatalf("unexpected attachment filename")
	}
	if efMustHashString(t, att, "sha256") == "" {
		t.Fatalf("expected attachment hash")
	}
}

func TestEmailSPFDKIMAndURLs(t *testing.T) {
	raw := testRawSimpleEmail()

	// Keep the test hermetic: no real DNS. The sample's DKIM-Signature is
	// malformed so it fails before any key lookup; the DMARC lookup resolves to
	// "not found" and degrades gracefully.
	restore := dkimLookupTXT
	dkimLookupTXT = func(name string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	defer func() { dkimLookupTXT = restore }()

	spfPayload, errObj := unwrapPair(t, EmailSPFDKIM(stringObj(raw)))
	if errObj != nil {
		t.Fatalf("email_spf_dkim error: %s", errObj.Inspect())
	}
	spfHash := efMustHash(t, spfPayload)
	if efMustHashString(t, spfHash, "spf") != "pass" {
		t.Fatalf("expected SPF pass (reported by receiving MTA)")
	}
	// The sample message carries a malformed DKIM-Signature (no b=/bh=/h= tags).
	// Real cryptographic verification MUST NOT report it as a pass, even though
	// the receiving MTA's Authentication-Results claimed dkim=pass.
	if got := efMustHashString(t, spfHash, "dkim"); got == "pass" {
		t.Fatalf("malformed DKIM signature must not verify as pass, got=%q", got)
	}
	if efMustHashString(t, spfHash, "dkim_reported") != "pass" {
		t.Fatalf("expected reported dkim=pass from Authentication-Results")
	}

	urlsPayload, errObj := unwrapPair(t, EmailURLs(stringObj(raw)))
	if errObj != nil {
		t.Fatalf("email_urls error: %s", errObj.Inspect())
	}
	urls, ok := urlsPayload.(*object.Array)
	if !ok {
		t.Fatalf("urls payload type: %T", urlsPayload)
	}
	if len(urls.Elements) < 2 {
		t.Fatalf("expected at least two URLs, got=%d", len(urls.Elements))
	}
}

func TestEmailDKIMRealVerification(t *testing.T) {
	// Generate a signing key, sign a message, publish the matching public key
	// through an injected offline resolver, and assert real verification passes.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %s", err)
	}

	unsigned := "From: sender@example.com\r\n" +
		"To: analyst@example.com\r\n" +
		"Subject: Signed message\r\n" +
		"Date: Mon, 01 Jul 2026 10:00:00 +0000\r\n" +
		"\r\n" +
		"Body under signature.\r\n"

	var signed bytes.Buffer
	signOpts := &dkim.SignOptions{
		Domain:                 "example.com",
		Selector:               "mail",
		Signer:                 key,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             []string{"From", "To", "Subject", "Date"},
	}
	if err := dkim.Sign(&signed, strings.NewReader(unsigned), signOpts); err != nil {
		t.Fatalf("sign: %s", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %s", err)
	}
	txtRecord := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pubDER)

	restore := dkimLookupTXT
	dkimLookupTXT = func(name string) ([]string, error) {
		if name == "mail._domainkey.example.com" {
			return []string{txtRecord}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	defer func() { dkimLookupTXT = restore }()

	payload, errObj := unwrapPair(t, EmailSPFDKIM(stringObj(signed.String())))
	if errObj != nil {
		t.Fatalf("email_spf_dkim error: %s", errObj.Inspect())
	}
	hash := efMustHash(t, payload)
	if got := efMustHashString(t, hash, "dkim"); got != "pass" {
		t.Fatalf("expected real DKIM pass, got=%q", got)
	}
	if !efMustHashBool(t, hash, "dkim_aligned") {
		t.Fatalf("expected DKIM signature aligned with From domain")
	}

	// Tampering with the signed body must break verification.
	tampered := strings.Replace(signed.String(), "Body under signature.", "Body was modified.", 1)
	payload2, errObj := unwrapPair(t, EmailSPFDKIM(stringObj(tampered)))
	if errObj != nil {
		t.Fatalf("email_spf_dkim error: %s", errObj.Inspect())
	}
	if got := efMustHashString(t, efMustHash(t, payload2), "dkim"); got == "pass" {
		t.Fatalf("tampered body must not verify as pass, got=%q", got)
	}
}

func TestEmailBuiltinArgumentErrors(t *testing.T) {
	tests := []struct {
		name string
		call func() object.Object
	}{
		{name: "email_parse bad type", call: func() object.Object { return EmailParse(intObj(1)) }},
		{name: "email_headers bad type", call: func() object.Object { return EmailHeaders(intObj(1)) }},
		{name: "email_attachments bad type", call: func() object.Object { return EmailAttachments(intObj(1)) }},
		{name: "email_spf_dkim bad type", call: func() object.Object { return EmailSPFDKIM(intObj(1)) }},
		{name: "email_urls bad type", call: func() object.Object { return EmailURLs(intObj(1)) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errObj := unwrapPair(t, tt.call())
			if errObj == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func testRawSimpleEmail() string {
	return "From: sender@example.com\r\n" +
		"To: analyst@example.com\r\n" +
		"Subject: Test message\r\n" +
		"Date: Mon, 01 Jul 2026 10:00:00 +0000\r\n" +
		"Message-ID: <msg-1@example.com>\r\n" +
		"Received-SPF: pass (example.com: domain of sender@example.com designates 192.0.2.1 as permitted sender)\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail;\r\n" +
		"Authentication-Results: mx.example; spf=pass smtp.mailfrom=sender@example.com; dkim=pass header.d=example.com; dmarc=pass\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		"Hello analyst, visit https://example.com/ioc and http://malicious.test/phish.\r\n"
}

func testRawMultipartEmailWithAttachment() string {
	return "From: sender@example.com\r\n" +
		"To: analyst@example.com\r\n" +
		"Subject: Multipart\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=BOUNDARY123\r\n" +
		"\r\n" +
		"--BOUNDARY123\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		"See attached IOC list.\r\n" +
		"--BOUNDARY123\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Disposition: attachment; filename=\"ioc.txt\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		"aW9jLTEyMwppb2MtNDU2Cg==\r\n" +
		"--BOUNDARY123--\r\n"
}

func efMustHash(t *testing.T, obj object.Object) *object.Hash {
	t.Helper()
	h, ok := obj.(*object.Hash)
	if !ok {
		t.Fatalf("payload is not HASH: %T", obj)
	}
	return h
}

func efMustHashString(t *testing.T, hash *object.Hash, key string) string {
	t.Helper()
	obj := efMustHashValue(t, hash, key)
	str, ok := obj.(*object.String)
	if !ok {
		t.Fatalf("key %s is not STRING: %T", key, obj)
	}
	return str.Value
}

func efMustHashBool(t *testing.T, hash *object.Hash, key string) bool {
	t.Helper()
	obj := efMustHashValue(t, hash, key)
	b, ok := obj.(*object.Boolean)
	if !ok {
		t.Fatalf("key %s is not BOOLEAN: %T", key, obj)
	}
	return b.Value
}

func efMustHashValue(t *testing.T, hash *object.Hash, key string) object.Object {
	t.Helper()
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	return pair.Value
}
