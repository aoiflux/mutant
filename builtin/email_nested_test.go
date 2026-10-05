package builtin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"mutant/object"
)

// phishShapedEmail is built the way most mail is: a multipart/mixed carrying the
// attachment, holding a multipart/related that carries an inline image, holding
// a multipart/alternative with the text and HTML bodies. The boundaries are
// mixed-case because a boundary is case-sensitive.
func phishShapedEmail(payload []byte) string {
	return "From: billing@evil.example\r\n" +
		"To: victim@example.com\r\n" +
		"Subject: Invoice overdue\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"Mixed-AbC\"\r\n" +
		"\r\n" +
		"--Mixed-AbC\r\n" +
		"Content-Type: multipart/related; boundary=\"Related-DeF\"\r\n" +
		"\r\n" +
		"--Related-DeF\r\n" +
		"Content-Type: multipart/alternative; boundary=\"Alt-GhI\"\r\n" +
		"\r\n" +
		"--Alt-GhI\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		"Your invoice is overdue. Sign in at https://evil.example/login to pay.\r\n" +
		"--Alt-GhI\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		"<p>Your invoice is overdue. <a href=\"https://evil.example/pay\">Pay now</a></p>\r\n" +
		"--Alt-GhI--\r\n" +
		"--Related-DeF\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-Disposition: inline; filename=\"logo.png\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		"iVBORw0KGgo=\r\n" +
		"--Related-DeF--\r\n" +
		"--Mixed-AbC\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Disposition: attachment; filename=\"payload.exe\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		base64.StdEncoding.EncodeToString(payload) + "\r\n" +
		"--Mixed-AbC--\r\n"
}

// TestANestedMultipartMessageKeepsItsBodiesAndAttachments is M26-ART-013's
// regression test. The old walk looked at the top level only and dropped the
// multipart/related part whole: both bodies, both links and the inline image.
func TestANestedMultipartMessageKeepsItsBodiesAndAttachments(t *testing.T) {
	payload := []byte("MZ\x90\x00 not really a program")
	sum := sha256.Sum256(payload)
	raw := phishShapedEmail(payload)

	parsed, errObj := unwrapPair(t, EmailParse(stringObj(raw)))
	if errObj != nil {
		t.Fatalf("email_parse: %s", errObj.Inspect())
	}
	h := efMustHash(t, parsed)
	if got := efMustHashString(t, h, "text"); !strings.Contains(got, "https://evil.example/login") {
		t.Errorf("text = %q, want the text/plain body", got)
	}
	if got := efMustHashString(t, h, "html"); !strings.Contains(got, "https://evil.example/pay") {
		t.Errorf("html = %q, want the text/html body", got)
	}

	attached, errObj := unwrapPair(t, EmailAttachments(stringObj(raw)))
	if errObj != nil {
		t.Fatalf("email_attachments: %s", errObj.Inspect())
	}
	byName := map[string]string{}
	for _, e := range attached.(*object.Array).Elements {
		a := efMustHash(t, e)
		byName[efMustHashString(t, a, "filename")] = efMustHashString(t, a, "sha256")
	}
	if byName["payload.exe"] != hex.EncodeToString(sum[:]) {
		t.Errorf("payload.exe sha256 = %q, want %x", byName["payload.exe"], sum)
	}
	if _, ok := byName["logo.png"]; !ok || len(byName) != 2 {
		t.Errorf("attachments = %v, want payload.exe and the inline logo.png", byName)
	}

	urls, errObj := unwrapPair(t, EmailURLs(stringObj(raw)))
	if errObj != nil {
		t.Fatalf("email_urls: %s", errObj.Inspect())
	}
	found := map[string]bool{}
	for _, e := range urls.(*object.Array).Elements {
		found[efMustHashString(t, efMustHash(t, e), "url")] = true
	}
	for _, want := range []string{"https://evil.example/login", "https://evil.example/pay"} {
		if !found[want] {
			t.Errorf("email_urls is missing %s (got %v)", want, found)
		}
	}
}

// TestAMultipartNestedPastTheLimitIsRefused: every level is walked with its own
// boundary, so the depth is bounded, and a message past the bound is refused by
// name rather than read as empty.
func TestAMultipartNestedPastTheLimitIsRefused(t *testing.T) {
	const levels = 20
	var b strings.Builder
	b.WriteString("From: a@example.com\r\nMIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"L0\"\r\n\r\n")
	for i := 0; i < levels; i++ {
		fmt.Fprintf(&b, "--L%d\r\nContent-Type: multipart/mixed; boundary=\"L%d\"\r\n\r\n", i, i+1)
	}
	fmt.Fprintf(&b, "--L%d\r\nContent-Type: text/plain\r\n\r\nbottom\r\n--L%d--\r\n", levels, levels)
	for i := levels - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "--L%d--\r\n", i)
	}

	_, errObj := unwrapPair(t, EmailParse(stringObj(b.String())))
	if errObj == nil || !strings.Contains(errObj.Inspect(), "nested more than") {
		t.Fatalf("email_parse of a %d-deep message: error = %v, want a refusal naming the depth", levels, errObj)
	}
}
