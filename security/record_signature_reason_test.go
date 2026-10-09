package security

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// SignatureReason exists to say why a record has NO signature. SignRecordFooter
// wrote it on records that do have one, and what it wrote was not a reason at
// all: it bound the fourth return of EnsureLocalSigningKeyPair, which is the
// key store's DIRECTORY, to a variable named `reason` and assigned that to the
// field. Every signed record therefore published the absolute path of the
// examiner's private-key directory -- <home>/.mutant/keys on a default install,
// so the operating-system account name travelled with it -- and disclose_bundle
// copies the .mrec into a recipient's package byte for byte, so the path
// reached every recipient of every disclosure (M26-SEC-002).
//
// builtin/custody_seal.go already keeps key locations out of custody manifests
// for exactly this reason, in as many words: the path is useless to a recipient
// and it tells them where to go looking for the key.
//
// These tests drive the exported SignRecordFooter and the keystore testing
// override, and nothing unexported that the fix introduces, so they compile
// against the defective record_file.go as well as the fixed one. That is
// deliberate: a regression test that has only ever been run against the fix has
// not been shown to test anything, which is the standard the rest of this
// package's keystore tests already hold themselves to.

// signedFooterForReasonTest seals a footer under a keystore of its own and
// returns the directory that keystore lives in alongside it.
//
// The directory is returned rather than recomputed because it is the exact
// string the defect leaked. An assertion that names it cannot pass vacuously
// the way one guessing at the shape of a path could.
func signedFooterForReasonTest(t *testing.T) (*RecordFooter, string, []byte, [sha256.Size]byte) {
	t.Helper()
	dir := t.TempDir()
	useKeyStore(t, dir)

	_, _, _, baseDir, err := EnsureLocalSigningKeyPair()
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if baseDir == "" {
		t.Fatal("the keystore reported no directory of its own, so this test could not tell " +
			"whether a directory leaked into the footer")
	}

	header := []byte("a header stands in for every artifact this key signs")
	root := sha256.Sum256([]byte("the segments root"))
	footer := &RecordFooter{}
	if err := SignRecordFooter(footer, header, root, true); err != nil {
		t.Fatalf("SignRecordFooter: %v", err)
	}
	if !footer.Signed {
		t.Fatalf("signed = false, reason %q: these tests need a footer that is signed", footer.SignatureReason)
	}
	return footer, baseDir, header, root
}

// The defect, stated as the footer a signed record must come back with.
func TestASignedFooterPublishesNoKeyStorePath(t *testing.T) {
	footer, baseDir, header, root := signedFooterForReasonTest(t)

	if strings.Contains(footer.SignatureReason, baseDir) {
		t.Fatalf("signature_reason = %q, which names the key store at %q: the examiner's "+
			"private-key directory travelled in the footer of every signed record, and into "+
			"every package disclose_bundle made from one", footer.SignatureReason, baseDir)
	}
	if footer.SignatureReason != "" {
		t.Fatalf("signature_reason = %q on a signed record, want empty: the field records why a "+
			"record has no signature, and this record has one", footer.SignatureReason)
	}

	// Dropping the field must not disturb the signature, which is the one thing
	// a reader of a sealed record cannot do without.
	published, err := hex.DecodeString(footer.PublicKey)
	if err != nil {
		t.Fatalf("decode the footer public key: %v", err)
	}
	signature, err := hex.DecodeString(footer.Signature)
	if err != nil {
		t.Fatalf("decode the footer signature: %v", err)
	}
	message := RecordSigningMessage(header, root, footerMetaBytes(footer))
	if !ed25519.Verify(ed25519.PublicKey(published), message, signature) {
		t.Fatal("the footer's signature no longer verifies under the key it publishes")
	}
}

// The leak travelled as JSON, so the JSON is what has to be checked.
//
// The struct field and the wire field are not the same assertion: omitempty
// drops signature_reason only when it is exactly empty, and a recipient reading
// a package sees the wire form. The needle is run through json.Marshal rather
// than used raw, because a Windows path is written with doubled separators in
// JSON and a raw path would not be found in it -- an escaping detail that would
// make this test pass against the defect it is here to catch.
func TestASignedFootersJSONCarriesNoSignatureReason(t *testing.T) {
	footer, baseDir, _, _ := signedFooterForReasonTest(t)

	encoded, err := json.Marshal(footer)
	if err != nil {
		t.Fatalf("marshal the footer: %v", err)
	}

	quoted, err := json.Marshal(baseDir)
	if err != nil {
		t.Fatalf("marshal the keystore directory: %v", err)
	}
	needle := string(quoted[1 : len(quoted)-1])
	if strings.Contains(string(encoded), needle) {
		t.Fatalf("the footer's JSON names the key store at %q: %s", baseDir, encoded)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("read the footer back as fields: %v", err)
	}
	if raw, present := fields["signature_reason"]; present {
		t.Fatalf("a signed footer still carries a signature_reason field, set to %s", raw)
	}
}

// The fix must not become "the field is always empty".
//
// Where there is no signature the reason is the only thing a reader has, and
// VerifyRecordSignature hands it back unchanged as the detail for an unsigned
// record. Emptying it there would turn a deliberately unsigned record and a
// keystore that failed into the same report.
func TestAnUnsignedFooterStillSaysWhyItIsUnsigned(t *testing.T) {
	dir := t.TempDir()
	useKeyStore(t, dir)

	header := []byte("a header stands in for every artifact this key signs")
	root := sha256.Sum256([]byte("the segments root"))

	footer := &RecordFooter{}
	if err := SignRecordFooter(footer, header, root, false); err != nil {
		t.Fatalf("SignRecordFooter with sign=false: %v", err)
	}
	if footer.Signed {
		t.Fatal("signed = true for a record sealed with sign:false")
	}
	if footer.SignatureReason == "" {
		t.Fatal("an unsigned footer gives no reason at all: a reader cannot tell a record " +
			"sealed without a signature on purpose from one whose keystore could not be read")
	}
	if footer.Signature != "" || footer.PublicKey != "" {
		t.Fatalf("an unsigned footer carries signature %q and public key %q",
			footer.Signature, footer.PublicKey)
	}

	signed, valid, detail := VerifyRecordSignature(footer, header, root)
	if signed || valid {
		t.Fatalf("VerifyRecordSignature reported signed=%v valid=%v for a sign:false record",
			signed, valid)
	}
	if detail != footer.SignatureReason {
		t.Fatalf("the verifier's detail %q is not the reason the footer gives, %q: the reason "+
			"stopped reaching the reader it is written for", detail, footer.SignatureReason)
	}
}
