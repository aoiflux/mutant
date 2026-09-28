package security

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// An erased generation is refused by name, the current one is not erased on
// its own, the file's MAC covers the erasure, and a passphrase rotation carries
// an erased generation over as it is.
func TestAnErasedGenerationIsRefusedAndOutlivesAPassphraseRotation(t *testing.T) {
	pass := []byte("correct horse battery staple")
	cuid, err := RandomCaseUID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 28, 9, 0, 0, 0, time.UTC)
	f, first, err := NewCaseKeyFile(pass, cuid, "IR-ERASE", now)
	if err != nil {
		t.Fatal(err)
	}
	defer SecureZero(first)
	salt, err := f.SaltBytes()
	if err != nil {
		t.Fatal(err)
	}
	wrapKey, err := DeriveWrappingKey(pass, salt, f.Version)
	if err != nil {
		t.Fatal(err)
	}
	defer SecureZero(wrapKey)
	if _, _, err := SealCaseKeyFile(f, wrapKey, false); err != nil {
		t.Fatal(err)
	}
	second, err := f.RotateCaseKey(pass, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer SecureZero(second)
	// A case-key rotation keeps the salt, so the wrapping key is the same one.
	if _, _, err := SealCaseKeyFile(f, wrapKey, false); err != nil {
		t.Fatal(err)
	}
	mac := f.FileMAC

	if err := f.EraseGeneration(2); err == nil {
		t.Fatal("the current generation was erased on its own")
	}
	if err := f.EraseGeneration(3); err == nil {
		t.Fatal("a generation the file does not have was erased")
	}
	if err := f.EraseGeneration(1); err != nil {
		t.Fatal(err)
	}
	if !f.Generations[0].Erased() || f.Generations[1].Erased() || f.PreviousFileMAC != mac {
		t.Fatalf("erasing generation 1 left %+v, previous_file_mac %q", f.Generations, f.PreviousFileMAC)
	}
	if err := f.EraseGeneration(1); !errors.Is(err, ErrCaseKeyGenerationErased) {
		t.Fatalf("erasing generation 1 twice: %v", err)
	}
	if _, _, err := SealCaseKeyFile(f, wrapKey, false); err != nil {
		t.Fatal(err)
	}
	document, err := MarshalCaseKeyFile(f)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCaseKeyFile(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCaseKeyFile(parsed, wrapKey); err != nil {
		t.Fatalf("the file's MAC does not cover the erasure: %v", err)
	}
	if _, err := parsed.UnwrapGeneration(wrapKey, 1); !errors.Is(err, ErrCaseKeyGenerationErased) {
		t.Fatalf("unwrapping the erased generation: %v", err)
	}
	if _, _, err := OpenCaseKeyFile(parsed, pass, 1); !errors.Is(err, ErrCaseKeyGenerationErased) {
		t.Fatalf("opening the erased generation: %v", err)
	}
	if key, err := parsed.UnwrapGeneration(wrapKey, 2); err != nil || !bytes.Equal(key, second) {
		t.Fatalf("generation 2 after generation 1 was erased: %v", err)
	}

	// One of the two fields zeroed is an edit, not an erasure.
	half := parsed.Generations[1]
	half.Nonce = strings.Repeat("0", len(half.Nonce))
	if half.Erased() {
		t.Fatal("a generation with only its nonce zeroed reads as erased")
	}

	newPass := []byte("a different passphrase entirely")
	if err := parsed.RotatePassphrase(pass, newPass, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("a passphrase rotation over an erased generation: %v", err)
	}
	if !parsed.Generations[0].Erased() {
		t.Fatal("a passphrase rotation rewrapped the erased generation")
	}
	newSalt, err := parsed.SaltBytes()
	if err != nil {
		t.Fatal(err)
	}
	newWrapKey, err := DeriveWrappingKey(newPass, newSalt, parsed.Version)
	if err != nil {
		t.Fatal(err)
	}
	defer SecureZero(newWrapKey)
	if key, err := parsed.UnwrapGeneration(newWrapKey, 2); err != nil || !bytes.Equal(key, second) {
		t.Fatalf("generation 2 under the new passphrase: %v", err)
	}
}

// A record's key is erased when both of its fields hold the zeros, and an
// erasure leaves the header as long as it was.
func TestAnErasedRecordKeyIsBothFieldsZeroed(t *testing.T) {
	header := &RecordHeader{
		Format:           RecordFileFormat,
		Version:          RecordFileVersion,
		RecordKeyNonce:   strings.Repeat("ab", 24),
		RecordKeyWrapped: strings.Repeat("cd", WrappedKeySize),
	}
	before, err := MarshalRecordHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if header.RecordKeyErased() {
		t.Fatal("a header holding a wrapped key reads as erased")
	}
	nonce := header.RecordKeyNonce
	header.EraseRecordKey()
	after, err := MarshalRecordHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if !header.RecordKeyErased() || len(after) != len(before) {
		t.Fatalf("an erased header reads as erased %t and is %d bytes, from %d", header.RecordKeyErased(),
			len(after), len(before))
	}
	header.RecordKeyNonce = nonce
	if header.RecordKeyErased() {
		t.Fatal("a header with only its wrapped key zeroed reads as erased")
	}
}
