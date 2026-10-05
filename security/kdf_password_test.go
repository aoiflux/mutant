package security

import (
	"bytes"
	"testing"
)

// TestReconstructKeyRefusesAKeyThatIgnoresThePassword is M26-SEC-009's
// regression test for ReconstructKey's "hkdf-sha256" branch.
//
// That branch derived the key from params.Salt as both the secret and the salt
// and never read the password, so every passphrase produced the same key and a
// stored blob naming that algorithm opened under any password at all. Before
// the fix this test fails on its first assertion: no error comes back, a
// 32-byte key does, and the empty password derives the same one.
func TestReconstructKeyRefusesAKeyThatIgnoresThePassword(t *testing.T) {
	params := &KDFParams{
		Algorithm: "hkdf-sha256",
		Salt:      bytes.Repeat([]byte{0xA5}, 32),
		KeyLen:    DefaultKeyLen,
		Info:      []byte(HKDFInfoBytecode + "|whatever"),
	}

	key, err := ReconstructKey("the real passphrase", params)
	if err == nil {
		t.Fatalf("hkdf-sha256 was accepted and handed back a %d-byte key", len(key))
	}
	if key != nil {
		t.Errorf("the refusal still returned %d bytes of key material", len(key))
	}

	// The defect itself: the same parameters under a password that should not
	// open them. Unfixed, this returns the identical key.
	empty, emptyErr := ReconstructKey("", params)
	if emptyErr == nil {
		t.Fatalf("hkdf-sha256 opened under an empty password, giving %d bytes", len(empty))
	}
	if key != nil && empty != nil && bytes.Equal(key, empty) {
		t.Error("two different passwords derived the same key")
	}
}

// TestReconstructKeyWithArgon2idFollowsThePassword holds the path AESDecrypt
// actually takes, so the refusal above cannot be widened into refusing the one
// algorithm that is in use. It also states the property the refused branch
// lacked: a different password gives a different key.
func TestReconstructKeyWithArgon2idFollowsThePassword(t *testing.T) {
	params := &KDFParams{
		Algorithm: "argon2id",
		Salt:      bytes.Repeat([]byte{0x5A}, 32),
		Time:      DefaultArgon2Time,
		Memory:    DefaultArgon2Memory,
		Threads:   DefaultArgon2Threads,
		KeyLen:    DefaultKeyLen,
	}

	key, err := ReconstructKey("correct horse battery staple", params)
	if err != nil {
		t.Fatalf("argon2id was refused: %v", err)
	}
	if len(key) != DefaultKeyLen {
		t.Fatalf("key is %d bytes, want %d", len(key), DefaultKeyLen)
	}

	again, err := ReconstructKey("correct horse battery staple", params)
	if err != nil {
		t.Fatalf("the second derivation was refused: %v", err)
	}
	if !bytes.Equal(key, again) {
		t.Error("the same password and parameters derived two different keys")
	}

	other, err := ReconstructKey("incorrect horse battery staple", params)
	if err != nil {
		t.Fatalf("the wrong password was refused rather than derived: %v", err)
	}
	if bytes.Equal(key, other) {
		t.Error("a different password derived the same key")
	}
}

// TestReconstructKeyNamesAnAlgorithmItDoesNotKnow keeps the default arm a
// refusal rather than a zero-length key, since a caller that ignored the error
// would otherwise encrypt under nothing at all.
func TestReconstructKeyNamesAnAlgorithmItDoesNotKnow(t *testing.T) {
	for _, name := range []string{"", "hkdf", "HKDF-SHA256", "argon2i", "scrypt"} {
		key, err := ReconstructKey("passphrase", &KDFParams{
			Algorithm: name,
			Salt:      bytes.Repeat([]byte{0x11}, 32),
			KeyLen:    DefaultKeyLen,
		})
		if err == nil {
			t.Errorf("algorithm %q was accepted, returning %d bytes", name, len(key))
		}
		if key != nil {
			t.Errorf("algorithm %q was refused but returned %d bytes", name, len(key))
		}
	}
}
