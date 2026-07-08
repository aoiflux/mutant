package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
)

const (
	streamSeedByteSize      = 8
	streamBlockSize         = 64
	streamVersionPrefix     = "mutant-stream-v1"
	streamMaterialSeparator = "|"
	streamKeyLabel          = "key|"
	streamNonceLabel        = "nonce|"
)

// SecureRandByte generates a cryptographically secure random byte
// Replaces the insecure math/rand implementation
func SecureRandByte() (byte, error) {
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	return b[0], nil
}

// SecureRandBytes generates n cryptographically secure random bytes
func SecureRandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// SecureXOR performs XOR with a cryptographically secure key derived from seed and password
// This replaces the old XOR that used math/rand
// seed: instruction length or other deterministic value
// password: optional user password (empty string for deterministic encryption without password)
func SecureXOR(data []byte, seed int64, password string) ([]byte, error) {
	return SecureXORAt(data, seed, password, 0)
}

// SecureXORAt encrypts/decrypts data using an offset-aware ChaCha20 keystream.
// offset is the logical stream position and should match byte position in encrypted instruction/object regions.
func SecureXORAt(data []byte, seed int64, password string, offset int64) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data cannot be empty")
	}
	if offset < 0 {
		return nil, errors.New("offset cannot be negative")
	}

	key, nonce := deriveStreamKeyAndNonce(seed, password)
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return nil, err
	}

	blockOffset := uint32(offset / streamBlockSize)
	if blockOffset > 0 {
		cipher.SetCounter(blockOffset)
	}

	skip := int(offset % streamBlockSize)
	if skip > 0 {
		discard := make([]byte, skip)
		cipher.XORKeyStream(discard, discard)
	}

	result := make([]byte, len(data))
	cipher.XORKeyStream(result, data)

	return result, nil
}

// SecureXOROne performs XOR on a single byte with secure random key derived from seed and password
func SecureXOROne(instruction byte, seed int64, password string) (byte, error) {
	return SecureXOROneAt(instruction, seed, password, 0)
}

// SecureXOROneAt encrypts/decrypts a single byte at the given stream offset.
func SecureXOROneAt(instruction byte, seed int64, password string, offset int64) (byte, error) {
	res, err := SecureXORAt([]byte{instruction}, seed, password, offset)
	if err != nil {
		return 0, err
	}
	return res[0], nil
}

// DerivePasswordFromInstructions derives a deterministic password seed from instruction hash
// This ensures same program always gets same key, different programs get different keys
// Returns a uint64 that's converted to string in the caller
func DerivePasswordFromInstructions(instructions []byte) uint64 {
	if len(instructions) == 0 {
		return 0
	}

	hash := sha256.Sum256(instructions)
	// Use first 8 bytes as seed
	return binary.LittleEndian.Uint64(hash[:8])
}

func deriveStreamKeyAndNonce(seed int64, password string) ([32]byte, [12]byte) {
	seedBytes := make([]byte, streamSeedByteSize)
	binary.LittleEndian.PutUint64(seedBytes, uint64(seed))

	baseMaterial := append([]byte(streamVersionPrefix+streamMaterialSeparator), seedBytes...)
	baseMaterial = append(baseMaterial, streamMaterialSeparator...)
	baseMaterial = append(baseMaterial, []byte(password)...)

	keyHash := sha256.Sum256(append([]byte(streamKeyLabel), baseMaterial...))
	nonceHash := sha256.Sum256(append([]byte(streamNonceLabel), baseMaterial...))

	var key [32]byte
	var nonce [12]byte
	copy(key[:], keyHash[:])
	copy(nonce[:], nonceHash[:12])
	return key, nonce
}

// SecureCompare performs constant-time comparison to prevent timing attacks
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// SecureZero zeroes out sensitive data in memory
func SecureZero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// SecureZeroString zeroes out a string (via conversion)
// Note: This doesn't zero the original string, but the conversion
func SecureZeroString(s *string) {
	if s == nil {
		return
	}

	// Convert to byte slice and zero
	bytes := []byte(*s)
	SecureZero(bytes)
	*s = ""
}
