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
	// streamSeedByteSize is the seed's width in the stream key's material: an
	// int64, little-endian.
	//
	//mutant:format mutant-stream-v1: the seed as a 64-bit integer
	streamSeedByteSize = 8
	// streamBlockSize is the ChaCha20 block a stream offset is counted in.
	//
	//mutant:format RFC 8439 section 2.3: a 64-byte ChaCha20 block
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

// XORStream caches the derived key/nonce for a fixed (seed, password) so callers
// on a hot path (e.g. the VM decrypting every opcode byte, where seed=inslen and
// password are constant for the whole run) avoid recomputing two SHA-256 hashes
// per byte. It is safe for concurrent use: each call builds its own cipher.
// (dev-sec-platform-upgrades)
type XORStream struct {
	key   [32]byte
	nonce [12]byte
}

// NewXORStream derives and caches the key/nonce for the given seed and password.
func NewXORStream(seed int64, password string) *XORStream {
	key, nonce := deriveStreamKeyAndNonce(seed, password)
	return &XORStream{key: key, nonce: nonce}
}

// Zero wipes the derived key and nonce.
//
// A stream is derived from a password, so it is key material and it keeps that
// rule: nothing derived from a secret outlives the secret. The runtime calls
// this where it zeroes the password itself, in
// vm.CleanupRuntimeSensitiveData -- which until M26-VM-001 left the derived
// instruction key in memory after the password it came from had gone, and now
// has the values' key to answer for as well.
//
// The stream stays allocated rather than being dropped: the fetch loop reads
// its field directly, so replacing it with nil would turn a use after teardown
// into a nil dereference. A VM that has been cleaned up is finished, which is
// the same thing the stack and globals wiped beside it already assume.
func (s *XORStream) Zero() {
	if s == nil {
		return
	}
	SecureZero(s.key[:])
	SecureZero(s.nonce[:])
}

// XOROneAt decrypts/encrypts a single byte at the given stream offset using the
// cached key/nonce. Equivalent to SecureXOROneAt but without the per-call KDF.
func (s *XORStream) XOROneAt(b byte, offset int64) (byte, error) {
	if offset < 0 {
		return 0, errors.New("offset cannot be negative")
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(s.key[:], s.nonce[:])
	if err != nil {
		return 0, err
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
	out := [1]byte{b}
	cipher.XORKeyStream(out[:], out[:])
	return out[0], nil
}

// XORAt decrypts/encrypts a buffer at the given stream offset using the cached
// key/nonce (the multi-byte analogue of XOROneAt).
func (s *XORStream) XORAt(data []byte, offset int64) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data cannot be empty")
	}
	if offset < 0 {
		return nil, errors.New("offset cannot be negative")
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(s.key[:], s.nonce[:])
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
