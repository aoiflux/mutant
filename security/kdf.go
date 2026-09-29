package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// KDFParams stores key derivation parameters
type KDFParams struct {
	Algorithm string // "argon2id" or "hkdf"
	Salt      []byte
	Time      uint32 // Argon2 only
	Memory    uint32 // Argon2 only (in KB)
	Threads   uint8  // Argon2 only
	KeyLen    uint32 // Output key length
	Info      []byte // HKDF only
}

const (
	// DefaultArgon2Time is the Argon2id pass count an artifact's password key
	// is derived with. The generator writes the cost into the artifact beside
	// the salt and the runner derives with what the artifact says, so the
	// default can change without stranding an artifact already written. One
	// pass over DefaultArgon2Memory meets OWASP's Argon2id minimum for a
	// single pass, 46 MiB.
	//
	//mutant:limit iterations
	DefaultArgon2Time = 1
	// DefaultArgon2Memory is the Argon2id memory cost of an artifact's
	// password key, in the kibibytes Argon2 counts in: 64 MiB.
	//
	//mutant:limit kibibytes
	DefaultArgon2Memory = 64 * 1024
	// DefaultArgon2Threads is the Argon2id lane count of an artifact's
	// password key: four, as both of RFC 9106's recommended parameter sets
	// use.
	//
	//mutant:limit count
	DefaultArgon2Threads = 4
	// DefaultKeyLen is the length of an artifact's password key. The artifact
	// cipher is AES-256-GCM and an artifact records no key length, so every
	// artifact's key is this long.
	//
	//mutant:format FIPS 197: an AES-256 key
	DefaultKeyLen = 32

	// MinArgon2Time is Argon2's own floor of one pass.
	//
	//mutant:format RFC 9106 section 3.1
	MinArgon2Time = 1
	// MaxArgon2Time bounds the passes an artifact's header may ask for. The
	// runner derives the key before it has anything to authenticate the header
	// with, so this is a cost a crafted header could name. It stops at the
	// costliest derivation in the tree -- caseKeyProfiles' and
	// grantFileProfiles' three passes over 256 MiB in four lanes, which
	// TestCaseKeyProfileIsInBand holds inside these bounds.
	//
	//mutant:limit iterations
	MaxArgon2Time = 3
	// MinArgon2Memory is the least memory an artifact's header may ask for:
	// the default this build writes, so a header edited down to a cheap
	// derivation is refused rather than honoured.
	//
	//mutant:limit kibibytes
	MinArgon2Memory = 64 * 1024
	// MaxArgon2Memory bounds the memory an artifact's header may ask for, at
	// the same costliest derivation MaxArgon2Time stops at: 256 MiB.
	//
	//mutant:limit kibibytes
	MaxArgon2Memory = 256 * 1024
	// MinArgon2Threads is Argon2's own floor of one lane.
	//
	//mutant:format RFC 9106 section 3.1
	MinArgon2Threads = 1
	// MaxArgon2Threads bounds the lanes an artifact's header may ask for, at
	// the four every derivation in the tree uses.
	//
	//mutant:limit count
	MaxArgon2Threads = 4

	// HKDF info strings
	HKDFInfoBytecode  = "mutant-bytecode-encryption-v1"
	HKDFInfoSignature = "mutant-signature-key-v1"
)

// DeriveKeyFromPassword derives a key from password using Argon2id
// This is used when user provides a password for compilation/execution
func DeriveKeyFromPassword(password string, salt []byte) ([]byte, *KDFParams, error) {
	if len(password) == 0 {
		return nil, nil, errors.New("password cannot be empty")
	}

	if len(salt) == 0 {
		salt = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, nil, err
		}
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		DefaultArgon2Time,
		DefaultArgon2Memory,
		DefaultArgon2Threads,
		DefaultKeyLen,
	)

	params := &KDFParams{
		Algorithm: "argon2id",
		Salt:      salt,
		Time:      DefaultArgon2Time,
		Memory:    DefaultArgon2Memory,
		Threads:   DefaultArgon2Threads,
		KeyLen:    DefaultKeyLen,
	}

	return key, params, nil
}

// ValidateArgon2Params validates Argon2id parameter bounds.
func ValidateArgon2Params(time, memory uint32, threads uint8) error {
	if time < MinArgon2Time || time > MaxArgon2Time {
		return fmt.Errorf("argon2 time must be between %d and %d", MinArgon2Time, MaxArgon2Time)
	}

	if memory < MinArgon2Memory || memory > MaxArgon2Memory {
		return fmt.Errorf("argon2 memory must be between %d and %d KB", MinArgon2Memory, MaxArgon2Memory)
	}

	if threads < MinArgon2Threads || threads > MaxArgon2Threads {
		return fmt.Errorf("argon2 threads must be between %d and %d", MinArgon2Threads, MaxArgon2Threads)
	}

	return nil
}

// DeriveKeyDeterministic derives a key deterministically from source code hash
// This is used when no password is provided (automatic mode)
func DeriveKeyDeterministic(sourceHash []byte, metadata string) ([]byte, *KDFParams, error) {
	if len(sourceHash) == 0 {
		return nil, nil, errors.New("source hash cannot be empty")
	}

	// Use source hash as salt for determinism
	salt := sourceHash

	// Create HKDF with SHA-256
	info := []byte(HKDFInfoBytecode + "|" + metadata)

	hkdfReader := hkdf.New(sha256.New, sourceHash, salt, info)

	key := make([]byte, DefaultKeyLen)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, nil, err
	}

	params := &KDFParams{
		Algorithm: "hkdf-sha256",
		Salt:      salt,
		KeyLen:    DefaultKeyLen,
		Info:      info,
	}

	return key, params, nil
}

// ReconstructKey reconstructs a key from password and stored parameters
func ReconstructKey(password string, params *KDFParams) ([]byte, error) {
	switch params.Algorithm {
	case "argon2id":
		return argon2.IDKey(
			[]byte(password),
			params.Salt,
			params.Time,
			params.Memory,
			params.Threads,
			params.KeyLen,
		), nil

	case "hkdf-sha256":
		// For HKDF, we need the original source hash
		// This should be derived from the salt which stores the source hash
		hkdfReader := hkdf.New(sha256.New, params.Salt, params.Salt, params.Info)
		key := make([]byte, params.KeyLen)
		if _, err := io.ReadFull(hkdfReader, key); err != nil {
			return nil, err
		}
		return key, nil

	default:
		return nil, fmt.Errorf("unknown KDF algorithm: %s", params.Algorithm)
	}
}

// HashSourceCode creates a SHA-256 hash of source code
func HashSourceCode(source []byte) []byte {
	hash := sha256.Sum256(source)
	return hash[:]
}

// GenerateMetadata creates metadata string for deterministic key derivation
func GenerateMetadata(filename, version string) string {
	// Use filename and version for additional entropy
	// This makes bytecode specific to project context
	return fmt.Sprintf("%s|%s", filename, version)
}

// GenerateSalt generates a cryptographically secure random salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// EncodeParams serializes KDF parameters for storage
func (p *KDFParams) Encode() string {
	return fmt.Sprintf("%s|%s|%d|%d|%d|%d|%s",
		p.Algorithm,
		hex.EncodeToString(p.Salt),
		p.Time,
		p.Memory,
		p.Threads,
		p.KeyLen,
		hex.EncodeToString(p.Info),
	)
}

// DecodeParams deserializes KDF parameters
func DecodeParams(encoded string) (*KDFParams, error) {
	var algo, saltHex, infoHex string
	var time, memory uint32
	var threads uint8
	var keyLen uint32

	_, err := fmt.Sscanf(encoded, "%s|%s|%d|%d|%d|%d|%s",
		&algo, &saltHex, &time, &memory, &threads, &keyLen, &infoHex)
	if err != nil {
		return nil, err
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, err
	}

	info, err := hex.DecodeString(infoHex)
	if err != nil {
		return nil, err
	}

	return &KDFParams{
		Algorithm: algo,
		Salt:      salt,
		Time:      time,
		Memory:    memory,
		Threads:   threads,
		KeyLen:    keyLen,
		Info:      info,
	}, nil
}
