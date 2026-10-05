package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	signingAlgorithmEd25519   = "Ed25519"
	signatureEncodedPartCount = 5
	signatureTimestampBytes   = 8
)

// CodeSignature represents a digital signature for bytecode
type CodeSignature struct {
	PublicKey []byte
	Signature []byte
	Algorithm string // "Ed25519"
	Timestamp int64
	Version   string
}

// KeyPair holds Ed25519 key pair
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair generates a new Ed25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// SignBytecode creates a digital signature for bytecode
func SignBytecode(bytecode []byte, privateKey ed25519.PrivateKey, version string) (*CodeSignature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}

	// Hash the bytecode first for consistency
	hash := sha256.Sum256(bytecode)

	// Sign the hash
	signature := ed25519.Sign(privateKey, hash[:])

	// Extract public key from private key
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &CodeSignature{
		PublicKey: publicKey,
		Signature: signature,
		Algorithm: signingAlgorithmEd25519,
		Timestamp: time.Now().Unix(),
		Version:   version,
	}, nil
}

// VerifyBytecode verifies a bytecode signature
func VerifyBytecode(bytecode []byte, sig *CodeSignature) error {
	if sig.Algorithm != signingAlgorithmEd25519 {
		return errors.New("unsupported signature algorithm")
	}

	if len(sig.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid public key size")
	}

	if len(sig.Signature) != ed25519.SignatureSize {
		return errors.New("invalid signature size")
	}

	// Hash the bytecode
	hash := sha256.Sum256(bytecode)

	// Verify signature
	if !ed25519.Verify(sig.PublicKey, hash[:], sig.Signature) {
		return errors.New("signature verification failed")
	}

	return nil
}

// Encode serializes a code signature. The timestamp is eight big-endian
// bytes because it is an int64. It was written as string(rune(cs.Timestamp)),
// which is a Unicode code point and not a number: every Unix timestamp since
// 1970-01-13 is larger than the largest valid code point, so the conversion
// yielded U+FFFD and the timestamp was destroyed before it reached the string
// -- 1600000000 encoded as efbfbd and decoded as 239, as did every other real
// timestamp (M26-SEC-009). Nothing called this pair, so there is no encoded
// signature anywhere to stay compatible with.
func (cs *CodeSignature) Encode() string {
	var ts [signatureTimestampBytes]byte
	binary.BigEndian.PutUint64(ts[:], uint64(cs.Timestamp))
	return strings.Join([]string{
		cs.Algorithm,
		hex.EncodeToString(cs.PublicKey),
		hex.EncodeToString(cs.Signature),
		hex.EncodeToString([]byte(cs.Version)),
		hex.EncodeToString(ts[:]),
	}, SEPERATOR)
}

// DecodeSignature deserializes a code signature
func DecodeSignature(encoded string) (*CodeSignature, error) {
	parts := strings.Split(encoded, SEPERATOR)
	if len(parts) != signatureEncodedPartCount {
		return nil, errors.New("invalid signature format")
	}

	pubKey, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	signature, err := hex.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	version, err := hex.DecodeString(parts[3])
	if err != nil {
		return nil, err
	}

	timestampBytes, err := hex.DecodeString(parts[4])
	if err != nil {
		return nil, err
	}

	// A refusal rather than a panic. This read timestampBytes[0], which
	// indexed an empty slice when the field was absent -- a runtime panic out
	// of a decoder handed untrusted text -- and took one byte of the eight when
	// it was not (M26-SEC-009).
	if len(timestampBytes) != signatureTimestampBytes {
		return nil, fmt.Errorf("invalid signature timestamp: %d bytes, want %d",
			len(timestampBytes), signatureTimestampBytes)
	}

	timestamp := int64(binary.BigEndian.Uint64(timestampBytes))

	return &CodeSignature{
		PublicKey: pubKey,
		Signature: signature,
		Algorithm: parts[0],
		Timestamp: timestamp,
		Version:   string(version),
	}, nil
}
