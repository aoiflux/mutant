package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const (
	signingAlgorithmEd25519   = "Ed25519"
	signatureEncodedPartCount = 5
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

// EncodeSignature serializes a code signature
func (cs *CodeSignature) Encode() string {
	return strings.Join([]string{
		cs.Algorithm,
		hex.EncodeToString(cs.PublicKey),
		hex.EncodeToString(cs.Signature),
		hex.EncodeToString([]byte(cs.Version)),
		hex.EncodeToString([]byte(string(rune(cs.Timestamp)))),
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

	timestamp := int64(timestampBytes[0])

	return &CodeSignature{
		PublicKey: pubKey,
		Signature: signature,
		Algorithm: parts[0],
		Timestamp: timestamp,
		Version:   string(version),
	}, nil
}
