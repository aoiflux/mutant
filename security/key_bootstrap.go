package security

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var localKeyStoreDirOverride = ""

func SetLocalKeyStoreDirForTesting(dir string) {
	localKeyStoreDirOverride = strings.TrimSpace(dir)
}

func ResolveLocalKeyStoreDir() (string, error) {
	if localKeyStoreDirOverride != "" {
		return localKeyStoreDirOverride, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}

	return filepath.Join(homeDir, ".mutant", "keys"), nil
}

func LocalKeyPairPaths(baseDir string) (string, string) {
	privatePath := filepath.Join(baseDir, LocalSigningPrivateKeyFileName)
	publicPath := filepath.Join(baseDir, LocalSigningPublicKeyFileName)
	return privatePath, publicPath
}

func EnsureLocalSigningKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, bool, string, error) {
	baseDir, err := ResolveLocalKeyStoreDir()
	if err != nil {
		return nil, nil, false, "", err
	}

	privateKey, publicKey, err := loadLocalSigningKeyPair(baseDir)
	if err == nil {
		return privateKey, publicKey, false, baseDir, nil
	}

	if !os.IsNotExist(err) {
		return nil, nil, false, "", err
	}

	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, nil, false, "", fmt.Errorf("create local keystore dir: %w", err)
	}

	keyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, false, "", err
	}

	privatePath, publicPath := LocalKeyPairPaths(baseDir)
	if err := os.WriteFile(privatePath, []byte(hex.EncodeToString(keyPair.PrivateKey)), 0600); err != nil {
		return nil, nil, false, "", fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(publicPath, []byte(hex.EncodeToString(keyPair.PublicKey)), 0600); err != nil {
		return nil, nil, false, "", fmt.Errorf("write public key: %w", err)
	}

	return keyPair.PrivateKey, keyPair.PublicKey, true, baseDir, nil
}

func ResolveTrustedPublicKeyHex() (string, bool, string, error) {
	_, publicKey, created, baseDir, err := EnsureLocalSigningKeyPair()
	if err != nil {
		return "", false, "", err
	}

	return hex.EncodeToString(publicKey), created, baseDir, nil
}

func loadLocalSigningKeyPair(baseDir string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privatePath, publicPath := LocalKeyPairPaths(baseDir)

	privateHex, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, nil, err
	}
	publicHex, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := hex.DecodeString(strings.TrimSpace(string(privateHex)))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid local private key encoding: %w", err)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("invalid local private key size: expected %d bytes", ed25519.PrivateKeySize)
	}

	publicKey, err := hex.DecodeString(strings.TrimSpace(string(publicHex)))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid local public key encoding: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid local public key size: expected %d bytes", ed25519.PublicKeySize)
	}

	return ed25519.PrivateKey(privateKey), ed25519.PublicKey(publicKey), nil
}
