package security

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var localKeyStoreDirOverride = ""

func SetLocalKeyStoreDirForTesting(dir string) {
	localKeyStoreDirOverride = strings.TrimSpace(dir)
}

// localKeyStoreMu serialises the bootstrap inside the process.
//
// Creation used to be neither exclusive nor atomic: two plain WriteFile calls,
// no lock and no O_EXCL. record_seal signs outside any custody lock and
// ledger_open takes none, so concurrent signers reaching a fresh keystore could
// interleave two bootstraps and leave the private key of one beside the public
// key of another. Eight goroutines on a fresh directory did it in 92 of 200
// attempts (M26-SEC-003).
//
// One mutex for every directory rather than one per directory. A process
// bootstraps a keystore once, so there is nothing to win from the bookkeeping,
// and an uncontended lock is the cheapest correct thing available here.
var localKeyStoreMu sync.Mutex

// ResolveLocalKeyStoreDir returns the directory that holds the local signing
// key pair: .mutant/keys under the home directory the operating system's
// account database records for the user Mutant runs as.
//
// Never HOME or USERPROFILE. The pair signs every artifact, case manifest,
// ledger commit and record, and its public half is the key --signer-auth trusts
// when no --trusted-key is named, so a variable nobody records would choose
// which key signs and which signer is trusted (M26-DOC3-001). A user the account
// database cannot answer for is refused, not guessed at.
func ResolveLocalKeyStoreDir() (string, error) {
	if localKeyStoreDirOverride != "" {
		return localKeyStoreDirOverride, nil
	}

	homeDir, err := accountHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve the local keystore: %w", err)
	}

	return filepath.Join(homeDir, ".mutant", "keys"), nil
}

func LocalKeyPairPaths(baseDir string) (string, string) {
	privatePath := filepath.Join(baseDir, LocalSigningPrivateKeyFileName)
	publicPath := filepath.Join(baseDir, LocalSigningPublicKeyFileName)
	return privatePath, publicPath
}

// EnsureLocalSigningKeyPair returns the local signing pair, creating it on first
// use. The bool reports whether this call is the one that created it.
//
// The private key is the only authority in the keystore and it is never written
// over. The public file holds a value the private key already carries in its
// last thirty-two bytes, so it is a cache: a missing one is rebuilt from the
// private key and a disagreeing one is refused. This function used to regenerate
// the whole pair whenever either file was missing, which destroyed a long-held
// signing key the moment a migration or a backup restore dropped the public
// half, and reported only that a key had been generated (M26-SEC-003).
//
// What that cost is worth stating plainly: the artifacts signed under the lost
// key do not report a lost key. Every record, case-key file and ledger made
// before it verifies against a key that signed none of them, which reads as
// tampering with the evidence rather than as a damaged keystore.
func EnsureLocalSigningKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, bool, string, error) {
	baseDir, err := ResolveLocalKeyStoreDir()
	if err != nil {
		return nil, nil, false, "", err
	}

	// The lock is taken here rather than inside the bootstrap so that the one
	// exported entry point is the one place that serialises. Resolving the
	// directory is a read of a string and needs no protection.
	localKeyStoreMu.Lock()
	defer localKeyStoreMu.Unlock()

	privateKey, publicKey, created, err := bootstrapLocalSigningKeyPair(baseDir)
	if err != nil {
		return nil, nil, false, "", err
	}

	return privateKey, publicKey, created, baseDir, nil
}

// bootstrapLocalSigningKeyPair loads the pair in baseDir or creates it. The
// caller holds localKeyStoreMu.
func bootstrapLocalSigningKeyPair(baseDir string) (ed25519.PrivateKey, ed25519.PublicKey, bool, error) {
	privateKey, publicKey, err := loadOrRepairLocalSigningKeyPair(baseDir)
	if err == nil {
		return privateKey, publicKey, false, nil
	}

	// A missing private key is now the only thing that reaches the generator. A
	// missing public file was handled above, and a malformed or disagreeing one
	// is an error that stops here rather than one the generator answers by
	// replacing the key it could not read.
	if !os.IsNotExist(err) {
		return nil, nil, false, err
	}

	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, nil, false, fmt.Errorf("create local keystore dir: %w", err)
	}

	keyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, false, err
	}

	privatePath, publicPath := LocalKeyPairPaths(baseDir)
	err = claimLocalKeyStoreFile(privatePath, []byte(hex.EncodeToString(keyPair.PrivateKey)))
	if os.IsExist(err) {
		// Another process created the private key between the read above and
		// this claim, and O_EXCL is what makes that a refusal instead of an
		// overwrite. The first writer's key is the store's key: this call reads
		// it back and discards the pair it had just generated, which is why it
		// reports that nothing was created for this run.
		privateKey, publicKey, err = loadOrRepairLocalSigningKeyPair(baseDir)
		if err != nil {
			return nil, nil, false, fmt.Errorf("another process created %s while this one was generating a "+
				"signing key, and reading theirs back failed: %w", filepath.Clean(privatePath), err)
		}

		return privateKey, publicKey, false, nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("write private key: %w", err)
	}

	if err := writeLocalKeyStoreFile(publicPath, []byte(hex.EncodeToString(keyPair.PublicKey))); err != nil {
		return nil, nil, false, fmt.Errorf("write public key: %w", err)
	}

	return keyPair.PrivateKey, keyPair.PublicKey, true, nil
}

// loadOrRepairLocalSigningKeyPair loads the pair and rebuilds the public file
// when that file is the only thing missing.
//
// Rebuilding changes nothing about which key signs: the bytes written are the
// ones the private key already carried. The write is still allowed to fail the
// call, for the same reason the original write of that file was. The public half
// is what --signer-auth trusts when no --trusted-key is named and what every
// consumer publishes beside a signature, so a keystore that cannot hold it is
// something an operator needs told once rather than a silence that repeats on
// every run.
func loadOrRepairLocalSigningKeyPair(baseDir string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privateKey, publicKey, publicFileMissing, err := loadLocalSigningKeyPair(baseDir)
	if err != nil {
		return nil, nil, err
	}

	if publicFileMissing {
		_, publicPath := LocalKeyPairPaths(baseDir)
		if err := writeLocalKeyStoreFile(publicPath, []byte(hex.EncodeToString(publicKey))); err != nil {
			return nil, nil, fmt.Errorf("the public half of the local signing key was missing from %s and "+
				"could not be rebuilt from the private key: %w", filepath.Clean(publicPath), err)
		}
	}

	return privateKey, publicKey, nil
}

func ResolveTrustedPublicKeyHex() (string, bool, string, error) {
	return ResolveTrustedPublicKeyHexFromPath("")
}

// ResolveTrustedPublicKeyHexFromPath reads the trusted verification key from
// path, falling back to the local keystore when path is empty. It reports
// whether a keystore pair had to be generated, and the directory the key came
// from.
//
// A path, never key material: the operator names a file on the command line, so
// the run stays reproducible from the invocation alone and the key itself never
// travels through the process environment or a shell history.
// See docs/CONFIGURATION_POLICY.md.
func ResolveTrustedPublicKeyHexFromPath(path string) (string, bool, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		_, publicKey, created, baseDir, err := EnsureLocalSigningKeyPair()
		if err != nil {
			return "", false, "", err
		}

		return hex.EncodeToString(publicKey), created, baseDir, nil
	}

	publicKey, err := loadTrustedPublicKeyFile(path)
	if err != nil {
		return "", false, "", err
	}

	return hex.EncodeToString(publicKey), false, filepath.Dir(path), nil
}

func loadTrustedPublicKeyFile(path string) (ed25519.PublicKey, error) {
	publicHex, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trusted public key %s: %w", filepath.Clean(path), err)
	}

	publicKey, err := hex.DecodeString(strings.TrimSpace(string(publicHex)))
	if err != nil {
		return nil, fmt.Errorf("invalid trusted public key encoding in %s: %w", filepath.Clean(path), err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid trusted public key size in %s: expected %d bytes, got %d",
			filepath.Clean(path), ed25519.PublicKeySize, len(publicKey))
	}

	return ed25519.PublicKey(publicKey), nil
}

// loadLocalSigningKeyPair reads the pair from baseDir. The bool reports that the
// private key was read and the public file was absent, which is a cache to
// rebuild rather than a failure; a missing private key is the only thing that
// comes back as an error os.IsNotExist agrees with.
//
// The public key returned is always derived from the private key. The file's
// copy is compared against it and never used in its place, because the two
// halves are read independently and a pair that disagreed used to load without
// complaint. After that, everything signed was signed with one key and published
// the other, and verified as "the signature does not cover this header and these
// segments" -- a false tamper report on real evidence, on every record, case-key
// file and ledger made from then on (M26-SEC-003).
//
// The comparison also catches a corrupted private key while the public file is
// intact, because the derived half moves with the corruption and the file's does
// not. What it cannot catch is two files that are a matching pair from somewhere
// else; nothing in the keystore can, since that is what a keystore looks like.
func loadLocalSigningKeyPair(baseDir string) (ed25519.PrivateKey, ed25519.PublicKey, bool, error) {
	privatePath, publicPath := LocalKeyPairPaths(baseDir)

	privateHex, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, nil, false, err
	}

	privateBytes, err := hex.DecodeString(strings.TrimSpace(string(privateHex)))
	if err != nil {
		return nil, nil, false, fmt.Errorf("invalid local private key encoding: %w", err)
	}
	if len(privateBytes) != ed25519.PrivateKeySize {
		return nil, nil, false, fmt.Errorf("invalid local private key size: expected %d bytes", ed25519.PrivateKeySize)
	}
	privateKey := ed25519.PrivateKey(privateBytes)

	// ed25519 documents Public() as returning an ed25519.PublicKey, so the
	// assertion holds by the standard library's own contract. It is checked
	// rather than taken bare because the alternative to an error nobody will
	// ever see is a panic in the one function every signature in this product
	// passes through.
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, false, fmt.Errorf("the local private key in %s did not yield an ed25519 public key",
			filepath.Clean(privatePath))
	}

	publicHex, err := os.ReadFile(publicPath)
	if os.IsNotExist(err) {
		return privateKey, publicKey, true, nil
	}
	if err != nil {
		return nil, nil, false, err
	}

	cachedBytes, err := hex.DecodeString(strings.TrimSpace(string(publicHex)))
	if err != nil {
		return nil, nil, false, fmt.Errorf("invalid local public key encoding: %w", err)
	}
	if len(cachedBytes) != ed25519.PublicKeySize {
		return nil, nil, false, fmt.Errorf("invalid local public key size: expected %d bytes", ed25519.PublicKeySize)
	}
	if !publicKey.Equal(ed25519.PublicKey(cachedBytes)) {
		return nil, nil, false, fmt.Errorf("the local keystore disagrees with itself: %s holds the public half "+
			"of a different key than %s. One of the two came from somewhere else, and a half-restored backup is "+
			"enough to do it. Which one is right is not for this to guess: the private key is what signed every "+
			"artifact already made, and the public key is what anyone verifying them is told to trust. Move the "+
			"public file aside to have it rebuilt from the private key, or put the matching pair back",
			filepath.Clean(publicPath), filepath.Clean(privatePath))
	}

	return privateKey, publicKey, false, nil
}

// claimLocalKeyStoreFile creates path with O_EXCL, so a private key is never
// written over a private key that is already there. An error os.IsExist agrees
// with means another process created it first, which is a race for the caller to
// resolve by reading and not a failure.
//
// The same discipline, for the same reason, as builtin.claimKeyFilePath -- which
// borrowed it from this defect while this defect was still here.
func claimLocalKeyStoreFile(path string, data []byte) error {
	handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}

	err = writeAndSyncKeyFile(handle, data)
	if closeErr := handle.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		// Whatever is at path was created by this call, because O_EXCL says so,
		// and removing it therefore destroys nobody's key. Leaving it would be
		// worse than the defect this function fixes: the size check in
		// loadLocalSigningKeyPair would refuse the stub on every later run, and
		// nothing would ever create the pair again, so the guard against
		// overwriting a key would have wedged the keystore instead.
		_ = os.Remove(path)
		return err
	}

	return nil
}

func writeAndSyncKeyFile(handle *os.File, data []byte) error {
	if _, err := handle.Write(data); err != nil {
		return err
	}

	return handle.Sync()
}

// writeLocalKeyStoreFile writes path through a temp file in the same directory
// and a rename, so a reader never sees a half-written key file.
//
// Only the public half is written this way. The private half is created with
// O_EXCL instead, because a rename replaces whatever is already at the name and
// replacing a private key is the thing being prevented. The public half is
// derived, so a second writer's copy is the same bytes and last-writer-wins is
// the behaviour wanted.
//
// The temp file goes in the same directory because a rename across filesystems
// is not atomic, and on Windows is not a rename at all.
func writeLocalKeyStoreFile(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".mutant-key-*")
	if err != nil {
		return err
	}

	name := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(name)
		}
	}()

	// 0600 before the content, so the window in which the file exists with the
	// default mode holds nothing. On Windows this is a statement of intent and
	// not an enforcement, as builtin.writeKeyFileAtomic records of the same
	// line.
	if err := temp.Chmod(0600); err != nil && !os.IsPermission(err) {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	committed = true

	return nil
}
