package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"testing"
)

// The local keystore holds the one thing in this product an operator cannot
// replace. Everything else Mutant writes can be rebuilt from the case; the
// private signing key is the reason a record sealed last year is still
// attributable, and there is no copy of it anywhere. These tests are the four
// ways the bootstrap used to put it at risk (M26-SEC-003).
//
// Every one of them goes through EnsureLocalSigningKeyPair and the testing
// override, and never through an internal function taking a directory. That is
// deliberate and it cost a redesign: a first draft called an unexported seam
// that the defective version of this file does not have, so it could not be
// compiled against the defect, let alone run there. A regression test that has
// only ever been run against the fix has not been shown to test anything.

func readKeyStoreFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func decodeKeyStoreHex(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimSpace(string(readKeyStoreFile(t, path))))
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return raw
}

// useKeyStore points the keystore at dir for the rest of the test.
func useKeyStore(t *testing.T, dir string) {
	t.Helper()
	SetLocalKeyStoreDirForTesting(dir)
	t.Cleanup(func() { SetLocalKeyStoreDirForTesting("") })
}

// The public file holds a value the private key already carries in its last
// thirty-two bytes, so losing it loses nothing. The bootstrap used to read that
// loss as "no keypair here" and generate a new one straight over the private
// key, which is how a migration or a backup restore that dropped one derived
// file destroyed an organisation's signing key.
//
// The private key file is compared as bytes and not only as a parsed key,
// because the defect was a write and a write is what has to be shown not to have
// happened.
func TestAMissingPublicFileIsRebuiltAndTheSigningKeyIsKept(t *testing.T) {
	dir := t.TempDir()
	useKeyStore(t, dir)
	privatePath, publicPath := LocalKeyPairPaths(dir)

	firstPrivate, firstPublic, created, _, err := EnsureLocalSigningKeyPair()
	if err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	if !created {
		t.Fatal("created = false on an empty directory, want true")
	}
	privateFileBefore := readKeyStoreFile(t, privatePath)

	if err := os.Remove(publicPath); err != nil {
		t.Fatalf("remove the public file: %v", err)
	}

	secondPrivate, secondPublic, created, _, err := EnsureLocalSigningKeyPair()
	if err != nil {
		t.Fatalf("second bootstrap with no public file: %v", err)
	}
	if created {
		t.Fatal("created = true: a missing public file made the bootstrap generate a new key, " +
			"which is the write that destroys the one already there")
	}
	if !bytes.Equal(firstPrivate, secondPrivate) {
		t.Fatal("the private key changed when only the public file was missing")
	}
	if got := readKeyStoreFile(t, privatePath); !bytes.Equal(privateFileBefore, got) {
		t.Fatalf("the private key file was rewritten: %d bytes before, %d after",
			len(privateFileBefore), len(got))
	}
	if !firstPublic.Equal(secondPublic) {
		t.Fatal("the public key returned changed, though the private key it comes from did not")
	}
	if rebuilt := decodeKeyStoreHex(t, publicPath); !secondPublic.Equal(ed25519.PublicKey(rebuilt)) {
		t.Fatal("the rebuilt public file does not hold the public half of the private key")
	}
}

// Two halves read independently can disagree, and a pair that disagreed used to
// load without complaint. Everything signed afterwards was signed with one key
// and published the other, so it verified as "the signature does not cover this
// header and these segments": a false tamper report on real evidence.
//
// The refusal has to reach the product and not only the loader, so the second
// half of this test seals a footer through SignRecordFooter and asserts it comes
// back unsigned with the reason. An unsigned record is a normal outcome this tree
// already reports as its own bit; a signature that cannot verify is not.
func TestASwappedPublicFileIsRefusedAndNothingIsSigned(t *testing.T) {
	dir := t.TempDir()
	useKeyStore(t, dir)
	privatePath, publicPath := LocalKeyPairPaths(dir)

	if _, _, _, _, err := EnsureLocalSigningKeyPair(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	privateFileBefore := readKeyStoreFile(t, privatePath)

	stranger, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate a second key: %v", err)
	}
	if err := os.WriteFile(publicPath, []byte(hex.EncodeToString(stranger.PublicKey)), 0600); err != nil {
		t.Fatalf("write the stranger's public key: %v", err)
	}

	_, _, _, _, err = EnsureLocalSigningKeyPair()
	if err == nil {
		t.Fatal("a public file holding a different key loaded without an error")
	}
	for _, want := range []string{"disagrees with itself", publicPath, privatePath} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not mention %q, so an operator cannot act on it: %v", want, err)
		}
	}
	if got := readKeyStoreFile(t, privatePath); !bytes.Equal(privateFileBefore, got) {
		t.Fatal("the private key file was rewritten while refusing a mismatched pair")
	}

	footer := &RecordFooter{}
	if err := SignRecordFooter(footer, []byte("header"), sha256.Sum256([]byte("segments")), true); err != nil {
		t.Fatalf("SignRecordFooter returned %v, want nil: a keystore that cannot be read is reported "+
			"on the footer, not as a sealing failure", err)
	}
	if footer.Signed {
		t.Fatal("signed = true against a mismatched keystore: the signature could not verify under " +
			"the key the footer publishes")
	}
	if footer.Signature != "" || footer.PublicKey != "" {
		t.Fatalf("an unsigned footer carries signature %q and public key %q", footer.Signature, footer.PublicKey)
	}
	if !strings.Contains(footer.SignatureReason, "disagrees with itself") {
		t.Fatalf("signature_reason = %q, want the keystore's own refusal", footer.SignatureReason)
	}
}

// The invariant underneath every signature in the product: a signature made with
// the keystore's private key verifies under the public key the keystore
// publishes. This runs it over a rebuilt public file, because that is the path
// which used to hand back a brand new key instead.
func TestASealedFooterVerifiesUnderThePublishedPublicKey(t *testing.T) {
	dir := t.TempDir()
	useKeyStore(t, dir)
	_, publicPath := LocalKeyPairPaths(dir)

	if _, _, _, _, err := EnsureLocalSigningKeyPair(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := os.Remove(publicPath); err != nil {
		t.Fatalf("remove the public file: %v", err)
	}

	header := []byte("a header stands in for every artifact this key signs")
	root := sha256.Sum256([]byte("the segments root"))
	footer := &RecordFooter{}
	if err := SignRecordFooter(footer, header, root, true); err != nil {
		t.Fatalf("SignRecordFooter: %v", err)
	}
	if !footer.Signed {
		t.Fatalf("signed = false, reason %q", footer.SignatureReason)
	}
	if footer.KeyCreatedForThisRun {
		t.Fatal("key_created_for_this_run = true: the key predates this call, and a footer that says " +
			"otherwise misdescribes how long the signer has been held")
	}

	published := decodeKeyStoreHex(t, publicPath)
	if footer.PublicKey != hex.EncodeToString(published) {
		t.Fatal("the footer publishes a different public key than the keystore file holds")
	}
	signature, err := hex.DecodeString(footer.Signature)
	if err != nil {
		t.Fatalf("decode the footer signature: %v", err)
	}
	message := RecordSigningMessage(header, root, footerMetaBytes(footer))
	if !ed25519.Verify(ed25519.PublicKey(published), message, signature) {
		t.Fatal("the footer's signature does not verify under the public key the keystore publishes, " +
			"which is what a mismatched pair looks like to everyone downstream")
	}
}

// Creation used to be two plain WriteFile calls with no lock and no O_EXCL.
// record_seal signs outside any custody lock and ledger_open takes none, so
// concurrent signers reaching a fresh keystore could interleave two bootstraps
// and leave the private key of one beside the public key of another; the
// auditor's eight goroutines did it in 92 of 200 attempts.
//
// A fresh directory per round, because the race is only reachable while the
// keystore does not yet exist. The override is written between rounds and only
// read inside them, which wg.Wait orders, so the directory is not itself the
// thing being raced over.
func TestConcurrentBootstrapsLeaveOneMatchingPair(t *testing.T) {
	const rounds, racers = 50, 8

	t.Cleanup(func() { SetLocalKeyStoreDirForTesting("") })

	for round := 0; round < rounds; round++ {
		dir := t.TempDir()
		SetLocalKeyStoreDirForTesting(dir)
		privatePath, publicPath := LocalKeyPairPaths(dir)

		privates := make([]ed25519.PrivateKey, racers)
		publics := make([]ed25519.PublicKey, racers)
		createdBy := make([]bool, racers)
		errs := make([]error, racers)

		var wg sync.WaitGroup
		wg.Add(racers)
		for i := 0; i < racers; i++ {
			go func(i int) {
				defer wg.Done()
				privates[i], publics[i], createdBy[i], _, errs[i] = EnsureLocalSigningKeyPair()
			}(i)
		}
		wg.Wait()

		creations := 0
		for i := 0; i < racers; i++ {
			if errs[i] != nil {
				t.Fatalf("round %d, caller %d: %v", round, i, errs[i])
			}
			if createdBy[i] {
				creations++
			}
			if !bytes.Equal(privates[0], privates[i]) {
				t.Fatalf("round %d: caller %d holds a different private key than caller 0", round, i)
			}
			if !publics[0].Equal(publics[i]) {
				t.Fatalf("round %d: caller %d holds a different public key than caller 0", round, i)
			}
		}
		if creations != 1 {
			t.Fatalf("round %d: %d of %d callers report creating the pair, want exactly 1",
				round, creations, racers)
		}

		// The files are the part that outlives the process, so they are what the
		// round is judged on. They are read directly rather than through the
		// loader, so that a loader which does not compare the two halves is
		// still measured by this test.
		onDiskPrivate := ed25519.PrivateKey(decodeKeyStoreHex(t, privatePath))
		onDiskPublic := ed25519.PublicKey(decodeKeyStoreHex(t, publicPath))
		derived, ok := onDiskPrivate.Public().(ed25519.PublicKey)
		if !ok {
			t.Fatalf("round %d: the private key on disk is not an ed25519 key", round)
		}
		if !derived.Equal(onDiskPublic) {
			t.Fatalf("round %d: the two files on disk are halves of different keys", round)
		}
		if !bytes.Equal(onDiskPrivate, privates[0]) || !onDiskPublic.Equal(publics[0]) {
			t.Fatalf("round %d: the pair on disk is not the pair the callers were given", round)
		}
	}
}

// The guard against overwriting a private key must hold for a private key that
// cannot be parsed, which is where replacing it looks most reasonable and is
// least recoverable: a key truncated by a full disk is still the only copy of the
// bytes that signed everything made before it, and an expert may get them back.
//
// Running this against the defect refined what the defect was. The ledger row
// describes the fall-through as firing when "only the public-key file is
// missing", but the old loader read the public file before it decoded the private
// one, so any missing public file sent an unreadable private key to the
// generator too -- the private key was overwritten without ever being looked at.
// The "no public file" cases below are the ones that failed there. The "public
// file present" cases refuse on both versions and are here to keep it that way,
// since the private key is now decoded first and that is the order which makes
// the refusal reachable at all.
func TestAMalformedPrivateKeyIsRefusedAndNotReplaced(t *testing.T) {
	// A public file that is well-formed and belongs to nothing: with a private
	// key this damaged there is no matching half to write.
	strangerPublic := strings.Repeat("ab", ed25519.PublicKeySize)

	for _, tc := range []struct {
		name    string
		private string
		public  string
		want    string
	}{
		{"not hex, no public file", "this is not hex at all", "", "invalid local private key encoding"},
		{"truncated, no public file", "aabbccdd", "", "invalid local private key size"},
		{"empty, no public file", "", "", "invalid local private key size"},
		{"not hex, public file present", "this is not hex at all", strangerPublic, "invalid local private key encoding"},
		{"truncated, public file present", "aabbccdd", strangerPublic, "invalid local private key size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			useKeyStore(t, dir)
			privatePath, publicPath := LocalKeyPairPaths(dir)
			if err := os.WriteFile(privatePath, []byte(tc.private), 0600); err != nil {
				t.Fatalf("write the damaged private key: %v", err)
			}
			if tc.public != "" {
				if err := os.WriteFile(publicPath, []byte(tc.public), 0600); err != nil {
					t.Fatalf("write the public file: %v", err)
				}
			}

			_, _, _, _, err := EnsureLocalSigningKeyPair()
			if err == nil {
				t.Fatal("a damaged private key bootstrapped without an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
			if got := readKeyStoreFile(t, privatePath); string(got) != tc.private {
				t.Fatalf("the damaged private key was rewritten: %q became %q", tc.private, got)
			}
		})
	}
}
