package builtin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mutant/global"
	"mutant/object"
	"mutant/security"
)

func readDisclosureManifest(t *testing.T, dir string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, discloseManifestName))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var manifest map[string]any
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

// resealAsStranger is what anyone holding a package can do: edit the manifest,
// point its file digests and SHA256SUMS at whatever is in the directory now,
// and sign it with a key of their own. Only the seal's own check can tell, and
// it cannot: the signature holds over the edited document.
func resealAsStranger(t *testing.T, dir string, manifest map[string]any) {
	t.Helper()
	files, _ := manifest["files"].([]any)
	var sums []string
	for _, entry := range files {
		row := entry.(map[string]any)
		data, err := os.ReadFile(filepath.Join(dir, stringField(row, "name")))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		row["sha256"] = hex.EncodeToString(sum[:])
		sums = append(sums, fmt.Sprintf("%s  %s", row["sha256"], row["name"]))
	}
	sort.Strings(sums)
	if err := os.WriteFile(filepath.Join(dir, discloseChecksumsName), []byte(strings.Join(sums, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	delete(manifest, "seal")
	canonical, err := custodyCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := security.SignBytecode(canonical, stranger, global.Version)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	manifest["seal"] = map[string]any{
		"hash_algo":           "sha256",
		"manifest_hash":       hex.EncodeToString(digest[:]),
		"signed":              true,
		"signature_algorithm": signature.Algorithm,
		"signature":           hex.EncodeToString(signature.Signature),
		"public_key":          hex.EncodeToString(signature.PublicKey),
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, discloseManifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyPackage(t *testing.T, from string) string {
	t.Helper()
	to := filepath.Join(t.TempDir(), "forged")
	if err := os.MkdirAll(to, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(from, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, entry.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return to
}

// M26-REC-005. The ledger check proved only that the manifest's own copy of the
// Disclosure node is in the snapshot. Nothing compared that copy with the
// package around it, and the manifest's signature is checked against the key
// the manifest carries. So anyone holding one genuine package could relabel it,
// or swap in another disclosure's grant, re-sign the manifest with their own key
// and have it verify against the genuine root. The ledger's record of the
// disclosure is now held to the files in the package, property by property.
func TestAPackageTheLedgerDoesNotRecordFailsVerification(t *testing.T) {
	f := newDiscloseFixture(t)
	counselUID := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	regulatorUID := keyFieldString(t, f.issue(t, "regulator", "The regulator"), "disclosure_uid")
	regulatorDir, _ := f.bundle(t, regulatorUID)
	counselDir, root := f.bundle(t, counselUID)

	genuine := f.verify(t, counselDir, stringObj(root))
	if !discloseBool(t, genuine, "verified") {
		t.Fatalf("the genuine package does not verify: %v", discloseChecks(t, genuine))
	}
	for _, field := range []string{"manifest_public_key", "record_public_key"} {
		if key, _ := hashValueByKey(genuine, field).(*object.String); key == nil || key.Value == "" {
			t.Errorf("the result does not give %s, so a recipient cannot compare the signer with a key they trust", field)
		}
	}

	t.Run("relabelled and re-signed", func(t *testing.T) {
		dir := copyPackage(t, counselDir)
		manifest := readDisclosureManifest(t, dir)
		disclosure := manifestMap(manifest, "disclosure")
		disclosure["recipient"] = "Mallory"
		disclosure["recipient_fp"] = disclosureRecipientFingerprint("Mallory")
		disclosure["examiner"] = "Somebody Else"
		resealAsStranger(t, dir, manifest)

		result := f.verify(t, dir, stringObj(root))
		if discloseBool(t, result, "verified") {
			t.Fatalf("a package relabelled for Mallory verified: %v", discloseChecks(t, result))
		}
		if outcome := discloseChecks(t, result)["ledger_matches_package"]; !strings.Contains(outcome, "recipient") {
			t.Errorf("ledger_matches_package does not name the recipient: %q", outcome)
		}
	})

	t.Run("another disclosure's grant under this one's ledger record", func(t *testing.T) {
		dir := copyPackage(t, regulatorDir)
		counsel := readDisclosureManifest(t, counselDir)
		manifest := readDisclosureManifest(t, dir)
		manifest["ledger"] = counsel["ledger"]
		proof, err := os.ReadFile(filepath.Join(counselDir, discloseProofName))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, discloseProofName), proof, 0o600); err != nil {
			t.Fatal(err)
		}
		resealAsStranger(t, dir, manifest)

		result := f.verify(t, dir, stringObj(root))
		if discloseBool(t, result, "verified") {
			t.Fatalf("the regulator's grant verified as counsel's disclosure: %v", discloseChecks(t, result))
		}
		outcome := discloseChecks(t, result)["ledger_matches_package"]
		for _, want := range []string{"disclosure.uid", "disclosure.grant_sha256", "disclosure.granted_runs"} {
			if !strings.Contains(outcome, want) {
				t.Errorf("ledger_matches_package does not name %s: %q", want, outcome)
			}
		}
	})
}
