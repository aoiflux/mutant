package builtin

// The seal, and the reproducibility record (F-1, parts 3 and 4).
//
// A manifest that only makes claims about itself is worth very little. This file
// is what makes the claims checkable by somebody else:
//
//   - **manifest_hash** is SHA-256 over the canonical JSON of the manifest with
//     the seal removed. Anyone holding the document can recompute it.
//   - **the signature** is Ed25519 over those same bytes, from the local key
//     pair Mutant already maintains for bytecode signing. The public key travels
//     in the document, so verification needs nothing but the file.
//   - **the program record** names the artifact that produced the manifest and
//     its digest, which is the claim no other scripting DFIR toolkit makes: not
//     merely "a tool wrote this" but "this exact bytecode wrote this".
//
// Canonical means `json.Marshal` of the manifest map. Go sorts map keys, every
// number in a manifest is an integer, and verification decodes with
// `Decoder.UseNumber` so a round trip cannot turn 4096 into 4096.0. The file on
// disk is indented for a human to read; the canonical form is re-derived from
// the parsed document, so the indentation is not part of what is signed.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"mutant/global"
	"mutant/object"
	"mutant/security"
)

// custodyProgram is what the running artifact is, as the runner saw it before
// any of it executed.
type custodyProgram struct {
	Path   string
	Digest string
	Algo   string
}

var (
	custodyProgramMu sync.RWMutex
	custodyProgramID custodyProgram
)

// SetProgramIdentity records the artifact currently executing, so a case
// manifest can name what produced it.
//
// It is called by the runner with the signed bytecode it just read off disk and
// has not yet decoded -- the exact bytes, before anything could have altered
// them. A program reached by some other route (the REPL, the test runner, a
// library embedding the VM) never calls this, and the manifest then says
// `"recorded": false` rather than inventing an identity.
func SetProgramIdentity(path string, artifact []byte) {
	digest := sha256.Sum256(artifact)

	custodyProgramMu.Lock()
	custodyProgramID = custodyProgram{
		Path:   path,
		Digest: hex.EncodeToString(digest[:]),
		Algo:   "sha256",
	}
	custodyProgramMu.Unlock()
}

// custodyProgramRecord renders the reproducibility section.
func custodyProgramRecord() map[string]any {
	custodyProgramMu.RLock()
	identity := custodyProgramID
	custodyProgramMu.RUnlock()

	if identity.Digest == "" {
		return map[string]any{
			"recorded": false,
			"detail": "this program was not started through the Mutant runner, so the artifact " +
				"that produced this manifest cannot be named",
		}
	}
	return map[string]any{
		"recorded":  true,
		"path":      identity.Path,
		"hash":      identity.Digest,
		"hash_algo": identity.Algo,
	}
}

// resetProgramIdentityForTesting drops the recorded artifact.
func resetProgramIdentityForTesting() {
	custodyProgramMu.Lock()
	custodyProgramID = custodyProgram{}
	custodyProgramMu.Unlock()
}

// custodyCanonical returns the bytes a manifest's hash and signature are taken
// over: the document with its seal removed, marshalled compactly with sorted
// keys.
func custodyCanonical(manifest map[string]any) ([]byte, error) {
	withoutSeal := make(map[string]any, len(manifest))
	for key, value := range manifest {
		if key == "seal" {
			continue
		}
		withoutSeal[key] = value
	}
	return json.Marshal(withoutSeal)
}

// custodySeal computes the manifest's own hash and, when asked, signs it.
//
// Signing is not done for `case_manifest()` or `case_close()`: reading the key
// store -- and creating a key pair on a machine that has none -- is not something
// that should happen as a side effect of looking at a document. It happens when
// the document leaves the process, in `case_write`.
func custodySeal(manifest map[string]any, sign bool) error {
	canonical, err := custodyCanonical(manifest)
	if err != nil {
		// The document still gets a seal, saying plainly that it has no hash and
		// why. A missing field would read as an oversight.
		manifest["seal"] = map[string]any{
			"hash_algo":     "sha256",
			"manifest_hash": "",
			"signed":        false,
			"hash_error":    err.Error(),
		}
		return fmt.Errorf("the manifest cannot be canonicalised: %w", err)
	}
	digest := sha256.Sum256(canonical)

	seal := map[string]any{
		"hash_algo":     "sha256",
		"manifest_hash": hex.EncodeToString(digest[:]),
		"signed":        false,
		"covers":        "every field of this document except `seal`",
	}
	manifest["seal"] = seal
	if !sign {
		return nil
	}

	privateKey, _, generated, _, err := security.EnsureLocalSigningKeyPair()
	if err != nil {
		seal["signature_error"] = err.Error()
		return nil
	}

	signature, err := security.SignBytecode(canonical, privateKey, global.Version)
	if err != nil {
		seal["signature_error"] = err.Error()
		return nil
	}

	seal["signed"] = true
	seal["signature_algorithm"] = signature.Algorithm
	seal["signature"] = hex.EncodeToString(signature.Signature)
	seal["public_key"] = hex.EncodeToString(signature.PublicKey)
	seal["signed_at"] = time.Unix(signature.Timestamp, 0).UTC().Format(time.RFC3339)
	// The key's *location* is deliberately absent. A manifest is written to be
	// handed to someone else, the public key above is the whole of what a reader
	// needs to check the signature, and the path to the private key would be
	// both useless to them and a disclosure of where to go looking for it.
	seal["key_source"] = "the local Mutant signing key pair"
	seal["key_created_for_this_run"] = generated
	return nil
}

// CaseWrite writes the manifest to disk as a signed JSON document.
func CaseWrite(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `case_write` must be STRING, got %s", args[0].Type()))
	}
	if strings.TrimSpace(pathObj.Value) == "" {
		return resultAndError(nil, newError("case_write: the path must not be empty"))
	}

	sign := true
	if len(args) == 2 {
		sign = optBool(args[1], "sign", true)
	}

	custodyStore.RLock()
	session := custodyStore.session
	var manifest map[string]any
	if session != nil {
		manifest = session.manifest()
	}
	custodyStore.RUnlock()

	if session == nil {
		return resultAndError(nil, newError(
			"case_write: no case has been opened; call `case_open(id, examiner)` first"))
	}

	if err := custodySeal(manifest, sign); err != nil {
		return resultAndError(nil, newError("case_write: %s", err.Error()))
	}

	document, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return resultAndError(nil, newError("case_write: the manifest cannot be written as JSON: %s", err.Error()))
	}
	document = append(document, '\n')

	if err := os.WriteFile(pathObj.Value, document, 0o600); err != nil {
		return resultAndError(nil, newError("case_write: %s", err.Error()))
	}

	seal, _ := manifest["seal"].(map[string]any)
	signed, _ := seal["signed"].(bool)
	manifestHash, _ := seal["manifest_hash"].(string)
	result := map[string]any{
		"path":          pathObj.Value,
		"bytes":         int64(len(document)),
		"manifest_hash": manifestHash,
		"signed":        signed,
		"status":        "ok",
	}
	if reason, ok := seal["signature_error"].(string); ok {
		result["signature_error"] = reason
	}

	return custodyManifestResult(BuiltinNameCaseWrite, result)
}

// CaseManifestVerify checks a written manifest: that its contents still hash to
// the value in its seal, and that the signature over them holds.
//
// This is deliberately a function of the file alone. It does not need the case
// that produced it, the machine that wrote it, or any key the reader does not
// already have in their hands -- which is the difference between a document that
// asserts its own integrity and one whose integrity anybody can check.
func CaseManifestVerify(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `case_manifest_verify` must be STRING, got %s", args[0].Type()))
	}

	raw, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("case_manifest_verify: %s", err.Error()))
	}

	// UseNumber is what makes the round trip exact: without it every integer in
	// the document comes back as a float64 and re-marshals differently, so a
	// perfectly good manifest would fail its own hash check.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return resultAndError(nil, newError("case_manifest_verify: %s is not a manifest: %s", pathObj.Value, err.Error()))
	}

	seal, ok := document["seal"].(map[string]any)
	if !ok {
		return resultAndError(nil, newError(
			"case_manifest_verify: %s has no seal; it was not written by `case_write`", pathObj.Value))
	}

	canonical, err := custodyCanonical(document)
	if err != nil {
		return resultAndError(nil, newError("case_manifest_verify: %s", err.Error()))
	}
	digest := sha256.Sum256(canonical)
	recomputed := hex.EncodeToString(digest[:])
	recorded, _ := seal["manifest_hash"].(string)

	result := map[string]any{
		"path":             pathObj.Value,
		"manifest_hash":    recorded,
		"computed_hash":    recomputed,
		"hash_matches":     recorded != "" && recorded == recomputed,
		"signed":           false,
		"signature_valid":  false,
		"signature_detail": "this manifest carries no signature",
	}
	if caseInfo, ok := document["case"].(map[string]any); ok {
		result["case_id"], _ = caseInfo["id"].(string)
		result["examiner"], _ = caseInfo["examiner"].(string)
	}

	signed, _ := seal["signed"].(bool)
	if !signed {
		return custodyManifestResult(BuiltinNameCaseManifestVerify, result)
	}
	result["signed"] = true

	publicKey, keyErr := hex.DecodeString(stringField(seal, "public_key"))
	signature, sigErr := hex.DecodeString(stringField(seal, "signature"))
	switch {
	case keyErr != nil || len(publicKey) != ed25519.PublicKeySize:
		result["signature_detail"] = "the public key in the seal is not a valid Ed25519 key"
	case sigErr != nil || len(signature) != ed25519.SignatureSize:
		result["signature_detail"] = "the signature in the seal is not a valid Ed25519 signature"
	default:
		err := security.VerifyBytecode(canonical, &security.CodeSignature{
			PublicKey: publicKey,
			Signature: signature,
			Algorithm: stringField(seal, "signature_algorithm"),
		})
		if err != nil {
			result["signature_detail"] = err.Error()
		} else {
			result["signature_valid"] = true
			result["signature_detail"] = "the signature holds over this document's contents"
			result["public_key"] = stringField(seal, "public_key")
		}
	}

	return custodyManifestResult(BuiltinNameCaseManifestVerify, result)
}

// stringField reads a string out of a decoded JSON object, or "" when it is
// absent or another type.
func stringField(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}
