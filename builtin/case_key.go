package builtin

// The case key.
//
// A classified record is sealed under a key, and this is where that key comes
// from. Four builtins: mint one, open one for the life of a case, rotate it,
// and read what a key file claims about itself without opening it at all.
//
// # A path, never key material
//
// Every one of these takes a file path. None takes a passphrase, and
// `case_key_create` refuses an option called `passphrase` by name rather than
// ignoring it, because the refusal is the documentation. Key material in an
// argument is key material in program text, in a variable a traceback can
// print, and in a Go string that `security.SecureZero` cannot reach -- Go
// strings are immutable, which is the same reason `object.Bytes` exists and
// why `clearObject`'s String arm has always been a no-op it apologises for.
//
// The passphrase is asked for at the terminal, through the seam
// `security.SetPassphraseSource` publishes and `main` fills. That indirection
// is not ceremony. `builtin` cannot import `mutant/credential` and reach a
// terminal safely: `builtin/gets.go` already owns a package-level
// `bufio.Reader` over stdin, and two readers on one descriptor lose bytes
// between them. More to the point, under `go test` there is no terminal and no
// source is installed, so a conformance probe that calls `case_key_create`
// with a null argument cannot reach a passphrase, cannot reach crypto/rand and
// cannot create a file. That ordering is load-bearing and the tests assert it.
//
// docs/CONFIGURATION_POLICY.md settled the shape before any of this was
// written: "Key material never belongs in the environment. A key file path
// belongs on the command line."
//
// # Why there is no case_key_close
//
// `case_key_open` returns no handle. It requires an open case, refuses a key
// whose case id is not the open case's, and hangs the unwrapped key on the
// custody session; `case_close` zeroes it inside the lock it already holds.
//
// The alternative -- a handle with its own lifetime -- was rejected because
// `CaseClose` returns early when no case is open, so a key opened without a
// case would have no reachable way to be zeroed at all. Coupling the two makes
// the zeroing path unconditional. The honest cost is that `case_key_open` is
// an opener with no closer, which the language server's unclosed-resource rule
// cannot see; `case_open` already sits in that same gap for the same reason.

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mutant/object"
	"mutant/security"
)

// caseKeyCreateOptions, and the other three option sets, are listed rather
// than inferred so that a misspelled key is an error naming the accepted ones.
var (
	caseKeyCreateOptions = []string{"case_id", "sign"}
	caseKeyOpenOptions   = []string{"generation"}
	caseKeyRotateOptions = []string{"mode", "sign"}
)

// CaseKeyCreate mints a case key and writes it to a file that must not exist.
//
// The order of what follows is the order `case_bundle` established and it is
// not cosmetic: every argument is checked before anything reads crypto/rand,
// asks for a passphrase or touches the filesystem. The conformance probes call
// this function for real, with null and wrong-kind arguments, and a
// key-generating builtin that validated late would generate keys during
// `go test`.
func CaseKeyCreate(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	path, errObj := requireStringArg(BuiltinNameCaseKeyCreate, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(path) == "" {
		return resultAndError(nil, newError("%s: the path must not be empty", BuiltinNameCaseKeyCreate))
	}
	if errObj := refusePassphraseOption(BuiltinNameCaseKeyCreate, args, 2); errObj != nil {
		return resultAndError(nil, errObj)
	}
	opts, errObj := formatOptionsArg(BuiltinNameCaseKeyCreate, args, 2, caseKeyCreateOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	sign, errObj := opts.boolean("sign", true)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// The case id defaults to the open case's, which is the only value that
	// makes `case_key_open`'s later refusal meaningful.
	custodyStore.RLock()
	session, errObj := openSessionLocked(BuiltinNameCaseKeyCreate)
	if errObj != nil {
		custodyStore.RUnlock()
		return resultAndError(nil, errObj)
	}
	openCaseID := session.ID
	custodyStore.RUnlock()

	caseID, errObj := opts.str("case_id", openCaseID)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(caseID) == "" {
		return resultAndError(nil, newError("%s: the case id must not be empty", BuiltinNameCaseKeyCreate))
	}

	// Claiming the path with O_EXCL is the last cheap check and the first one
	// that can fail for a reason the caller cannot see from their arguments.
	handle, errObj := claimKeyFilePath(BuiltinNameCaseKeyCreate, path)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	// The claim is a placeholder. Everything below writes through a temp file
	// and a rename, so the claim is closed immediately and removed if the work
	// that follows fails.
	_ = handle.Close()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(path)
		}
	}()

	passphrase, err := security.RequestPassphrase(security.PassphraseRequest{
		Purpose: BuiltinNameCaseKeyCreate,
		Path:    path,
		Confirm: true,
	})
	if err != nil {
		return resultAndError(nil, passphraseError(BuiltinNameCaseKeyCreate, err))
	}
	defer security.SecureZero(passphrase)

	caseUID, err := security.RandomCaseUID()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyCreate, err.Error()))
	}
	// NewCaseKeyFile hands back the unwrapped CASE key, which this function has
	// no use for: it is already wrapped inside the file. What seals the file is
	// the WRAPPING key, derived separately from the same passphrase and the
	// salt the file now carries.
	file, caseKey, err := security.NewCaseKeyFile(passphrase, caseUID, caseID, custodyNow())
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyCreate, err.Error()))
	}
	security.SecureZero(caseKey)

	salt, err := file.SaltBytes()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyCreate, err.Error()))
	}
	wrapKey, err := security.DeriveWrappingKey(passphrase, salt, file.Version)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyCreate, err.Error()))
	}
	defer security.SecureZero(wrapKey)

	signed, detail, err := security.SealCaseKeyFile(file, wrapKey, sign)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyCreate, err.Error()))
	}
	document, err := security.MarshalCaseKeyFile(file)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyCreate, err.Error()))
	}
	if errObj := writeKeyFileAtomic(BuiltinNameCaseKeyCreate, path, document); errObj != nil {
		return resultAndError(nil, errObj)
	}
	committed = true

	generation, err := file.Generation(file.Current)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyCreate, err.Error()))
	}

	custodyRecordArtifact(BuiltinNameCaseKeyCreate,
		fmt.Sprintf("case key minted for case %s, generation %d", caseID, file.Current),
		caseKeyEventData(generation.Fingerprint, file.Current, "", signed))

	return resultAndError(makeHashObject(map[string]object.Object{
		"case_id":          stringObj(file.CaseID),
		"case_uid":         stringObj(file.CaseUID),
		"fingerprint":      stringObj(generation.Fingerprint),
		"generation":       intObj(int64(file.Current)),
		"key_id":           stringObj(custodyKeyID(generation.Fingerprint)),
		"kdf":              caseKeyKDFObject(file),
		"path":             stringObj(path),
		"signed":           boolObj(signed),
		"signature_detail": stringObj(detail),
		"status":           stringObj("ok"),
	}), nil)
}

// CaseKeyOpen unwraps a case key and holds it for the life of the case.
func CaseKeyOpen(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	path, errObj := requireStringArg(BuiltinNameCaseKeyOpen, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(path) == "" {
		return resultAndError(nil, newError("%s: the path must not be empty", BuiltinNameCaseKeyOpen))
	}
	if errObj := refusePassphraseOption(BuiltinNameCaseKeyOpen, args, 2); errObj != nil {
		return resultAndError(nil, errObj)
	}
	opts, errObj := formatOptionsArg(BuiltinNameCaseKeyOpen, args, 2, caseKeyOpenOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	wanted, errObj := caseKeyGenerationOption(BuiltinNameCaseKeyOpen, opts)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyStore.RLock()
	session, errObj := openSessionLocked(BuiltinNameCaseKeyOpen)
	if errObj != nil {
		custodyStore.RUnlock()
		return resultAndError(nil, errObj)
	}
	openCaseID, alreadyKeyed := session.ID, session.caseKey != nil
	custodyStore.RUnlock()

	if alreadyKeyed {
		return resultAndError(nil, newError("%s: a case key is already open for case %s. "+
			"One case has one key; close the case to open another",
			BuiltinNameCaseKeyOpen, openCaseID))
	}

	file, errObj := readKeyFile(BuiltinNameCaseKeyOpen, path)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	// Refused before the passphrase is asked for, so a mistyped path costs a
	// message rather than a prompt the examiner then answers for the wrong key.
	if file.CaseID != openCaseID {
		return resultAndError(nil, newError("%s: this key belongs to case %q and the open case is %q. "+
			"A key with no case has nothing to protect",
			BuiltinNameCaseKeyOpen, file.CaseID, openCaseID))
	}

	passphrase, err := security.RequestPassphrase(security.PassphraseRequest{
		Purpose: BuiltinNameCaseKeyOpen,
		Path:    path,
		Confirm: false,
	})
	if err != nil {
		return resultAndError(nil, passphraseError(BuiltinNameCaseKeyOpen, err))
	}
	defer security.SecureZero(passphrase)

	caseKey, wrapKey, err := security.OpenCaseKeyFile(file, passphrase, wanted)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyOpen, err.Error()))
	}
	security.SecureZero(wrapKey)

	generationNumber := wanted
	if generationNumber == 0 {
		generationNumber = file.Current
	}
	generation, err := file.Generation(generationNumber)
	if err != nil {
		security.SecureZero(caseKey)
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyOpen, err.Error()))
	}

	// Derived once, here, so that tagging a label later never touches K_case.
	classTagKey, err := security.ClassTagKey(caseKey)
	if err != nil {
		security.SecureZero(caseKey)
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyOpen, err.Error()))
	}

	signed, valid, detail := security.VerifyCaseKeyFileSignature(file)

	custodyStore.Lock()
	session, errObj = openSessionLocked(BuiltinNameCaseKeyOpen)
	if errObj != nil {
		custodyStore.Unlock()
		security.SecureZero(caseKey)
		security.SecureZero(classTagKey)
		return resultAndError(nil, errObj)
	}
	// Re-checked under the write lock: between the read above and here another
	// task could have opened one, and two case keys on one session would leave
	// one of them unzeroable.
	if session.caseKey != nil {
		custodyStore.Unlock()
		security.SecureZero(caseKey)
		security.SecureZero(classTagKey)
		return resultAndError(nil, newError("%s: a case key is already open for case %s. "+
			"One case has one key; close the case to open another",
			BuiltinNameCaseKeyOpen, session.ID))
	}
	session.caseKey = caseKey
	session.classTagKey = classTagKey
	session.keyPath = path
	session.keyFingerprint = generation.Fingerprint
	session.keyGeneration = generationNumber
	custodyStore.Unlock()

	custodyRecordArtifact(BuiltinNameCaseKeyOpen,
		fmt.Sprintf("case key opened for case %s, generation %d", file.CaseID, generationNumber),
		caseKeyEventData(generation.Fingerprint, generationNumber, "", signed))

	return resultAndError(makeHashObject(map[string]object.Object{
		"case_id":          stringObj(file.CaseID),
		"case_uid":         stringObj(file.CaseUID),
		"fingerprint":      stringObj(generation.Fingerprint),
		"generation":       intObj(int64(generationNumber)),
		"key_id":           stringObj(custodyKeyID(generation.Fingerprint)),
		"path":             stringObj(path),
		"signed":           boolObj(signed),
		"signature_valid":  boolObj(valid),
		"signature_detail": stringObj(detail),
		"status":           stringObj("ok"),
	}), nil)
}

// CaseKeyRotate changes the passphrase, or mints a new case key. They are two
// operations and `mode` has no default, because guessing which one an examiner
// meant is not something a key manager gets to do.
func CaseKeyRotate(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	path, errObj := requireStringArg(BuiltinNameCaseKeyRotate, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(path) == "" {
		return resultAndError(nil, newError("%s: the path must not be empty", BuiltinNameCaseKeyRotate))
	}
	if errObj := refusePassphraseOption(BuiltinNameCaseKeyRotate, args, 2); errObj != nil {
		return resultAndError(nil, errObj)
	}
	opts, errObj := formatOptionsArg(BuiltinNameCaseKeyRotate, args, 2, caseKeyRotateOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	mode, errObj := opts.str("mode", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if mode != "passphrase" && mode != "case_key" {
		return resultAndError(nil, newError("%s: mode must be \"passphrase\" or \"case_key\". "+
			"Changing the passphrase and minting a new case key are different operations and "+
			"guessing which one you meant is not something this can do safely",
			BuiltinNameCaseKeyRotate))
	}
	sign, errObj := opts.boolean("sign", true)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyStore.RLock()
	_, errObj = openSessionLocked(BuiltinNameCaseKeyRotate)
	custodyStore.RUnlock()
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	file, errObj := readKeyFile(BuiltinNameCaseKeyRotate, path)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	previousGeneration := file.Current
	previous, err := file.Generation(previousGeneration)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyRotate, err.Error()))
	}

	current, err := security.RequestPassphrase(security.PassphraseRequest{
		Purpose: BuiltinNameCaseKeyRotate,
		Path:    path,
		Confirm: false,
	})
	if err != nil {
		return resultAndError(nil, passphraseError(BuiltinNameCaseKeyRotate, err))
	}
	defer security.SecureZero(current)

	var wrapKey []byte
	switch mode {
	case "passphrase":
		replacement, err := security.RequestPassphrase(security.PassphraseRequest{
			Purpose: BuiltinNameCaseKeyRotate,
			Path:    path,
			Confirm: true,
		})
		if err != nil {
			return resultAndError(nil, passphraseError(BuiltinNameCaseKeyRotate, err))
		}
		defer security.SecureZero(replacement)
		if err := file.RotatePassphrase(current, replacement, custodyNow()); err != nil {
			return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyRotate, err.Error()))
		}
		salt, err := file.SaltBytes()
		if err != nil {
			return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyRotate, err.Error()))
		}
		wrapKey, err = security.DeriveWrappingKey(replacement, salt, file.Version)
		if err != nil {
			return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyRotate, err.Error()))
		}
	case "case_key":
		caseKey, err := file.RotateCaseKey(current, custodyNow())
		if err != nil {
			return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyRotate, err.Error()))
		}
		security.SecureZero(caseKey)
		salt, err := file.SaltBytes()
		if err != nil {
			return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyRotate, err.Error()))
		}
		wrapKey, err = security.DeriveWrappingKey(current, salt, file.Version)
		if err != nil {
			return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyRotate, err.Error()))
		}
	}
	defer security.SecureZero(wrapKey)

	signed, detail, err := security.SealCaseKeyFile(file, wrapKey, sign)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyRotate, err.Error()))
	}
	document, err := security.MarshalCaseKeyFile(file)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyRotate, err.Error()))
	}
	if errObj := writeKeyFileAtomic(BuiltinNameCaseKeyRotate, path, document); errObj != nil {
		return resultAndError(nil, errObj)
	}

	generation, err := file.Generation(file.Current)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameCaseKeyRotate, err.Error()))
	}

	custodyRecordArtifact(BuiltinNameCaseKeyRotate,
		fmt.Sprintf("case key rotated (%s) for case %s, generation %d -> %d",
			mode, file.CaseID, previousGeneration, file.Current),
		caseKeyEventData(generation.Fingerprint, file.Current, mode, signed))

	return resultAndError(makeHashObject(map[string]object.Object{
		"case_id":     stringObj(file.CaseID),
		"fingerprint": stringObj(generation.Fingerprint),
		"generation":  intObj(int64(file.Current)),
		"key_id":      stringObj(custodyKeyID(generation.Fingerprint)),
		"mode":        stringObj(mode),
		"path":        stringObj(path),
		// A record sealed before this call still opens: its header names the
		// generation it was sealed under and earlier generations are kept. The
		// count is zero here and the field exists so that item 2, which can
		// rewrap headers, is not a breaking change to this shape.
		"records_rewrapped":    intObj(0),
		"previous_generation":  intObj(int64(previousGeneration)),
		"previous_fingerprint": stringObj(previous.Fingerprint),
		"signed":               boolObj(signed),
		"signature_detail":     stringObj(detail),
		"status":               stringObj("ok"),
	}), nil)
}

// CaseKeyFingerprint reads what a key file says about itself.
//
// No passphrase, no Argon2, no unwrapping -- so `authenticated` is false and
// always will be. Everything returned is what the file CLAIMS; the signature
// narrows that to "what somebody holding this examiner's signing key claims",
// which is better than nothing and is not proof. Four bits rather than one,
// matching `case_manifest_verify` exactly so the two verifiers read the same
// way: `signed` says a signature is present, `signature_valid` says it checks,
// `signature_detail` says why when it does not, and `authenticated` says the
// file MAC -- the only check that needs the passphrase -- was not attempted.
func CaseKeyFingerprint(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg(BuiltinNameCaseKeyFingerprint, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(path) == "" {
		return resultAndError(nil, newError("%s: the path must not be empty", BuiltinNameCaseKeyFingerprint))
	}

	file, errObj := readKeyFile(BuiltinNameCaseKeyFingerprint, path)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	signed, valid, detail := security.VerifyCaseKeyFileSignature(file)

	generations := make([]object.Object, 0, len(file.Generations))
	for _, g := range file.Generations {
		generations = append(generations, makeHashObject(map[string]object.Object{
			"generation":  intObj(int64(g.Generation)),
			"created":     stringObj(g.Created),
			"fingerprint": stringObj(g.Fingerprint),
			"key_id":      stringObj(custodyKeyID(g.Fingerprint)),
		}))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"case_id":           stringObj(file.CaseID),
		"case_uid":          stringObj(file.CaseUID),
		"current":           intObj(int64(file.Current)),
		"generations":       &object.Array{Elements: generations},
		"authenticated":     boolObj(false),
		"signed":            boolObj(signed),
		"signature_valid":   boolObj(valid),
		"signature_detail":  stringObj(detail),
		"previous_file_mac": stringObj(file.PreviousFileMAC),
		"path":              stringObj(path),
		"status":            stringObj("ok"),
	}), nil)
}

// --- helpers ---

// refusePassphraseOption turns the most likely misuse into the clearest
// available lesson.
//
// It reads the raw hash rather than a parsed formatOptions, and runs BEFORE
// formatOptionsArg, because formatOptionsArg refuses any unknown key and would
// answer "unknown option \"passphrase\" (accepted: case_id, sign)" -- which is
// true, unhelpful, and reads as though the name were merely misspelled. The
// whole point of this refusal is that the option is not missing, it is
// forbidden, and silently ignoring it would leave an examiner believing they
// had supplied a passphrase.
func refusePassphraseOption(op string, args []object.Object, pos int) *object.Error {
	if len(args) < pos {
		return nil
	}
	hash, ok := args[pos-1].(*object.Hash)
	if !ok {
		return nil
	}
	for _, pair := range hash.Pairs {
		name, ok := pair.Key.(*object.String)
		if !ok {
			continue
		}
		switch name.Value {
		case "passphrase", "password", "secret", "key":
			return newError("%s: a passphrase is not an argument. Key material must not sit in "+
				"program text, in a variable a traceback can print, or in an unzeroable Go "+
				"string. It is asked for at the terminal", op)
		}
	}
	return nil
}

// caseKeyGenerationOption reads the optional generation number. Zero means
// "whichever the file says is current", which is what the schedule's own
// functions take.
func caseKeyGenerationOption(op string, opts *formatOptions) (uint32, *object.Error) {
	value, present := opts.pairs["generation"]
	if !present {
		return 0, nil
	}
	number, ok := value.(*object.Integer)
	if !ok {
		return 0, newError("%s: option %q must be INTEGER, got %s", op, "generation", value.Type())
	}
	if number.Value < 1 {
		return 0, newError("%s: generation %d does not exist; generations are numbered from 1",
			op, number.Value)
	}
	return uint32(number.Value), nil
}

// passphraseError explains the one failure an examiner will actually hit: a
// program run somewhere there is nobody to ask.
func passphraseError(op string, err error) *object.Error {
	if err == security.ErrNoPassphraseSource {
		return newError("%s: no passphrase source is installed in this process, so there is "+
			"nowhere to ask. Run the program with the mutant command line, which installs one; "+
			"a language server, a test run and an embedding host do not", op)
	}
	return newError("%s: %s", op, err.Error())
}

// claimKeyFilePath creates path with O_EXCL and refuses an existing file.
//
// The lesson is borrowed from a defect next door:
// `security.EnsureLocalSigningKeyPair` overwrites a private key when only the
// public half is missing. Applied to a case key the same mistake is
// unrecoverable -- every record sealed under the old key becomes unopenable
// and there is no copy anywhere.
func claimKeyFilePath(op, path string) (*os.File, *object.Error) {
	handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		return handle, nil
	}
	if os.IsExist(err) {
		return nil, newError("%s: %s already exists. Writing a key over a key makes every "+
			"record sealed under the old one unopenable, and there is no undo", op, path)
	}
	return nil, newError("%s: %s", op, err.Error())
}

// writeKeyFileAtomic writes through a temp file in the same directory and a
// rename.
//
// There was no atomic-write helper anywhere in this repository; this is the
// first, and it exists because this is the first file whose old contents cannot
// be reproduced. Every other writer here -- `writeArtifact`, `case_write` --
// writes a document that can be regenerated from the case, so a torn write
// costs a re-run. A torn key file costs the case.
//
// `writeArtifact` is deliberately not reused for a second reason: it reads the
// file back and returns its digest, and the digest of a key file is a value
// that should not reach the language.
//
// The temp file is created in the same directory because a rename across
// filesystems is not atomic and on Windows is not a rename at all.
func writeKeyFileAtomic(op, path string, data []byte) *object.Error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".mutant-key-*")
	if err != nil {
		return newError("%s: %s", op, err.Error())
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
	// not an enforcement: the observed mode there is -rw-rw-rw-, and a case
	// key's confidentiality on that platform rests on where the examiner put
	// it and on the passphrase.
	if err := temp.Chmod(0o600); err != nil && !os.IsPermission(err) {
		return newError("%s: %s", op, err.Error())
	}
	if _, err := temp.Write(data); err != nil {
		return newError("%s: %s", op, err.Error())
	}
	if err := temp.Sync(); err != nil {
		return newError("%s: %s", op, err.Error())
	}
	if err := temp.Close(); err != nil {
		return newError("%s: %s", op, err.Error())
	}
	if err := os.Rename(name, path); err != nil {
		return newError("%s: %s", op, err.Error())
	}
	committed = true
	return nil
}

// readKeyFile reads and parses, and says which of the two failed. A parse
// refusal here is the format-version check doing its job: the KDF block is
// pinned to the version and a file whose parameters differ is refused before
// Argon2 is asked to honour them.
func readKeyFile(op, path string) (*security.CaseKeyFile, *object.Error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, newError("%s: %s does not exist", op, path)
		}
		return nil, newError("%s: %s", op, err.Error())
	}
	file, err := security.ParseCaseKeyFile(raw)
	if err != nil {
		return nil, newError("%s: %s is not a usable case key file: %s", op, path, err.Error())
	}
	return file, nil
}

// caseKeyKDFObject renders the parameters the file records. They are reported
// rather than honoured: the parser refuses any file whose block is not the one
// pinned to its format version, so these numbers are a statement of what was
// used and not an instruction about what to use.
func caseKeyKDFObject(file *security.CaseKeyFile) object.Object {
	return makeHashObject(map[string]object.Object{
		"algorithm":  stringObj(file.KDF.Algorithm),
		"time":       intObj(int64(file.KDF.Time)),
		"memory_kib": intObj(int64(file.KDF.MemoryKiB)),
		"threads":    intObj(int64(file.KDF.Threads)),
		"key_len":    intObj(int64(file.KDF.KeyLen)),
	})
}

// caseKeyEventData is what a key operation writes into the case timeline.
//
// The path is deliberately absent, and that is a departure from
// `case_bundle`'s entry rather than an oversight. A case key is a file the
// examiner keeps away from the handover; a manifest that recorded where it
// lives would partly undo the reason it is a separate file at all. The
// fingerprint identifies the key, which is what an auditor needs; the path
// locates it, which is what an adversary needs.
func caseKeyEventData(fingerprint string, generation uint32, mode string, signed bool) map[string]any {
	data := map[string]any{
		"key_id":      custodyKeyID(fingerprint),
		"fingerprint": fingerprint,
		"generation":  int64(generation),
		"signed":      signed,
	}
	if mode != "" {
		data["mode"] = mode
	}
	return data
}

// caseKeyHexOK reports whether s is hex of exactly n bytes. Used by the tests
// and by nothing else; it lives here so the expectation is written beside the
// code that has to meet it.
func caseKeyHexOK(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
