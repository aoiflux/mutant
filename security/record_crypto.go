package security

// The classified-record key schedule.
//
// This file does no I/O. It turns a passphrase into a case key, a case key into
// a wrapped record key, and a record key into per-segment keys, nonces and
// additional data -- and hands `builtin` bytes. Where a file lives, what mode
// it is created with and whether a write is atomic are decided in
// builtin/case_key.go, in one place a reviewer can read whole.
//
// The precedent is security/crypto.go and security/kdf.go: a versioned HKDF
// info string, a fresh nonce read with io.ReadFull(cryptoRand.Reader, ...), and
// `defer SecureZero(key)` on every derived key. It is NOT secure_random.go's
// SecureXORAt, which is unauthenticated and derives its nonce from the same
// inputs as its key.
//
// # What this file cannot do, stated first
//
// A segment key is symmetric, so it is a WRITE capability and not only a read
// capability. Anyone handed K_seg[i] can re-seal segment i with content of
// their choosing and OpenSegment will accept it. OpenSegment therefore means
// "written by a holder of this segment's key", which after any disclosure
// includes the recipient -- it does NOT mean "written by the examiner". That is
// why SealSegment also returns a digest: the record footer that will carry a
// signature over those digests is the only thing that can tell the examiner's
// bytes from a grant holder's, and it is not in this file.
//
// A per-segment tag also cannot see the record. Deleting trailing segments
// leaves every surviving segment individually valid unless the total is bound,
// which is why SegmentAAD carries the segment count -- but an older sealed
// version of the whole record has an identical AAD and is indistinguishable
// here. Rollback needs the ledger.
//
// Finally, a record is sealed ONCE. Re-sealing a record under the same record
// key and seal salt would reuse (key, nonce) against different plaintext, which
// is a total loss of confidentiality for both. The API makes that unspellable
// rather than discouraged: the only way to get a handle that can seal is
// NewRecordKeysForSeal, which mints both the record key and a fresh 16-byte
// seal salt itself, and a handle rebuilt from stored material can only open.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Versioned domain separators.
//
// A key drawn under one info string is unusable under any other, which is what
// lets a later version add a purpose without reusing bytes. The names follow
// HKDFInfoBytecode in kdf.go; none of these collides with it, with
// HKDFInfoSignature, or with mutil's instruction-key string.
const (
	// HKDFInfoCaseKeyFileMAC derives the key that authenticates the parts of a
	// case-key file no AEAD tag covers: which generation is current, and the
	// membership and order of the generation list.
	HKDFInfoCaseKeyFileMAC = "mutant-case-key-file-mac-v1"
	// HKDFInfoCaseKeyFingerprint names one generation's case key without
	// revealing it.
	HKDFInfoCaseKeyFingerprint = "mutant-case-key-fingerprint-v1"
	// HKDFInfoCaseClassTagKey derives the key a class label is tagged under, so
	// that a class tag is meaningless to anyone who does not hold the case key.
	HKDFInfoCaseClassTagKey = "mutant-case-class-tag-key-v1"
	// HKDFInfoRecordKeyWrap derives the key that wraps one record's key.
	HKDFInfoRecordKeyWrap = "mutant-record-key-wrap-v1"
	// HKDFInfoSegment derives one segment's key and nonce together, from a
	// digest of the whole of that segment's additional data.
	HKDFInfoSegment = "mutant-record-segment-v1"

	// ClassTagDomain prefixes the label inside the class tag's HMAC message, so
	// the tag cannot be confused with any other HMAC this tree computes.
	ClassTagDomain = "mutant-class-tag-v1|"
	// CaseKeyFileDomain opens the canonical form the file MAC and the signature
	// cover.
	CaseKeyFileDomain = "mutant-case-key-file-v1"
	// CaseKeyGenerationDomain opens the canonical form one generation's AEAD
	// tag covers.
	CaseKeyGenerationDomain = "mutant-case-key-generation-v1"
	// SegmentAADMagic is the first eight bytes of every segment's additional
	// data. It domain-separates this AEAD use from every other in the tree and
	// stops a later format's segment being opened as one of these.
	SegmentAADMagic = "MRECAAD1"

	// CaseKeyFileFormat is the value of a case-key file's "format" field.
	CaseKeyFileFormat = "mutant-case-key"
	// CaseKeyFileVersion is the version this build writes.
	CaseKeyFileVersion uint32 = 1
)

const (
	// KeySize is the size of a case key, a record key and a segment key.
	KeySize = chacha20poly1305.KeySize
	// CaseUIDSize is the length of the case identity bound into every segment.
	CaseUIDSize = 16
	// RecordUIDSize is the length of the random identifier that makes a
	// cross-record graft unrepresentable.
	RecordUIDSize = 16
	// SealSaltSize is the length of the per-seal salt that makes two seals of
	// the same record under the same key derive disjoint segment material.
	SealSaltSize = 16
	// CaseKeySaltSize is the Argon2id salt length.
	CaseKeySaltSize = 32
	// WrappedKeySize is a 32-byte key plus a 16-byte Poly1305 tag.
	WrappedKeySize = KeySize + chacha20poly1305.Overhead
	// SegmentAADSize is the fixed encoded width of a SegmentAAD.
	SegmentAADSize = 104
	// MaxSegmentPlaintext keeps every call far below the size at which
	// chacha20poly1305 panics instead of returning an error. A segment is a
	// unit of disclosure, not a unit of storage; a record has as many as it
	// needs.
	MaxSegmentPlaintext = 1 << 20
	// MaxClassLabel is the longest class label a tag will be computed over. A
	// label ends up in a report, a CSV and possibly a court exhibit.
	MaxClassLabel = 64
)

// argon2Profile is the Argon2id cost for one case-key file version.
//
// It is a table keyed by format version rather than a set of fields read off
// disk, and that is the whole point. To check any tag in the file you must
// first derive the wrapping key, and to derive it you must run Argon2 under
// some parameters -- so parameters a file supplies are parameters you honour
// before you can authenticate them. ValidateArgon2Params permits up to 4 GiB at
// eight passes, and a 4 GiB allocation is a Go runtime fatal rather than a
// recoverable error, which a builtin could never report. So the file's KDF
// block is compared against this table at parse time and the file is refused if
// it disagrees; the numbers are kept in the document and bound as additional
// data as a record of what was used, never as an instruction.
type argon2Profile struct {
	algorithm string
	time      uint32
	memoryKiB uint32
	threads   uint8
	keyLen    uint32
}

// caseKeyProfiles fixes the cost per format version.
//
// 256 MiB at three passes rather than DeriveKeyFromPassword's 64 MiB at one:
// that function protects a value derived while a program runs, and this one
// protects a file that sits at rest and is attacked offline, with the whole of
// the case behind it. The constant is put through ValidateArgon2Params by
// TestCaseKeyProfileIsInBand, which is a machine-checked statement that the
// number in this table is one the rest of the tree agrees is sane.
var caseKeyProfiles = map[uint32]argon2Profile{
	1: {algorithm: "argon2id", time: 3, memoryKiB: 256 * 1024, threads: 4, keyLen: KeySize},
}

// Errors this file returns by identity, so a caller can branch on the one
// distinction that is safe to make: whether there was anybody to ask.
var (
	// ErrNoPassphraseSource is what RequestPassphrase returns when nothing has
	// been installed, which is the state every `go test` run is in.
	ErrNoPassphraseSource = errors.New("no passphrase source is installed in this process, so there is nowhere to ask")
	// ErrEmptyPassphrase is returned rather than deriving a key from nothing.
	ErrEmptyPassphrase = errors.New("the passphrase is empty")
	// ErrSegmentAuth is the single failure every authentication failure reports.
	//
	// One error for a wrong key, a wrong position, a wrong class, a spliced
	// offset, a grafted record and a flipped byte, because an error that told
	// them apart would be an oracle. It deliberately does not say "authentic":
	// what a successful open proves is that the bytes were written by somebody
	// holding this segment's key, and after a disclosure that set is larger
	// than the examiner.
	ErrSegmentAuth = errors.New("the segment does not open under this key and position")
	// ErrCaseKeyAuth is the same discipline for the case-key file.
	ErrCaseKeyAuth = errors.New("the case key did not open: the passphrase is wrong, or the file has been edited")
)

// ---------------------------------------------------------------------------
// The passphrase seam
// ---------------------------------------------------------------------------

// PassphraseRequest says what is being unlocked and whether the answer has to
// be typed twice.
//
// Path is the key file, so a prompt can say which key it wants rather than
// asking for "the passphrase" in a program that holds several. Confirm is true
// on the paths that create key material, where a typo is unrecoverable, and
// false on the paths that only open it, where a wrong answer simply fails.
type PassphraseRequest struct {
	Purpose string
	Path    string
	Confirm bool
}

// PassphraseSource answers a PassphraseRequest.
//
// It is an interface for exactly the reason AuditSink is: the package that
// knows how to ask a terminal is `main`, and `security` cannot import it. The
// direction matters -- main.go imports mutant/security and does NOT import
// mutant/builtin, so this hole has to be here and not there.
//
// Implementations may be called from a spawned task's goroutine and must be
// safe for concurrent use. A source that cannot ask must return an error rather
// than block: a builtin that hangs on stdin takes the whole run with it.
type PassphraseSource interface {
	Passphrase(PassphraseRequest) ([]byte, error)
}

// passphraseSource holds a *PassphraseSource because atomic.Pointer needs
// something addressable, which is the shape SetAuditSink already uses.
var passphraseSource atomic.Pointer[PassphraseSource]

// SetPassphraseSource installs src and returns whatever it replaced, so a
// caller that borrows the seam -- a test, an embedding host -- can put back what
// was there. A nil source uninstalls.
//
// Nothing installs one by default, and that is the load-bearing part. Under
// `go test`, in the language server, in the WASM REPL and in an embedding host
// there is no source, so every path that needs a passphrase refuses by name
// before it reads crypto/rand or touches the filesystem. The conformance probes
// call these builtins for real; this is what makes "generate a key pair during
// go test" structurally impossible rather than merely ordered against.
func SetPassphraseSource(src PassphraseSource) PassphraseSource {
	var previous PassphraseSource
	if old := passphraseSource.Load(); old != nil {
		previous = *old
	}
	if src == nil {
		passphraseSource.Store(nil)
		return previous
	}
	passphraseSource.Store(&src)
	return previous
}

// PassphraseSourceInstalled reports whether there is anybody to ask, so a
// document can say "this run had no way to obtain a passphrase" rather than
// print a failure that reads like a wrong answer.
func PassphraseSourceInstalled() bool { return passphraseSource.Load() != nil }

// RequestPassphrase asks the installed source.
//
// The caller owns the returned bytes and must SecureZero them. An empty answer
// is refused here rather than at the KDF, so every caller gets the same
// sentence for it.
func RequestPassphrase(req PassphraseRequest) ([]byte, error) {
	src := passphraseSource.Load()
	if src == nil {
		return nil, ErrNoPassphraseSource
	}
	passphrase, err := (*src).Passphrase(req)
	if err != nil {
		return nil, err
	}
	if len(passphrase) == 0 {
		SecureZero(passphrase)
		return nil, ErrEmptyPassphrase
	}
	return passphrase, nil
}

// PassphraseForgetter is implemented by a source that remembers answers.
//
// Remembering is the whole of what makes a program that opens one key twice
// ask the examiner once, and it is also how a typo becomes permanent: an
// answer is remembered when it is typed, which is before anything has checked
// it, so a source that is never told an answer failed goes on serving the
// failure for the rest of the run without asking again.
type PassphraseForgetter interface {
	Forget(PassphraseRequest)
}

// ForgetPassphrase tells the installed source that the answer it gave for
// req.Path did not open what it was asked for, so the next request for that
// path asks again. A source that remembers nothing need not implement it.
//
// Called by every builtin whose passphrase failed to authenticate, and never
// with the passphrase itself: the source is told which question went wrong,
// not handed the secret a second time.
func ForgetPassphrase(req PassphraseRequest) {
	src := passphraseSource.Load()
	if src == nil {
		return
	}
	if forgetter, ok := (*src).(PassphraseForgetter); ok {
		forgetter.Forget(req)
	}
}

// ---------------------------------------------------------------------------
// Fixed-width types: a wrong length is a compile error, not a panic
// ---------------------------------------------------------------------------

// XNonce is an XChaCha20-Poly1305 nonce.
//
// It is an array passed by value, not a slice, because Seal and Open PANIC on a
// nonce of the wrong length -- with a plain string, not an error -- and a panic
// inside a builtin is uncatchable by the language and takes the VM down. A
// []byte of any length, and an array of any other length, are both compile
// errors at every call site. There is no runtime branch to forget.
type XNonce [chacha20poly1305.NonceSizeX]byte

// XNonceFromSlice is the one place a nonce read back off disk is measured.
//
// Segment nonces are derived and never stored, so they have no parse path at
// all; this exists for the key-wrap nonce, which is in the file.
func XNonceFromSlice(b []byte) (XNonce, error) {
	var n XNonce
	if len(b) != len(n) {
		return n, fmt.Errorf("a nonce must be %d bytes, got %d", len(n), len(b))
	}
	copy(n[:], b)
	return n, nil
}

// CaseUID is a case's identity, and it is deliberately NOT derived from the
// case key.
//
// It is bound into every segment's additional data, and a case-key rotation
// must not invalidate a single sealed record. A name derived from the key
// changes when the key changes, which would make "rotate the case key" mean
// "destroy every record" -- so the identity is 16 random bytes minted once by
// case_key_create and carried unchanged through every rotation. The value that
// does change per generation is the fingerprint, which names the key rather
// than the case and never enters a segment's additional data.
type CaseUID [CaseUIDSize]byte

// RecordUID names one record. It must be random and never a counter: two cases
// numbering from zero would collide, and the uid is what makes a cross-record
// graft unspellable.
type RecordUID [RecordUIDSize]byte

// ClassTag binds a class label into a segment without storing the label.
//
// It is keyed to the case, not a bare hash of the word. An unkeyed
// SHA-256("pii") is the same 32 bytes in every case ever sealed, so an attacker
// holding only the record recovers the classification of every segment from a
// dictionary of a dozen obvious labels, and can link cases by it. Keyed, it is
// 32 indistinguishable bytes to anyone without the case key -- and a disclosure
// recipient is handed the tag along with the segment material they need anyway,
// so nothing about a grant gets harder.
type ClassTag [sha256.Size]byte

// UnclassifiedTag is the tag of a segment carrying no class. It is the zero
// value, which means a caller that forgets to set a class binds "no class"
// rather than binding nothing.
var UnclassifiedTag ClassTag

// randomBytes reads n bytes with io.ReadFull rather than rand.Read.
//
// rand.Read never returns an error; it crashes the process irrecoverably
// instead, and a recover() cannot see it. io.ReadFull on the same Reader
// returns the error, which is the only shape a builtin can report. This matches
// security/crypto.go:53.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(cryptoRand.Reader, b); err != nil {
		return nil, fmt.Errorf("reading %d random bytes: %w", n, err)
	}
	return b, nil
}

// RandomCaseUID mints a case identity.
func RandomCaseUID() (CaseUID, error) {
	var uid CaseUID
	b, err := randomBytes(CaseUIDSize)
	if err != nil {
		return uid, err
	}
	copy(uid[:], b)
	return uid, nil
}

// RandomRecordUID mints a record identity.
func RandomRecordUID() (RecordUID, error) {
	var uid RecordUID
	b, err := randomBytes(RecordUIDSize)
	if err != nil {
		return uid, err
	}
	copy(uid[:], b)
	return uid, nil
}

// CaseUIDFromSlice and RecordUIDFromSlice are the parse paths for identities
// read back off disk.
func CaseUIDFromSlice(b []byte) (CaseUID, error) {
	var uid CaseUID
	if len(b) != len(uid) {
		return uid, fmt.Errorf("a case uid must be %d bytes, got %d", len(uid), len(b))
	}
	copy(uid[:], b)
	return uid, nil
}

func RecordUIDFromSlice(b []byte) (RecordUID, error) {
	var uid RecordUID
	if len(b) != len(uid) {
		return uid, fmt.Errorf("a record uid must be %d bytes, got %d", len(uid), len(b))
	}
	copy(uid[:], b)
	return uid, nil
}

// ---------------------------------------------------------------------------
// Derivation helpers
// ---------------------------------------------------------------------------

// expandFrom runs one HKDF-Extract and one HKDF-Expand.
//
// The stdlib crypto/hkdf rather than x/crypto/hkdf, for two reasons that are
// not speed. x/crypto's Extract PANICS on error -- its own comment says the
// only possible error is FIPS 140 enforcement, "which had to panic under this
// API anyway" -- and a panic inside a builtin is uncatchable. And Expand takes
// the output length explicitly, so there is no io.Reader with an entropy limit
// for a caller to mishandle.
func expandFrom(ikm, salt []byte, info string, length int) ([]byte, error) {
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, err
	}
	defer SecureZero(prk)
	return hkdf.Expand(sha256.New, prk, info, length)
}

// DeriveWrappingKey turns a passphrase into the key that wraps a case key.
//
// The parameters are chosen by the file's format version and are NOT an
// argument, because "fixed by the format version and not operator-tunable" is a
// property of an API, not of a comment. The passphrase is []byte the whole way
// down and is never converted to a string: a Go string is immutable, so a copy
// of a secret in one can never be erased, and SecureZero on the slice it came
// from leaves the copy intact.
//
// This does NOT call ReconstructKey. That function switches on an algorithm
// name, and its "hkdf-sha256" branch derives the key from the salt alone and
// ignores the password entirely -- so a file that named that algorithm would
// open under any passphrase at all.
func DeriveWrappingKey(passphrase []byte, salt []byte, version uint32) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}
	profile, ok := caseKeyProfiles[version]
	if !ok {
		return nil, fmt.Errorf("case-key format version %d is not one this build knows", version)
	}
	if len(salt) != CaseKeySaltSize {
		return nil, fmt.Errorf("the salt must be %d bytes, got %d", CaseKeySaltSize, len(salt))
	}
	key, err := deriveArgon2id(passphrase, salt, profile)
	if err != nil {
		return nil, fmt.Errorf("the built-in cost for version %d is out of band: %w", version, err)
	}
	return key, nil
}

// deriveArgon2id runs one fixed profile. Every passphrase in this package goes
// through it, so a profile that has drifted out of band is refused in one
// place rather than in each caller that remembered to check.
func deriveArgon2id(passphrase, salt []byte, profile argon2Profile) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}
	if err := ValidateArgon2Params(profile.time, profile.memoryKiB, profile.threads); err != nil {
		return nil, err
	}
	return argon2.IDKey(passphrase, salt, profile.time, profile.memoryKiB, profile.threads, profile.keyLen), nil
}

// FileMACKey derives the key that authenticates what no AEAD tag covers.
func FileMACKey(wrapKey []byte) ([]byte, error) {
	return expandFrom(wrapKey, nil, HKDFInfoCaseKeyFileMAC, 32)
}

// CaseKeyFingerprint names a case key without revealing it.
//
// It is a one-way function of the key, so it changes on a case-key rotation and
// does not change on a passphrase rotation -- which is exactly what a record
// header needs in order to say which generation opens it. It is not the case's
// identity; see CaseUID for why those must be two different values.
func CaseKeyFingerprint(caseKey []byte) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	if len(caseKey) != KeySize {
		return out, fmt.Errorf("a case key must be %d bytes, got %d", KeySize, len(caseKey))
	}
	b, err := expandFrom(caseKey, nil, HKDFInfoCaseKeyFingerprint, sha256.Size)
	if err != nil {
		return out, err
	}
	defer SecureZero(b)
	copy(out[:], b)
	return out, nil
}

// ClassTagKey derives the key a case's class labels are tagged under. The
// caller owns the bytes and must SecureZero them.
func ClassTagKey(caseKey []byte) ([]byte, error) {
	if len(caseKey) != KeySize {
		return nil, fmt.Errorf("a case key must be %d bytes, got %d", KeySize, len(caseKey))
	}
	return expandFrom(caseKey, nil, HKDFInfoCaseClassTagKey, 32)
}

// TagForClass computes the tag for an already-canonicalised label.
//
// The caller canonicalises and this function does not, so two callers cannot
// disagree about how. builtin/class.go owns the one definition of canonical.
func TagForClass(classTagKey []byte, canonicalLabel string) (ClassTag, error) {
	var tag ClassTag
	if len(classTagKey) != 32 {
		return tag, fmt.Errorf("a class-tag key must be 32 bytes, got %d", len(classTagKey))
	}
	if canonicalLabel == "" {
		return tag, errors.New("a class label must not be empty")
	}
	if len(canonicalLabel) > MaxClassLabel {
		return tag, fmt.Errorf("a class label must be at most %d bytes, got %d", MaxClassLabel, len(canonicalLabel))
	}
	mac := hmac.New(sha256.New, classTagKey)
	mac.Write([]byte(ClassTagDomain))
	mac.Write([]byte(canonicalLabel))
	copy(tag[:], mac.Sum(nil))
	return tag, nil
}

// RecordWrappingKey derives the key that wraps one record's key. The record uid
// is the extract salt, so every record wraps under a key of its own.
func RecordWrappingKey(caseKey []byte, uid RecordUID) ([]byte, error) {
	if len(caseKey) != KeySize {
		return nil, fmt.Errorf("a case key must be %d bytes, got %d", KeySize, len(caseKey))
	}
	return expandFrom(caseKey, uid[:], HKDFInfoRecordKeyWrap, KeySize)
}

// ---------------------------------------------------------------------------
// The AEAD, with every panic path closed
// ---------------------------------------------------------------------------

// sealWith encrypts under a 32-byte key and a typed nonce.
//
// chacha20poly1305 has four panic families and all four are closed here rather
// than avoided by care. The nonce length is a compile-time property of XNonce.
// The constructor's error is checked, because under FIPS-140-only mode -- which
// a `//go:debug fips140=only` directive in an embedding main package can set
// with no environment variable at all -- NewX returns nil and the next Seal is
// a nil dereference. The output buffer is allocated here and never supplied by
// a caller, so the inexact-overlap panics have nothing to overlap with. And the
// plaintext is bounded far below the 2^38 size limit.
func sealWith(key []byte, nonce XNonce, plaintext, aad []byte) ([]byte, error) {
	return sealWithLimit(key, nonce, plaintext, aad, MaxSegmentPlaintext, "a segment")
}

// sealWithLimit is sealWith under a bound the caller names. Only one caller
// needs a different one: a disclosure grant carries 56 bytes per granted
// segment, which for a large record is more than a segment is allowed to be
// and still four orders of magnitude inside the size at which the cipher
// panics. The bound is an argument rather than a second copy of this function
// so that the four closed panic paths stay closed in one place.
func sealWithLimit(key []byte, nonce XNonce, plaintext, aad []byte, limit int, what string) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("a key must be %d bytes, got %d", KeySize, len(key))
	}
	if len(plaintext) > limit {
		return nil, fmt.Errorf("%s must be at most %d bytes, got %d", what, limit, len(plaintext))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("segment cipher: %w", err)
	}
	dst := make([]byte, 0, len(plaintext)+aead.Overhead())
	return aead.Seal(dst, nonce[:], plaintext, aad), nil
}

// openWith is sealWith's inverse. It reports one error for every authentication
// failure, so nothing here is an oracle.
func openWith(key []byte, nonce XNonce, ciphertext, aad []byte, authErr error) ([]byte, error) {
	return openWithLimit(key, nonce, ciphertext, aad, authErr, MaxSegmentPlaintext, "a segment")
}

// openWithLimit is openWith under a bound the caller names; see sealWithLimit.
func openWithLimit(key []byte, nonce XNonce, ciphertext, aad []byte, authErr error, limit int, what string) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("a key must be %d bytes, got %d", KeySize, len(key))
	}
	if len(ciphertext) < chacha20poly1305.Overhead {
		return nil, authErr
	}
	if len(ciphertext) > limit+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("%s must be at most %d bytes, got %d",
			what, limit, len(ciphertext)-chacha20poly1305.Overhead)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("segment cipher: %w", err)
	}
	dst := make([]byte, 0, len(ciphertext)-aead.Overhead())
	plaintext, err := aead.Open(dst, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, authErr
	}
	return plaintext, nil
}

// ---------------------------------------------------------------------------
// The segment descriptor: a wrong AAD is not a value this program can express
// ---------------------------------------------------------------------------

// SegmentAAD is the additional data for one segment.
//
// Every field is unexported, so no package outside this one can write a
// literal, and neither SealSegment nor OpenSegment takes AAD bytes. The only
// way to obtain one is (*RecordKeys).SegmentAAD, which fills the case identity,
// the record identity, the segment count and the generation from the record you
// actually opened rather than from whatever the caller believed. A cross-record
// graft is not detected: it cannot be spelled.
//
// The descriptor is also what the segment's key and nonce are derived FROM, not
// merely what they are used alongside. That is the difference between "a
// different AAD is refused" and "a different AAD is a different keystream", and
// it is the whole reason this type exists. Deriving from the index alone -- the
// obvious design -- makes two seals that differ only in class, or only in
// offset, or only in length share a key and a nonce, which is a two-time pad
// that recovers both plaintexts with no key at all.
type SegmentAAD struct {
	caseUID    CaseUID
	recordUID  RecordUID
	index      uint64
	total      uint64
	offset     uint64
	length     uint32
	generation uint32
	classTag   ClassTag
}

// encode returns the fixed 104-byte form.
//
// An array and never a slice: it cannot be short, cannot be nil, and there is
// no append path that could grow it. That matters more than it looks, because a
// nil AAD and an empty AAD produce byte-identical ciphertext, so "forgot to
// pass the additional data" and "passed none" are indistinguishable. An array
// makes the question unaskable.
//
//	off  len  field
//	  0    8  magic "MRECAAD1"
//	  8   16  case uid            (stable across every rotation)
//	 24   16  record uid
//	 40    8  segment index       big endian
//	 48    8  segment count       big endian
//	 56    8  plaintext offset    big endian
//	 64    4  plaintext length    big endian
//	 68    4  sealed-under generation
//	 72   32  class tag
//	---  104
func (a SegmentAAD) encode() [SegmentAADSize]byte {
	var b [SegmentAADSize]byte
	copy(b[0:8], SegmentAADMagic)
	copy(b[8:24], a.caseUID[:])
	copy(b[24:40], a.recordUID[:])
	binary.BigEndian.PutUint64(b[40:48], a.index)
	binary.BigEndian.PutUint64(b[48:56], a.total)
	binary.BigEndian.PutUint64(b[56:64], a.offset)
	binary.BigEndian.PutUint32(b[64:68], a.length)
	binary.BigEndian.PutUint32(b[68:72], a.generation)
	copy(b[72:104], a.classTag[:])
	return b
}

// Index, Total, Offset, Length and ClassTag report what this descriptor names,
// for a caller that has to put it in a manifest. There are no setters: a
// descriptor is what the record said, not what a caller would like it to say.
func (a SegmentAAD) Index() uint64      { return a.index }
func (a SegmentAAD) Total() uint64      { return a.total }
func (a SegmentAAD) Offset() uint64     { return a.offset }
func (a SegmentAAD) Length() uint32     { return a.length }
func (a SegmentAAD) ClassTag() ClassTag { return a.classTag }

// ---------------------------------------------------------------------------
// The per-record schedule
// ---------------------------------------------------------------------------

// RecordKeys is one record's key schedule.
//
// It holds the record's identity as well as its material, which is what lets
// SegmentAAD fill the identity fields from the record itself. It also holds
// whether it may seal: a handle built by NewRecordKeysForSeal may, and a handle
// rebuilt from stored material by OpenRecordKeys may not. That is not a
// courtesy check. Sealing twice from stored material would reuse (key, nonce)
// at every index, and the tree's own idiom -- six ledger_redact_* builtins --
// is "re-seal this position with the content removed", which is precisely the
// case where the original plaintext must be unrecoverable.
//
// sealable alone was not enough, and the gap is worth recording because the
// defence was written for exactly the case it missed. It stops a SECOND handle
// sealing over a first. It stopped nothing inside one: a sealable handle would
// seal index 3 twice, and since the key and the nonce are derived from the
// descriptor -- which names the position and not the plaintext -- the two
// ciphertexts were one keystream over two messages, from which XOR returns both
// with no key at all. The redaction idiom named above reaches that in a single
// step, because re-sealing a position with the content removed IS one index
// sealed twice.
//
// nextIndex closes it. A sealable handle seals segment 0, then 1, then 2, and
// any other index is refused. Refusing is the only fix available: OpenSegment
// has to re-derive a segment's material from its descriptor alone, so the
// keystream cannot be varied per seal without making the record unopenable.
// Eight bytes also make two other shapes unrepresentable that nothing here was
// checking -- a record with a gap in it, and a record whose segments were
// sealed out of order.
type RecordKeys struct {
	caseUID    CaseUID
	uid        RecordUID
	generation uint32
	total      uint64
	prk        []byte
	sealable   bool
	// nextIndex is the only index SealSegment will accept. It advances on a
	// successful seal and never rewinds, so a handle that reaches total has
	// sealed every segment of the record exactly once.
	nextIndex uint64
}

// NewRecordKeysForSeal mints a record key and a seal salt and returns a handle
// that can seal.
//
// The record key is returned so the caller can wrap it into the record header
// and must SecureZero it afterwards; the seal salt goes in the header in the
// clear. The caller does not supply either, which is what makes a two-time pad
// unrepresentable rather than merely discouraged: there is no way to ask this
// package to seal a second record under material that has sealed one before.
//
// generation is the case-key generation the record is being sealed under, and
// it never changes again. A rotation migration rewraps the 32 bytes of record
// key in the header under a new generation's case key; the generation bound
// into the segments is the one it was SEALED under and rewrapping must not
// touch it. Those are two different fields in the record header and confusing
// them makes every segment of a migrated record permanently unopenable.
//
// total is the number of segments the record will have. It is fixed before the
// first seal on purpose: a segment count that is decided as you go is a segment
// count nothing can bind, and then dropping the tail of a record leaves every
// surviving segment individually valid.
func NewRecordKeysForSeal(caseUID CaseUID, uid RecordUID, generation uint32, total uint64) (keys *RecordKeys, recordKey, sealSalt []byte, err error) {
	if total == 0 {
		return nil, nil, nil, errors.New("a record must have at least one segment")
	}
	recordKey, err = randomBytes(KeySize)
	if err != nil {
		return nil, nil, nil, err
	}
	sealSalt, err = randomBytes(SealSaltSize)
	if err != nil {
		SecureZero(recordKey)
		return nil, nil, nil, err
	}
	keys, err = newRecordKeys(caseUID, uid, generation, total, recordKey, sealSalt, true)
	if err != nil {
		SecureZero(recordKey)
		return nil, nil, nil, err
	}
	return keys, recordKey, sealSalt, nil
}

// OpenRecordKeys rebuilds a record's schedule from material recovered out of
// its header. The handle it returns can open and cannot seal.
func OpenRecordKeys(caseUID CaseUID, uid RecordUID, generation uint32, total uint64, recordKey, sealSalt []byte) (*RecordKeys, error) {
	return newRecordKeys(caseUID, uid, generation, total, recordKey, sealSalt, false)
}

// newRecordKeys runs the one HKDF-Extract per record.
//
// Extract once, then a fresh Expand per segment. A single HKDF reader yields
// 255 * sha256.Size = 8160 bytes and then returns "hkdf: entropy limit reached"
// -- and at 32 bytes of key plus 24 of nonce that is floor(8160/56) = 145
// segments, after which a record simply stops being writable mid-write. A fresh
// Expand restarts the counter at 1 and nothing accumulates, so there is no cap
// at all. The seal salt is in the extract salt beside the uid, so two seals of
// the same record identity derive disjoint material even if a caller re-mints a
// record with the same uid.
func newRecordKeys(caseUID CaseUID, uid RecordUID, generation uint32, total uint64, recordKey, sealSalt []byte, sealable bool) (*RecordKeys, error) {
	if len(recordKey) != KeySize {
		return nil, fmt.Errorf("a record key must be %d bytes, got %d", KeySize, len(recordKey))
	}
	if len(sealSalt) != SealSaltSize {
		return nil, fmt.Errorf("a seal salt must be %d bytes, got %d", SealSaltSize, len(sealSalt))
	}
	if total == 0 {
		return nil, errors.New("a record must have at least one segment")
	}
	salt := make([]byte, 0, RecordUIDSize+SealSaltSize)
	salt = append(salt, uid[:]...)
	salt = append(salt, sealSalt...)
	prk, err := hkdf.Extract(sha256.New, recordKey, salt)
	if err != nil {
		return nil, err
	}
	return &RecordKeys{
		caseUID:    caseUID,
		uid:        uid,
		generation: generation,
		total:      total,
		prk:        prk,
		sealable:   sealable,
	}, nil
}

// Zero releases the pseudorandom key. Read the honest limits for what it does
// not reach: chacha20poly1305 copies a key into a struct this code cannot see,
// SecureZero honours len and not cap, and a value passed by value leaves a
// stack copy nothing can clear.
func (r *RecordKeys) Zero() {
	if r == nil {
		return
	}
	SecureZero(r.prk)
	r.prk = nil
	r.sealable = false
}

// UID, SealedUnderGeneration and Total report the record identity the segments
// are bound to.
//
// SealedUnderGeneration is named at length on purpose. It is the generation the
// record was sealed under and it never changes. The generation whose case key
// currently wraps the record key is a SEPARATE field in the record header, and
// it is the only one a rotation migration may touch.
func (r *RecordKeys) UID() RecordUID                { return r.uid }
func (r *RecordKeys) CaseUID() CaseUID              { return r.caseUID }
func (r *RecordKeys) SealedUnderGeneration() uint32 { return r.generation }
func (r *RecordKeys) Total() uint64                 { return r.total }
func (r *RecordKeys) CanSeal() bool                 { return r != nil && r.sealable }

// SealedCount reports how many segments have been sealed through this handle
// and SealComplete whether that was all of them.
//
// Item 2's record footer needs both. A signature over the segment digests is a
// claim about a whole record, and a record with an unsealed segment is one this
// package will never refuse to open -- the segments that do exist are each
// individually valid, which is the point of per-segment authentication and also
// its blind spot. Nothing downstream can notice the absence, so the check has
// to happen where the sealing did.
func (r *RecordKeys) SealedCount() uint64 {
	if r == nil {
		return 0
	}
	return r.nextIndex
}

// SealComplete is false for a handle that cannot seal at all, which is the
// honest answer: an opening handle has sealed nothing.
func (r *RecordKeys) SealComplete() bool {
	return r != nil && r.sealable && r.nextIndex == r.total
}

// SegmentAAD describes one segment of this record.
//
// The caller chooses the index, the offset in the plaintext, the length and the
// class. It cannot choose the case, the record, the segment count or the
// generation: those come from the handle.
func (r *RecordKeys) SegmentAAD(index, offset uint64, length uint32, class ClassTag) SegmentAAD {
	return SegmentAAD{
		caseUID:    r.caseUID,
		recordUID:  r.uid,
		index:      index,
		total:      r.total,
		offset:     offset,
		length:     length,
		generation: r.generation,
		classTag:   class,
	}
}

// segmentMaterial derives one segment's key and nonce from a digest of the
// whole descriptor.
//
// The info string carries the SHA-256 of all 104 AAD bytes, not the index, so
// every field that binds the segment also separates its keystream. A caller who
// changes the class, the offset, the length, the count or the generation gets a
// different key and a different nonce, and cannot produce a two-time pad by
// changing anything the AAD names. Key and nonce come out of one 56-byte Expand
// so the two cannot be drawn out of step.
func (r *RecordKeys) segmentMaterial(aad [SegmentAADSize]byte) (key []byte, nonce XNonce, err error) {
	digest := sha256.Sum256(aad[:])
	material, err := hkdf.Expand(sha256.New, r.prk, HKDFInfoSegment+"|"+hex.EncodeToString(digest[:]), KeySize+len(nonce))
	if err != nil {
		return nil, nonce, err
	}
	key = make([]byte, KeySize)
	copy(key, material[:KeySize])
	copy(nonce[:], material[KeySize:])
	SecureZero(material)
	return key, nonce, nil
}

// SealSegment encrypts one segment and reports what it became.
//
// The digest is SHA-256 over the additional data followed by the ciphertext.
// Item 1 does not use it; it is returned because item 2's record footer has to
// carry a signature over the segments, and that signature is the ONLY thing
// that will distinguish bytes the examiner wrote from bytes a disclosure
// recipient wrote. Reserving it now costs nothing; adding it after a record
// format exists costs a version.
func (r *RecordKeys) SealSegment(aad SegmentAAD, plaintext []byte) (ciphertext []byte, digest [sha256.Size]byte, err error) {
	if r == nil || r.prk == nil {
		return nil, digest, errors.New("the record key schedule has been zeroed")
	}
	if !r.sealable {
		return nil, digest, errors.New(
			"this record handle can only open: a record is sealed once, and sealing again under the same " +
				"key and seal salt would reuse a nonce. Mint a new record with NewRecordKeysForSeal")
	}
	if aad.index >= aad.total {
		return nil, digest, fmt.Errorf("segment %d is out of range for a record of %d segments", aad.index, aad.total)
	}
	// In order, and each index exactly once. Sealing an index twice would put
	// two plaintexts under one keystream, because the descriptor this material
	// is derived from names the position and not the content; the second
	// ciphertext XORed against the first returns both messages without a key.
	// A caller that wants to change what a position holds mints a new record.
	if aad.index != r.nextIndex {
		return nil, digest, fmt.Errorf(
			"segment %d cannot be sealed here: this record has sealed %d of its %d segments and the next "+
				"one it will accept is %d. A record is sealed once, in order, and every segment exactly "+
				"once -- sealing a position twice would put two plaintexts under one keystream. To change "+
				"what a position holds, mint a new record",
			aad.index, r.nextIndex, r.total, r.nextIndex)
	}
	if int(aad.length) != len(plaintext) {
		return nil, digest, fmt.Errorf("the segment says it is %d bytes and the buffer is %d", aad.length, len(plaintext))
	}
	encoded := aad.encode()
	key, nonce, err := r.segmentMaterial(encoded)
	if err != nil {
		return nil, digest, err
	}
	defer SecureZero(key)

	ciphertext, err = sealWith(key, nonce, plaintext, encoded[:])
	if err != nil {
		return nil, digest, err
	}
	h := sha256.New()
	h.Write(encoded[:])
	h.Write(ciphertext)
	copy(digest[:], h.Sum(nil))

	// Advanced only now, so a seal that failed before emitting anything can be
	// retried at the same index. There is no ciphertext from the failed attempt
	// for a retry to collide with.
	r.nextIndex++
	return ciphertext, digest, nil
}

// OpenSegment decrypts one segment.
//
// A successful open proves the bytes were written by somebody holding this
// segment's key at this position. It does not prove they were written by the
// examiner, and after a disclosure it positively does not: a grant of segment
// keys is a grant to write those segments. The error says "does not open"
// rather than "is not authentic" for that reason.
func (r *RecordKeys) OpenSegment(aad SegmentAAD, ciphertext []byte) ([]byte, error) {
	if r == nil || r.prk == nil {
		return nil, errors.New("the record key schedule has been zeroed")
	}
	if aad.index >= aad.total {
		return nil, fmt.Errorf("segment %d is out of range for a record of %d segments", aad.index, aad.total)
	}
	encoded := aad.encode()
	key, nonce, err := r.segmentMaterial(encoded)
	if err != nil {
		return nil, err
	}
	defer SecureZero(key)

	plaintext, err := openWith(key, nonce, ciphertext, encoded[:], ErrSegmentAuth)
	if err != nil {
		return nil, err
	}
	if len(plaintext) != int(aad.length) {
		SecureZero(plaintext)
		return nil, ErrSegmentAuth
	}
	return plaintext, nil
}

// WrapRecordKey seals a record key under a case key, bound to the record.
//
// The nonce is drawn inside this function and returned, never supplied. A
// caller who reused a stored nonce across two wraps of the same plaintext under
// the same key would reuse the Poly1305 one-time key, which hands an attacker
// the material to forge a tag. There is no parameter through which to do it.
func WrapRecordKey(caseKey []byte, uid RecordUID, recordKey []byte) (nonce XNonce, wrapped []byte, err error) {
	if len(recordKey) != KeySize {
		return nonce, nil, fmt.Errorf("a record key must be %d bytes, got %d", KeySize, len(recordKey))
	}
	wrapKey, err := RecordWrappingKey(caseKey, uid)
	if err != nil {
		return nonce, nil, err
	}
	defer SecureZero(wrapKey)

	raw, err := randomBytes(len(nonce))
	if err != nil {
		return nonce, nil, err
	}
	copy(nonce[:], raw)
	wrapped, err = sealWith(wrapKey, nonce, recordKey, uid[:])
	if err != nil {
		return nonce, nil, err
	}
	return nonce, wrapped, nil
}

// UnwrapRecordKey recovers a record key. The caller owns the bytes and must
// SecureZero them.
func UnwrapRecordKey(caseKey []byte, uid RecordUID, nonce XNonce, wrapped []byte) ([]byte, error) {
	wrapKey, err := RecordWrappingKey(caseKey, uid)
	if err != nil {
		return nil, err
	}
	defer SecureZero(wrapKey)
	return openWith(wrapKey, nonce, wrapped, uid[:],
		errors.New("this record key was not wrapped by this case key for this record"))
}

// ---------------------------------------------------------------------------
// The case-key file
// ---------------------------------------------------------------------------

// CaseKeyKDF records how the wrapping key was derived.
//
// It is documentation and an authenticated input, never an instruction: the
// parameters this build will actually run are chosen by Version and compared
// against these at parse time, and a file that disagrees is refused.
type CaseKeyKDF struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	KeyLen    uint32 `json:"key_len"`
}

// CaseKeyGeneration is one case key as it appears on disk: wrapped, beside the
// cleartext metadata its own AEAD tag covers.
type CaseKeyGeneration struct {
	Generation  uint32 `json:"generation"`
	Created     string `json:"created"`
	Fingerprint string `json:"fingerprint"`
	Nonce       string `json:"nonce"`
	Wrapped     string `json:"wrapped"`
}

// CaseKeyFile is a parsed key file. Nothing in it is secret; the secrets are
// inside Generations[i].Wrapped.
//
// It is JSON so an examiner can read it and a reviewer can diff it, but nothing
// is ever authenticated over the JSON text: JSON has no canonical byte form, so
// authenticating the document would make a re-serialisation a forgery. The
// authenticated object is the length-prefixed canonical form below, and the
// JSON is transport.
type CaseKeyFile struct {
	Format          string              `json:"format"`
	Version         uint32              `json:"version"`
	CaseUID         string              `json:"case_uid"`
	CaseID          string              `json:"case_id"`
	Created         string              `json:"created"`
	Rotated         string              `json:"rotated"`
	KDF             CaseKeyKDF          `json:"kdf"`
	Current         uint32              `json:"current"`
	Generations     []CaseKeyGeneration `json:"generations"`
	PreviousFileMAC string              `json:"previous_file_mac"`
	FileMAC         string              `json:"file_mac"`
	Signer          string              `json:"signer"`
	Signature       string              `json:"signature"`
}

// appendField writes a length-prefixed field, so a value containing a
// separator cannot be read as two fields and the encoding is injective with no
// delimiters to spell.
func appendField(dst []byte, field []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(field)))
	dst = append(dst, n[:]...)
	return append(dst, field...)
}

func appendString(dst []byte, s string) []byte { return appendField(dst, []byte(s)) }

func appendU32(dst []byte, v uint32) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], v)
	return append(dst, n[:]...)
}

// CanonicalGeneration is the additional data one generation's wrap is bound to.
//
// It covers the case identity, the case id, the format version, the generation
// number, the fingerprint, the creation time and the whole KDF block including
// the salt. So a generation blob cannot be moved to another key file, another
// case, or another generation slot. It deliberately does NOT cover `current` or
// the membership of the generation list -- binding those would mean that
// appending a generation invalidated the seal on every generation it
// supersedes, which would make the first rotation lock the examiner out of
// every record not yet rewrapped. Those are the file MAC's job.
func (f *CaseKeyFile) CanonicalGeneration(g CaseKeyGeneration) []byte {
	out := make([]byte, 0, 256)
	out = appendString(out, CaseKeyGenerationDomain)
	out = appendU32(out, f.Version)
	out = appendString(out, f.CaseUID)
	out = appendString(out, f.CaseID)
	out = appendU32(out, g.Generation)
	out = appendString(out, g.Created)
	out = appendString(out, g.Fingerprint)
	out = appendString(out, f.KDF.Algorithm)
	out = appendU32(out, f.KDF.Time)
	out = appendU32(out, f.KDF.MemoryKiB)
	out = appendU32(out, uint32(f.KDF.Threads))
	out = appendU32(out, f.KDF.KeyLen)
	out = appendString(out, f.KDF.Salt)
	return out
}

// CanonicalFile is what the file MAC and the signature cover: everything,
// including `current`, the membership and order of the generation list, the
// signer, and the MAC of the file this one replaced.
//
// previous_file_mac is what makes the sequence of versions linear rather than a
// set. It does not stop a rollback on its own -- nothing inside a file can, and
// restoring yesterday's copy produces a file whose MAC and signature both
// verify -- but it is the field the ledger anchors in item 4, and without it
// there would be nowhere to put the anchor.
func (f *CaseKeyFile) CanonicalFile() []byte {
	out := make([]byte, 0, 512+len(f.Generations)*256)
	out = appendString(out, CaseKeyFileDomain)
	out = appendU32(out, f.Version)
	out = appendString(out, f.CaseUID)
	out = appendString(out, f.CaseID)
	out = appendString(out, f.Created)
	out = appendString(out, f.Rotated)
	out = appendString(out, f.KDF.Algorithm)
	out = appendU32(out, f.KDF.Time)
	out = appendU32(out, f.KDF.MemoryKiB)
	out = appendU32(out, uint32(f.KDF.Threads))
	out = appendU32(out, f.KDF.KeyLen)
	out = appendString(out, f.KDF.Salt)
	out = appendU32(out, f.Current)
	out = appendU32(out, uint32(len(f.Generations)))
	for _, g := range f.Generations {
		out = appendU32(out, g.Generation)
		out = appendString(out, g.Created)
		out = appendString(out, g.Fingerprint)
		out = appendString(out, g.Nonce)
		out = appendString(out, g.Wrapped)
	}
	out = appendString(out, f.PreviousFileMAC)
	out = appendString(out, f.Signer)
	return out
}

// NewCaseKeyFile builds a file holding generation 1 and returns it with the
// unwrapped case key. It writes nothing; the caller decides where, which keeps
// every filesystem decision in builtin/case_key.go.
//
// The case key is 32 bytes from crypto/rand and is NOT derived from the
// passphrase. That single choice is what makes a passphrase rotation free and
// makes a disclosure durable: if the case key were a function of the
// passphrase, changing the passphrase would change every key in the system.
func NewCaseKeyFile(passphrase []byte, caseUID CaseUID, caseID string, now time.Time) (*CaseKeyFile, []byte, error) {
	profile, ok := caseKeyProfiles[CaseKeyFileVersion]
	if !ok {
		return nil, nil, fmt.Errorf("case-key format version %d has no cost profile", CaseKeyFileVersion)
	}
	salt, err := randomBytes(CaseKeySaltSize)
	if err != nil {
		return nil, nil, err
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	f := &CaseKeyFile{
		Format:  CaseKeyFileFormat,
		Version: CaseKeyFileVersion,
		CaseUID: hex.EncodeToString(caseUID[:]),
		CaseID:  caseID,
		Created: stamp,
		Rotated: "",
		KDF: CaseKeyKDF{
			Algorithm: profile.algorithm,
			Salt:      hex.EncodeToString(salt),
			Time:      profile.time,
			MemoryKiB: profile.memoryKiB,
			Threads:   profile.threads,
			KeyLen:    profile.keyLen,
		},
		Current: 1,
	}

	wrapKey, err := DeriveWrappingKey(passphrase, salt, f.Version)
	if err != nil {
		return nil, nil, err
	}
	defer SecureZero(wrapKey)

	caseKey, err := randomBytes(KeySize)
	if err != nil {
		return nil, nil, err
	}
	generation, err := f.wrapGeneration(wrapKey, 1, caseKey, stamp)
	if err != nil {
		SecureZero(caseKey)
		return nil, nil, err
	}
	f.Generations = []CaseKeyGeneration{generation}
	return f, caseKey, nil
}

// wrapGeneration seals one case key into a generation record.
//
// The nonce is drawn here and nowhere else, so no path through this file can
// re-seal a generation under a nonce it has already used. Every mutation of the
// header that changes the canonical generation form goes through this function,
// which is why a field and its tag cannot drift.
func (f *CaseKeyFile) wrapGeneration(wrapKey []byte, number uint32, caseKey []byte, created string) (CaseKeyGeneration, error) {
	fingerprint, err := CaseKeyFingerprint(caseKey)
	if err != nil {
		return CaseKeyGeneration{}, err
	}
	g := CaseKeyGeneration{
		Generation:  number,
		Created:     created,
		Fingerprint: hex.EncodeToString(fingerprint[:]),
	}
	raw, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return CaseKeyGeneration{}, err
	}
	nonce, err := XNonceFromSlice(raw)
	if err != nil {
		return CaseKeyGeneration{}, err
	}
	wrapped, err := sealWith(wrapKey, nonce, caseKey, f.CanonicalGeneration(g))
	if err != nil {
		return CaseKeyGeneration{}, err
	}
	g.Nonce = hex.EncodeToString(nonce[:])
	g.Wrapped = hex.EncodeToString(wrapped)
	return g, nil
}

// UnwrapGeneration recovers one generation's case key. The caller owns the
// bytes and must SecureZero them.
func (f *CaseKeyFile) UnwrapGeneration(wrapKey []byte, number uint32) ([]byte, error) {
	g, err := f.Generation(number)
	if err != nil {
		return nil, err
	}
	nonceBytes, err := hex.DecodeString(g.Nonce)
	if err != nil {
		return nil, ErrCaseKeyAuth
	}
	nonce, err := XNonceFromSlice(nonceBytes)
	if err != nil {
		return nil, ErrCaseKeyAuth
	}
	wrapped, err := hex.DecodeString(g.Wrapped)
	if err != nil {
		return nil, ErrCaseKeyAuth
	}
	// The AAD is rebuilt from the file's own fields, so a generation moved to
	// another case, another slot or another set of KDF parameters fails here.
	caseKey, err := openWith(wrapKey, nonce, wrapped, f.CanonicalGeneration(g), ErrCaseKeyAuth)
	if err != nil {
		return nil, err
	}
	// A right passphrase against the wrong file is a named failure rather than
	// a key that opens nothing.
	fingerprint, err := CaseKeyFingerprint(caseKey)
	if err != nil {
		SecureZero(caseKey)
		return nil, err
	}
	if !hmac.Equal([]byte(hex.EncodeToString(fingerprint[:])), []byte(g.Fingerprint)) {
		SecureZero(caseKey)
		return nil, ErrCaseKeyAuth
	}
	return caseKey, nil
}

// Generation returns the numbered generation.
func (f *CaseKeyFile) Generation(number uint32) (CaseKeyGeneration, error) {
	for _, g := range f.Generations {
		if g.Generation == number {
			return g, nil
		}
	}
	return CaseKeyGeneration{}, fmt.Errorf("this key file has no generation %d", number)
}

// SealCaseKeyFile computes the file MAC and, when a signing key is available,
// the signature.
//
// The order is forced and not a convention: the signer goes into the canonical
// form, so it must be set before the MAC is computed, and the signature covers
// the canonical form followed by the MAC. Doing it in one function is what
// stops a caller getting that order wrong and producing a file that refuses its
// own MAC.
func SealCaseKeyFile(f *CaseKeyFile, wrapKey []byte, sign bool) (signed bool, reason string, err error) {
	f.Signer = ""
	f.Signature = ""

	var private ed25519.PrivateKey
	if sign {
		// The third return is "a pair had to be generated", not "a pair is
		// available": a call that returns no error has a usable key pair. This
		// is the one place in the create path that writes outside the key file,
		// and it writes only where case_bundle already does.
		key, public, _, _, keyErr := EnsureLocalSigningKeyPair()
		if keyErr != nil {
			reason = keyErr.Error()
		} else {
			private = key
			f.Signer = hex.EncodeToString(public)
		}
	}

	macKey, err := FileMACKey(wrapKey)
	if err != nil {
		return false, reason, err
	}
	defer SecureZero(macKey)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(f.CanonicalFile())
	sum := mac.Sum(nil)
	f.FileMAC = hex.EncodeToString(sum)

	if private == nil {
		return false, reason, nil
	}
	f.Signature = hex.EncodeToString(ed25519.Sign(private, append(f.CanonicalFile(), sum...)))
	return true, "", nil
}

// VerifyCaseKeyFile checks the file MAC in constant time.
//
// This is what catches an edit to `current`, a deleted generation and a
// reordered generation list -- the things no per-generation AEAD tag covers.
// What it does NOT catch is a whole-file replacement: an earlier version the
// examiner themselves wrote has a MAC and a signature that both verify, so
// restoring a pre-rotation copy from a backup is undetectable from inside the
// file. previous_file_mac makes the chain of versions readable; only the ledger
// can say which link is the head.
func VerifyCaseKeyFile(f *CaseKeyFile, wrapKey []byte) error {
	macKey, err := FileMACKey(wrapKey)
	if err != nil {
		return err
	}
	defer SecureZero(macKey)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(f.CanonicalFile())
	want, err := hex.DecodeString(f.FileMAC)
	if err != nil || !hmac.Equal(mac.Sum(nil), want) {
		return errors.New("the key file's contents do not match its own authentication tag; " +
			"something has edited which generation is current, or the list of generations")
	}
	return nil
}

// VerifyCaseKeyFileSignature checks the Ed25519 signature over the canonical
// form and the file MAC.
//
// It is the only integrity check that works without the passphrase, which is
// what makes case_key_fingerprint worth more than a transcription. It reports
// two bits and not one, because `sign:false` is a documented mode: a file with
// no signer is a normal file written on a machine with no key store, and
// conflating that with a forgery in one boolean is the shape this tree refuses
// everywhere else.
func VerifyCaseKeyFileSignature(f *CaseKeyFile) (signed, valid bool, detail string) {
	if strings.TrimSpace(f.Signer) == "" && strings.TrimSpace(f.Signature) == "" {
		return false, false, "the file carries no signature; it was written with sign:false, or on a machine with no key store"
	}
	signed = true
	public, err := hex.DecodeString(f.Signer)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return signed, false, "the named signer is not an Ed25519 public key"
	}
	signature, err := hex.DecodeString(f.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return signed, false, "the signature is not an Ed25519 signature"
	}
	mac, err := hex.DecodeString(f.FileMAC)
	if err != nil {
		return signed, false, "the file's authentication tag is not hexadecimal"
	}
	if !ed25519.Verify(public, append(f.CanonicalFile(), mac...), signature) {
		return signed, false, "the signature does not hold over this file's contents"
	}
	return signed, true, "the signature holds for the named signer"
}

// MarshalCaseKeyFile renders f as the JSON an examiner reads. It does not
// compute the MAC or the signature; SealCaseKeyFile does.
//
// An Encoder rather than MarshalIndent because it terminates the document with
// a newline, and a key file is a text file somebody will open in an editor and
// pipe through sha256sum.
func MarshalCaseKeyFile(f *CaseKeyFile) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(f); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ParseCaseKeyFile decodes a document and checks every length and every cost
// before anything is derived from it.
//
// An unknown field is refused rather than ignored: a field this build would not
// authenticate is a field it must not carry. And the KDF block is compared
// against the table for the file's version rather than honoured, which is the
// difference between a cheap refusal and a 4 GiB allocation dictated by a file
// that arrived in a handover.
func ParseCaseKeyFile(data []byte) (*CaseKeyFile, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var f CaseKeyFile
	if err := decoder.Decode(&f); err != nil {
		return nil, fmt.Errorf("this is not a case key file: %w", err)
	}
	if f.Format != CaseKeyFileFormat {
		return nil, fmt.Errorf("this is not a case key file: its format is %q", f.Format)
	}
	profile, ok := caseKeyProfiles[f.Version]
	if !ok {
		return nil, fmt.Errorf("this key file is version %d and this build writes and reads version %d",
			f.Version, CaseKeyFileVersion)
	}
	if f.KDF.Algorithm != profile.algorithm || f.KDF.Time != profile.time ||
		f.KDF.MemoryKiB != profile.memoryKiB || f.KDF.Threads != profile.threads ||
		f.KDF.KeyLen != profile.keyLen {
		return nil, fmt.Errorf(
			"this key file asks for %s at time=%d memory=%d KiB threads=%d keylen=%d, and version %d is "+
				"defined as %s at time=%d memory=%d KiB threads=%d keylen=%d. The cost of opening a key file "+
				"is fixed by its version, because it has to be paid before anything in the file can be checked",
			f.KDF.Algorithm, f.KDF.Time, f.KDF.MemoryKiB, f.KDF.Threads, f.KDF.KeyLen,
			f.Version, profile.algorithm, profile.time, profile.memoryKiB, profile.threads, profile.keyLen)
	}
	if _, err := hexOfLength(f.CaseUID, CaseUIDSize); err != nil {
		return nil, fmt.Errorf("case_uid: %w", err)
	}
	if _, err := hexOfLength(f.KDF.Salt, CaseKeySaltSize); err != nil {
		return nil, fmt.Errorf("kdf.salt: %w", err)
	}
	if len(f.Generations) == 0 {
		return nil, errors.New("this key file holds no generations, so there is no key in it")
	}
	for i, g := range f.Generations {
		if g.Generation != uint32(i+1) {
			return nil, fmt.Errorf("generation %d is in slot %d; generations are numbered from one, in order", g.Generation, i+1)
		}
		if _, err := hexOfLength(g.Fingerprint, sha256.Size); err != nil {
			return nil, fmt.Errorf("generation %d fingerprint: %w", g.Generation, err)
		}
		if _, err := hexOfLength(g.Nonce, chacha20poly1305.NonceSizeX); err != nil {
			return nil, fmt.Errorf("generation %d nonce: %w", g.Generation, err)
		}
		if _, err := hexOfLength(g.Wrapped, WrappedKeySize); err != nil {
			return nil, fmt.Errorf("generation %d wrapped key: %w", g.Generation, err)
		}
	}
	if f.Current == 0 || int(f.Current) > len(f.Generations) {
		return nil, fmt.Errorf("this key file says generation %d is current and holds %d", f.Current, len(f.Generations))
	}
	return &f, nil
}

// hexOfLength decodes a hex field and checks its decoded width, so nothing
// downstream has to.
func hexOfLength(s string, want int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("not hexadecimal")
	}
	if len(b) != want {
		return nil, fmt.Errorf("must be %d bytes, got %d", want, len(b))
	}
	return b, nil
}

// CaseUIDOf returns the file's case identity as the fixed-width value a segment
// binds.
func (f *CaseKeyFile) CaseUIDOf() (CaseUID, error) {
	raw, err := hexOfLength(f.CaseUID, CaseUIDSize)
	if err != nil {
		return CaseUID{}, fmt.Errorf("case_uid: %w", err)
	}
	return CaseUIDFromSlice(raw)
}

// SaltBytes returns the decoded Argon2id salt.
func (f *CaseKeyFile) SaltBytes() ([]byte, error) { return hexOfLength(f.KDF.Salt, CaseKeySaltSize) }

// RotatePassphrase re-wraps every generation under a new passphrase.
//
// It proves the old passphrase first, by unwrapping the current generation,
// before anything is written. Without that, a mistyped passphrase -- typed
// twice, identically, which is the common failure when you think you know it --
// produces a file that needs two different passphrases and says nothing about
// which generation is the odd one out.
//
// Every case key is byte-identical afterwards. No record is read, no record is
// written, and no fingerprint changes.
func (f *CaseKeyFile) RotatePassphrase(oldPassphrase, newPassphrase []byte, now time.Time) error {
	if len(newPassphrase) == 0 {
		return ErrEmptyPassphrase
	}
	oldSalt, err := f.SaltBytes()
	if err != nil {
		return err
	}
	oldWrapKey, err := DeriveWrappingKey(oldPassphrase, oldSalt, f.Version)
	if err != nil {
		return err
	}
	defer SecureZero(oldWrapKey)
	if err := VerifyCaseKeyFile(f, oldWrapKey); err != nil {
		return ErrCaseKeyAuth
	}

	keys := make([][]byte, 0, len(f.Generations))
	defer func() {
		for _, k := range keys {
			SecureZero(k)
		}
	}()
	for _, g := range f.Generations {
		caseKey, err := f.UnwrapGeneration(oldWrapKey, g.Generation)
		if err != nil {
			return err
		}
		keys = append(keys, caseKey)
	}

	newSalt, err := randomBytes(CaseKeySaltSize)
	if err != nil {
		return err
	}
	previous := f.FileMAC
	f.KDF.Salt = hex.EncodeToString(newSalt)
	f.Rotated = now.UTC().Format(time.RFC3339Nano)
	f.PreviousFileMAC = previous

	newWrapKey, err := DeriveWrappingKey(newPassphrase, newSalt, f.Version)
	if err != nil {
		return err
	}
	defer SecureZero(newWrapKey)

	rewrapped := make([]CaseKeyGeneration, 0, len(f.Generations))
	for i, g := range f.Generations {
		next, err := f.wrapGeneration(newWrapKey, g.Generation, keys[i], g.Created)
		if err != nil {
			return err
		}
		rewrapped = append(rewrapped, next)
	}
	f.Generations = rewrapped
	return nil
}

// RotateCaseKey appends a fresh case key as the next generation and makes it
// current, keeping every earlier generation.
//
// Earlier generations stay because a record still opens under the generation
// its header names, so rewrapping a record header becomes an optional migration
// rather than a correctness requirement. And rotation is not revocation: a
// grant already issued is bytes in somebody else's hands and nothing here
// reaches them.
func (f *CaseKeyFile) RotateCaseKey(passphrase []byte, now time.Time) ([]byte, error) {
	salt, err := f.SaltBytes()
	if err != nil {
		return nil, err
	}
	wrapKey, err := DeriveWrappingKey(passphrase, salt, f.Version)
	if err != nil {
		return nil, err
	}
	defer SecureZero(wrapKey)
	if err := VerifyCaseKeyFile(f, wrapKey); err != nil {
		return nil, ErrCaseKeyAuth
	}
	// Proving the passphrase opens the current generation before minting a new
	// one keeps a mistyped passphrase from producing a file with two of them.
	probe, err := f.UnwrapGeneration(wrapKey, f.Current)
	if err != nil {
		return nil, err
	}
	SecureZero(probe)

	caseKey, err := randomBytes(KeySize)
	if err != nil {
		return nil, err
	}
	number := uint32(len(f.Generations)) + 1
	stamp := now.UTC().Format(time.RFC3339Nano)
	g, err := f.wrapGeneration(wrapKey, number, caseKey, stamp)
	if err != nil {
		SecureZero(caseKey)
		return nil, err
	}
	f.PreviousFileMAC = f.FileMAC
	f.Generations = append(f.Generations, g)
	f.Current = number
	f.Rotated = stamp
	return caseKey, nil
}

// OpenCaseKeyFile derives the wrapping key, checks the file MAC, and returns
// the named generation's case key together with the wrapping key.
//
// The caller owns both and must SecureZero them. The wrapping key is returned
// because a caller that is about to rewrap -- class_define, a rotation -- would
// otherwise pay Argon2id twice, and 256 MiB at three passes is not a cost to
// pay by accident.
func OpenCaseKeyFile(f *CaseKeyFile, passphrase []byte, generation uint32) (caseKey, wrapKey []byte, err error) {
	salt, err := f.SaltBytes()
	if err != nil {
		return nil, nil, err
	}
	wrapKey, err = DeriveWrappingKey(passphrase, salt, f.Version)
	if err != nil {
		return nil, nil, err
	}
	// A wrong passphrase yields a wrong MAC key, so the MAC is the first thing
	// that fails and it fails for the same reason an edit does. Reporting the
	// MAC's own sentence here would tell an examiner their file had been
	// tampered with when they had simply mistyped, so this path reports the
	// error that covers both and says so.
	if err := VerifyCaseKeyFile(f, wrapKey); err != nil {
		SecureZero(wrapKey)
		return nil, nil, ErrCaseKeyAuth
	}
	if generation == 0 {
		generation = f.Current
	}
	caseKey, err = f.UnwrapGeneration(wrapKey, generation)
	if err != nil {
		SecureZero(wrapKey)
		return nil, nil, err
	}
	return caseKey, wrapKey, nil
}
