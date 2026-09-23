package security

// Disclosure grants: the key material for some of a record's segments and
// none of the others.
//
// A disclosure hands a recipient the record file exactly as it sits under
// custody -- every ciphertext, every boundary, every length -- and, beside it,
// the material for the segments they are granted. This file is that material,
// and the envelope it travels in.
//
// # Why this is a type of its own and not a RecordKeys
//
// (*RecordKeys).OpenSegment derives each segment's key and nonce from the
// record's pseudorandom key, and that key opens every segment the record has.
// So a RecordKeys cannot be a partial grant: the only way to hand over one
// segment through it is to hand over all of them. A grant therefore carries
// the DERIVED material -- one segment's key and nonce per granted segment --
// and nothing from which any other segment's could be derived. HKDF-Expand is
// one-way in its pseudorandom key: the output for one info string says nothing
// about the output for another, and the info string is a digest of the
// segment's whole descriptor.
//
// It is 56 bytes a segment and not 32. The key and the nonce come out of one
// Expand (see segmentMaterial) and the nonce is not derivable without the
// pseudorandom key, so a grant that carried only keys would open nothing.
//
// # What a grant is not
//
// It is not a read-only capability. A segment key is symmetric: a recipient
// can seal new content at a granted position and it will open under this same
// grant. What tells the examiner's bytes from a recipient's is the record
// footer's signature over the segment digests, which is in record_file.go and
// which a recipient cannot re-make under the examiner's key.
//
// It cannot be taken back. Once a recipient holds the ciphertext and this
// material, both halves are theirs, and nothing in this file or any other
// reaches their copy. That is why no function here is named anything like
// revoke, and why the disclosure family calls the act of stopping further
// grants a withdrawal.
//
// It survives a case-key rotation. Rotation rewraps the record key; the record
// key, the uid and the seal salt are unchanged, so the pseudorandom key is
// unchanged and so is every segment's material. TestRotationInvalidatesNoGrant
// pins that property for the material, and TestAGrantSurvivesRotation pins it
// for this type.
//
// # What travels, and what is bound to what
//
// A grant is sealed into a GrantFile under a key derived from a passphrase.
// Everything in the file except the material is public -- which record, which
// segments, under which disclosure -- and all of it is additional data to the
// one AEAD that holds the material, so none of it can be edited without the
// passphrase. The granted set is public on purpose: the disclosure manifest
// states it anyway, run for run, because a recipient who cannot see what they
// were NOT given cannot check that what they can open is all they were meant to.
//
// The file also carries a root over the descriptors of every granted segment.
// A descriptor is public -- it is rebuilt from the record header -- so the
// root costs a reader nothing to recompute, and it is what lets a recipient
// learn that a grant and a record header disagree before a single tag fails,
// and learn it as that rather than as "does not open".

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// GrantFileFormat is a grant file's "format" field.
	GrantFileFormat = "mutant-disclosure-grant"
	// GrantFileVersion is the version this build writes and the only one it
	// reads.
	GrantFileVersion uint32 = 1
	// GrantFileDomain opens the canonical form the grant's AEAD binds.
	GrantFileDomain = "mutant-disclosure-grant-v1"
	// GrantDescriptorsDomain prefixes the root over granted descriptors, so
	// the root cannot be replayed as any other digest this tree computes.
	GrantDescriptorsDomain = "mutant-grant-descriptors-v1"
	// HKDFInfoGrantWrap separates the key that seals a grant from every other
	// key a passphrase can reach. A grant passphrase and a case-key passphrase
	// are different secrets held by different people, and the day one is typed
	// where the other was meant must not be a day the two derive the same key.
	HKDFInfoGrantWrap = "mutant-grant-wrap-v1"

	// DisclosureUIDSize is the length of a disclosure's random identity.
	DisclosureUIDSize = 16
	// GrantMaterialSize is one segment's key and nonce.
	GrantMaterialSize = KeySize + chacha20poly1305.NonceSizeX
	// MaxGrantMaterial bounds a grant's sealed payload: every segment of the
	// largest record a header may describe. It is 56 MiB and exists so that a
	// grant file's own count cannot ask for more.
	MaxGrantMaterial = GrantMaterialSize * MaxRecordSegments
	// MaxGrantFile bounds what is read before anything in a grant file has
	// been checked. The hex of the largest payload, plus room for a run list
	// that is one row per segment, which is the most runs a set can have.
	MaxGrantFile = 2*(MaxGrantMaterial+chacha20poly1305.Overhead) + 48*MaxRecordSegments + (64 << 10)
)

// grantFileProfiles fixes the Argon2id cost per grant file version, for the
// reason caseKeyProfiles gives: a cost read off the file is a cost paid before
// the file can be checked. The same numbers as a case-key file, because the
// threat is the same -- a file at rest in somebody else's hands, attacked
// offline for as long as they like.
var grantFileProfiles = map[uint32]argon2Profile{
	1: {algorithm: "argon2id", time: 3, memoryKiB: 256 * 1024, threads: 4, keyLen: KeySize},
}

var (
	// ErrSegmentNotGranted is returned for a segment the grant carries no
	// material for. It is not an oracle: the granted set is public, in the
	// grant file and in the manifest beside it.
	ErrSegmentNotGranted = errors.New("this grant carries no material for that segment")
	// ErrGrantRecordMismatch is returned for a descriptor that names a
	// different record, case, generation or segment count from the grant.
	// Every one of those is public, so saying so gives nothing away.
	ErrGrantRecordMismatch = errors.New("this grant is for a different record")
	// ErrGrantAuth is the single failure a grant file reports for a wrong
	// passphrase and for an edited file alike.
	ErrGrantAuth = errors.New("the grant did not open: the passphrase is wrong, or the file has been edited")
)

// DisclosureUID names one disclosure. Random, never a counter, for the reason
// RecordUID is: two cases counting from one would collide, and the uid is what
// stops a grant from one disclosure being presented as another's.
type DisclosureUID [DisclosureUIDSize]byte

// RandomDisclosureUID mints a disclosure identity.
func RandomDisclosureUID() (DisclosureUID, error) {
	var uid DisclosureUID
	b, err := randomBytes(DisclosureUIDSize)
	if err != nil {
		return uid, err
	}
	copy(uid[:], b)
	return uid, nil
}

// GrantRun is a stretch of consecutive granted segments, both ends inclusive.
type GrantRun struct {
	First uint64 `json:"first"`
	Last  uint64 `json:"last"`
}

// RecordGrant is the material for some of one record's segments.
//
// Every field is unexported. A grant is issued by the record it opens part of,
// or recovered from a sealed grant file, and in neither case does a caller get
// to say which record it belongs to.
type RecordGrant struct {
	caseUID    CaseUID
	recordUID  RecordUID
	generation uint32
	total      uint64

	// indices is strictly ascending. material holds GrantMaterialSize bytes
	// per index, in the same order, in ONE allocation -- so that Zero is a
	// single call that reaches all of it, and so that nothing was ever grown
	// by append and left a copy of earlier material in an abandoned array.
	indices  []uint64
	material []byte

	descriptorsRoot [sha256.Size]byte
}

// IssueGrant derives the material for exactly the segments whose descriptors
// are given.
//
// The descriptors are the record's own: each must name this handle's case,
// record, generation and segment count, and a descriptor naming anything else
// is refused rather than granted, because material derived for a descriptor
// the record does not contain is material that opens nothing -- which a caller
// would discover from the recipient, later. An empty list is legal and issues
// a grant of nothing: a disclosure that hands over a record's existence, its
// signature and its shape and no content is a real posture, and view_define
// already accepts one.
//
// A handle still sealing is refused. A grant is issued from a record that
// exists, and until the last segment is sealed the one being granted from
// does not.
func (r *RecordKeys) IssueGrant(descriptors []SegmentAAD) (*RecordGrant, error) {
	if r == nil || r.prk == nil {
		return nil, errors.New("the record key schedule has been zeroed")
	}
	if r.sealable && !r.SealComplete() {
		return nil, fmt.Errorf("this record has sealed %d of its %d segments; a grant is issued from a "+
			"record that has been sealed, and this one has not been yet", r.nextIndex, r.total)
	}
	if uint64(len(descriptors)) > r.total {
		return nil, fmt.Errorf("a record of %d segments cannot grant %d of them", r.total, len(descriptors))
	}
	sorted := make([]SegmentAAD, len(descriptors))
	copy(sorted, descriptors)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].index < sorted[j].index })
	for i, d := range sorted {
		if d.caseUID != r.caseUID || d.recordUID != r.uid || d.generation != r.generation || d.total != r.total {
			return nil, fmt.Errorf("segment %d's descriptor names a different record from the one issuing "+
				"the grant: %w", d.index, ErrGrantRecordMismatch)
		}
		if d.index >= r.total {
			return nil, fmt.Errorf("segment %d is out of range for a record of %d segments", d.index, r.total)
		}
		// Refused rather than collapsed. Two descriptors for one index are
		// either the same descriptor twice -- a list whose author lost track of
		// it -- or two DIFFERENT descriptors for one position, and granting
		// either one silently would be choosing between them.
		if i > 0 && sorted[i-1].index == d.index {
			return nil, fmt.Errorf("segment %d is named twice; a grant names each segment once", d.index)
		}
	}

	grant := &RecordGrant{
		caseUID:    r.caseUID,
		recordUID:  r.uid,
		generation: r.generation,
		total:      r.total,
		indices:    make([]uint64, len(sorted)),
		material:   make([]byte, len(sorted)*GrantMaterialSize),
	}
	for i, d := range sorted {
		key, nonce, err := r.segmentMaterial(d.encode())
		if err != nil {
			grant.Zero()
			return nil, err
		}
		slot := grant.material[i*GrantMaterialSize : (i+1)*GrantMaterialSize]
		copy(slot[:KeySize], key)
		copy(slot[KeySize:], nonce[:])
		SecureZero(key)
		SecureZero(nonce[:])
		grant.indices[i] = d.index
	}
	grant.descriptorsRoot = grantDescriptorsRoot(sorted)
	return grant, nil
}

// grantDescriptorsRoot folds the granted descriptors, in index order, with the
// count first so that a fold over none and a fold over nothing differ.
func grantDescriptorsRoot(sorted []SegmentAAD) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(GrantDescriptorsDomain))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(sorted)))
	h.Write(count[:])
	for _, d := range sorted {
		encoded := d.encode()
		h.Write(encoded[:])
	}
	var root [sha256.Size]byte
	copy(root[:], h.Sum(nil))
	return root
}

// Zero releases the material. The indices are public and stay, so a zeroed
// grant can still say what it was a grant of.
func (g *RecordGrant) Zero() {
	if g == nil {
		return
	}
	SecureZero(g.material)
	g.material = nil
}

// CaseUID, RecordUID, SealedUnderGeneration and Total report the record the
// grant opens part of.
func (g *RecordGrant) CaseUID() CaseUID              { return g.caseUID }
func (g *RecordGrant) RecordUID() RecordUID          { return g.recordUID }
func (g *RecordGrant) SealedUnderGeneration() uint32 { return g.generation }
func (g *RecordGrant) Total() uint64                 { return g.total }

// Count is how many segments the grant opens.
func (g *RecordGrant) Count() int { return len(g.indices) }

// DescriptorsRoot is the fold over every granted segment's descriptor.
func (g *RecordGrant) DescriptorsRoot() [sha256.Size]byte { return g.descriptorsRoot }

// Indices returns the granted segment indices, ascending. A copy, so a caller
// cannot edit what the grant says it grants.
func (g *RecordGrant) Indices() []uint64 {
	out := make([]uint64, len(g.indices))
	copy(out, g.indices)
	return out
}

// Granted reports whether the grant carries material for a segment.
func (g *RecordGrant) Granted(index uint64) bool {
	_, ok := g.slot(index)
	return ok
}

// Runs returns the granted set as maximal runs of consecutive indices, the
// form a manifest states it in and a reader can check at a glance.
func (g *RecordGrant) Runs() []GrantRun { return grantRunsOf(g.indices) }

func grantRunsOf(indices []uint64) []GrantRun {
	runs := make([]GrantRun, 0)
	for _, index := range indices {
		if n := len(runs); n > 0 && runs[n-1].Last+1 == index {
			runs[n-1].Last = index
			continue
		}
		runs = append(runs, GrantRun{First: index, Last: index})
	}
	return runs
}

func (g *RecordGrant) slot(index uint64) (int, bool) {
	i := sort.Search(len(g.indices), func(i int) bool { return g.indices[i] >= index })
	if i < len(g.indices) && g.indices[i] == index {
		return i, true
	}
	return 0, false
}

// sameRecord reports whether a descriptor names the record this grant is for.
func (g *RecordGrant) sameRecord(aad SegmentAAD) bool {
	return aad.caseUID == g.caseUID && aad.recordUID == g.recordUID &&
		aad.generation == g.generation && aad.total == g.total
}

// OpenSegment decrypts one granted segment.
//
// Three refusals, in the order a reader would want them. A descriptor for a
// different record is named as that; a segment the grant does not cover is
// named as that; and everything else -- a wrong offset, a wrong class, a
// flipped byte, a segment moved from elsewhere -- is the one ErrSegmentAuth,
// for the reason that error gives. The first two are public facts and saying
// them is free. The third is the one that must not become an oracle.
//
// A successful open proves what (*RecordKeys).OpenSegment proves and no more:
// that the bytes were written by somebody holding this segment's key, which
// includes the holder of this grant.
func (g *RecordGrant) OpenSegment(aad SegmentAAD, ciphertext []byte) ([]byte, error) {
	if g == nil || g.material == nil {
		return nil, errors.New("this grant has been zeroed")
	}
	if !g.sameRecord(aad) {
		return nil, ErrGrantRecordMismatch
	}
	i, ok := g.slot(aad.index)
	if !ok {
		return nil, ErrSegmentNotGranted
	}
	slot := g.material[i*GrantMaterialSize : (i+1)*GrantMaterialSize]
	var nonce XNonce
	copy(nonce[:], slot[KeySize:])
	defer SecureZero(nonce[:])

	encoded := aad.encode()
	plaintext, err := openWith(slot[:KeySize], nonce, ciphertext, encoded[:], ErrSegmentAuth)
	if err != nil {
		return nil, err
	}
	if len(plaintext) != int(aad.length) {
		SecureZero(plaintext)
		return nil, ErrSegmentAuth
	}
	return plaintext, nil
}

// MatchesRecord checks, holding no plaintext and opening nothing, that a
// record's header describes every granted segment exactly as it was described
// when the grant was issued.
//
// describe returns the descriptor the header gives for an index. A mismatch is
// reported as what it is -- this grant and this header disagree -- which a
// failed tag could only have reported as "does not open".
func (g *RecordGrant) MatchesRecord(describe func(index uint64) (SegmentAAD, error)) error {
	if g == nil {
		return errors.New("there is no grant")
	}
	granted := make([]SegmentAAD, 0, len(g.indices))
	for _, index := range g.indices {
		d, err := describe(index)
		if err != nil {
			return fmt.Errorf("segment %d: %w", index, err)
		}
		if !g.sameRecord(d) || d.index != index {
			return ErrGrantRecordMismatch
		}
		granted = append(granted, d)
	}
	root := grantDescriptorsRoot(granted)
	if root != g.descriptorsRoot {
		return errors.New("the record header describes the granted segments differently from the " +
			"header the grant was issued against: an offset, a length or a class has changed")
	}
	return nil
}

// ---------------------------------------------------------------------------
// The grant file
// ---------------------------------------------------------------------------

// GrantFile is a sealed grant as it travels.
//
// Nothing in it is secret except Blob, which is the material. Every other
// field is additional data to the AEAD that seals Blob, so it cannot be edited
// by anyone without the passphrase -- and, like a case-key file, nothing is
// authenticated over the JSON text, because JSON has no canonical byte form.
// The canonical form below is what is bound; the JSON is transport.
type GrantFile struct {
	Format  string `json:"format"`
	Version uint32 `json:"version"`

	DisclosureUID string `json:"disclosure_uid"`

	CaseUID               string `json:"case_uid"`
	RecordUID             string `json:"record_uid"`
	SealedUnderGeneration uint32 `json:"sealed_under_generation"`
	Segments              uint64 `json:"segments"`

	Granted         uint64     `json:"granted"`
	Runs            []GrantRun `json:"runs"`
	DescriptorsRoot string     `json:"descriptors_root"`

	KDF   CaseKeyKDF `json:"kdf"`
	Nonce string     `json:"nonce"`
	Blob  string     `json:"blob"`
}

func appendU64(dst []byte, v uint64) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], v)
	return append(dst, n[:]...)
}

// canonical is the additional data the grant's AEAD binds: every field but
// the nonce and the blob, length-prefixed so no two fields can be re-split.
func (f *GrantFile) canonical() []byte {
	out := make([]byte, 0, 512+16*len(f.Runs))
	out = appendString(out, GrantFileDomain)
	out = appendU32(out, f.Version)
	out = appendString(out, f.DisclosureUID)
	out = appendString(out, f.CaseUID)
	out = appendString(out, f.RecordUID)
	out = appendU32(out, f.SealedUnderGeneration)
	out = appendU64(out, f.Segments)
	out = appendU64(out, f.Granted)
	out = appendU64(out, uint64(len(f.Runs)))
	for _, run := range f.Runs {
		out = appendU64(out, run.First)
		out = appendU64(out, run.Last)
	}
	out = appendString(out, f.DescriptorsRoot)
	out = appendString(out, f.KDF.Algorithm)
	out = appendU32(out, f.KDF.Time)
	out = appendU32(out, f.KDF.MemoryKiB)
	out = appendU32(out, uint32(f.KDF.Threads))
	out = appendU32(out, f.KDF.KeyLen)
	out = appendString(out, f.KDF.Salt)
	return out
}

// grantWrapKey turns a passphrase and a salt into the key a grant is sealed
// under: Argon2id at the version's fixed cost, then one HKDF step under the
// grant's own info string.
func grantWrapKey(passphrase, salt []byte, version uint32) ([]byte, error) {
	profile, ok := grantFileProfiles[version]
	if !ok {
		return nil, fmt.Errorf("grant file version %d is not one this build knows", version)
	}
	if len(salt) != CaseKeySaltSize {
		return nil, fmt.Errorf("the salt must be %d bytes, got %d", CaseKeySaltSize, len(salt))
	}
	stretched, err := deriveArgon2id(passphrase, salt, profile)
	if err != nil {
		return nil, err
	}
	defer SecureZero(stretched)
	return expandFrom(stretched, nil, HKDFInfoGrantWrap, KeySize)
}

// SealGrant seals a grant under a passphrase, for one disclosure.
//
// The salt and the nonce are drawn here and nowhere else. The passphrase is
// the caller's to zero; it is []byte the whole way for the reason
// DeriveWrappingKey gives.
func SealGrant(g *RecordGrant, disclosure DisclosureUID, passphrase []byte) (*GrantFile, error) {
	if g == nil || g.material == nil {
		return nil, errors.New("this grant has been zeroed")
	}
	profile, ok := grantFileProfiles[GrantFileVersion]
	if !ok {
		return nil, fmt.Errorf("grant file version %d has no cost profile", GrantFileVersion)
	}
	salt, err := randomBytes(CaseKeySaltSize)
	if err != nil {
		return nil, err
	}
	f := &GrantFile{
		Format:                GrantFileFormat,
		Version:               GrantFileVersion,
		DisclosureUID:         hex.EncodeToString(disclosure[:]),
		CaseUID:               hex.EncodeToString(g.caseUID[:]),
		RecordUID:             hex.EncodeToString(g.recordUID[:]),
		SealedUnderGeneration: g.generation,
		Segments:              g.total,
		Granted:               uint64(len(g.indices)),
		Runs:                  g.Runs(),
		DescriptorsRoot:       hex.EncodeToString(g.descriptorsRoot[:]),
		KDF: CaseKeyKDF{
			Algorithm: profile.algorithm,
			Salt:      hex.EncodeToString(salt),
			Time:      profile.time,
			MemoryKiB: profile.memoryKiB,
			Threads:   profile.threads,
			KeyLen:    profile.keyLen,
		},
	}
	wrapKey, err := grantWrapKey(passphrase, salt, f.Version)
	if err != nil {
		return nil, err
	}
	defer SecureZero(wrapKey)
	if err := sealGrantWithKey(f, g, wrapKey); err != nil {
		return nil, err
	}
	return f, nil
}

// sealGrantWithKey is the AEAD half of SealGrant, apart so that the tests can
// exercise the binding without paying for Argon2id per case.
func sealGrantWithKey(f *GrantFile, g *RecordGrant, wrapKey []byte) error {
	raw, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return err
	}
	nonce, err := XNonceFromSlice(raw)
	if err != nil {
		return err
	}
	blob, err := sealWithLimit(wrapKey, nonce, g.material, f.canonical(), MaxGrantMaterial, "a grant")
	if err != nil {
		return err
	}
	f.Nonce = hex.EncodeToString(nonce[:])
	f.Blob = hex.EncodeToString(blob)
	return nil
}

// OpenGrantFile recovers a grant. The file must have come through
// ParseGrantFile, which is where its shape was checked; this checks only what
// needs the passphrase.
func OpenGrantFile(f *GrantFile, passphrase []byte) (*RecordGrant, error) {
	salt, err := hexOfLength(f.KDF.Salt, CaseKeySaltSize)
	if err != nil {
		return nil, ErrGrantAuth
	}
	wrapKey, err := grantWrapKey(passphrase, salt, f.Version)
	if err != nil {
		return nil, err
	}
	defer SecureZero(wrapKey)
	return openGrantWithKey(f, wrapKey)
}

func openGrantWithKey(f *GrantFile, wrapKey []byte) (*RecordGrant, error) {
	nonceBytes, err := hexOfLength(f.Nonce, chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, ErrGrantAuth
	}
	nonce, err := XNonceFromSlice(nonceBytes)
	if err != nil {
		return nil, ErrGrantAuth
	}
	blob, err := hex.DecodeString(f.Blob)
	if err != nil {
		return nil, ErrGrantAuth
	}
	material, err := openWithLimit(wrapKey, nonce, blob, f.canonical(), ErrGrantAuth, MaxGrantMaterial, "a grant")
	if err != nil {
		return nil, err
	}
	if uint64(len(material)) != f.Granted*GrantMaterialSize {
		SecureZero(material)
		return nil, ErrGrantAuth
	}
	grant, err := f.shell()
	if err != nil {
		SecureZero(material)
		return nil, ErrGrantAuth
	}
	grant.material = material
	return grant, nil
}

// shell builds the public half of a grant from its file: which record, which
// segments, and the root over their descriptors -- everything but the
// material, which it does not have and does not need.
func (f *GrantFile) shell() (*RecordGrant, error) {
	grant := &RecordGrant{
		generation: f.SealedUnderGeneration,
		total:      f.Segments,
		indices:    make([]uint64, 0, f.Granted),
	}
	caseRaw, err := hexOfLength(f.CaseUID, CaseUIDSize)
	if err != nil {
		return nil, fmt.Errorf("case_uid: %w", err)
	}
	copy(grant.caseUID[:], caseRaw)
	recordRaw, err := hexOfLength(f.RecordUID, RecordUIDSize)
	if err != nil {
		return nil, fmt.Errorf("record_uid: %w", err)
	}
	copy(grant.recordUID[:], recordRaw)
	rootRaw, err := hexOfLength(f.DescriptorsRoot, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("descriptors_root: %w", err)
	}
	copy(grant.descriptorsRoot[:], rootRaw)
	// ParseGrantFile has already refused a run list that is out of order, out
	// of range or miscounted. Checked again here because this loop's bound is
	// a number read off the file, and a loop whose termination depends on a
	// check made somewhere else is a loop one refactor away from not ending.
	for _, run := range f.Runs {
		if run.First > run.Last || run.Last >= f.Segments || uint64(len(grant.indices))+run.Last-run.First+1 > f.Granted {
			return nil, errors.New("the grant's run list does not describe a set of its record's segments")
		}
		for index := run.First; index <= run.Last; index++ {
			grant.indices = append(grant.indices, index)
		}
	}
	if uint64(len(grant.indices)) != f.Granted {
		return nil, errors.New("the grant's runs do not cover the number of segments it says it grants")
	}
	return grant, nil
}

// MatchesHeader is MatchesRecord for a grant nobody has opened: it checks the
// granted descriptors against a record header using only the grant file's
// public fields, so a reader without the passphrase can still establish that
// this grant was issued against this record exactly as it stands.
func (f *GrantFile) MatchesHeader(describe func(index uint64) (SegmentAAD, error)) error {
	shell, err := f.shell()
	if err != nil {
		return err
	}
	return shell.MatchesRecord(describe)
}

// Indices is the granted set as the file states it, ascending. It needs no
// passphrase: the set is public.
func (f *GrantFile) Indices() ([]uint64, error) {
	shell, err := f.shell()
	if err != nil {
		return nil, err
	}
	return shell.indices, nil
}

// MarshalGrantFile renders a grant file, newline-terminated, for the reason
// MarshalCaseKeyFile gives.
func MarshalGrantFile(f *GrantFile) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(f); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ParseGrantFile decodes a grant file and checks every count, every length and
// the cost before anything is derived from it.
//
// It refuses what it does not fully understand, in the case-key file's
// manner: an unknown field is refused, the KDF block is compared against the
// version's table rather than honoured, and every length is checked before
// the decode that would allocate for it. The run list must be in its one
// canonical form -- ascending, within the record, and maximal, so that no two
// runs could be merged -- because a set with two spellings is a set two
// readers can count differently.
func ParseGrantFile(data []byte) (*GrantFile, error) {
	if len(data) > MaxGrantFile {
		return nil, fmt.Errorf("this is %d bytes and a grant file is at most %d", len(data), MaxGrantFile)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var f GrantFile
	if err := decoder.Decode(&f); err != nil {
		return nil, fmt.Errorf("this is not a grant file: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("this is not a grant file: the document is followed by more JSON")
	}
	if f.Format != GrantFileFormat {
		return nil, fmt.Errorf("this is not a grant file: its format is %q", f.Format)
	}
	profile, ok := grantFileProfiles[f.Version]
	if !ok {
		return nil, fmt.Errorf("this grant file is version %d and this build reads version %d",
			f.Version, GrantFileVersion)
	}
	if f.KDF.Algorithm != profile.algorithm || f.KDF.Time != profile.time ||
		f.KDF.MemoryKiB != profile.memoryKiB || f.KDF.Threads != profile.threads ||
		f.KDF.KeyLen != profile.keyLen {
		return nil, fmt.Errorf(
			"this grant file asks for %s at time=%d memory=%d KiB threads=%d keylen=%d, and version %d is "+
				"defined as %s at time=%d memory=%d KiB threads=%d keylen=%d. The cost of opening a grant "+
				"is fixed by its version, because it has to be paid before anything in the file can be checked",
			f.KDF.Algorithm, f.KDF.Time, f.KDF.MemoryKiB, f.KDF.Threads, f.KDF.KeyLen,
			f.Version, profile.algorithm, profile.time, profile.memoryKiB, profile.threads, profile.keyLen)
	}
	if _, err := hexOfLength(f.DisclosureUID, DisclosureUIDSize); err != nil {
		return nil, fmt.Errorf("disclosure_uid: %w", err)
	}
	if _, err := hexOfLength(f.CaseUID, CaseUIDSize); err != nil {
		return nil, fmt.Errorf("case_uid: %w", err)
	}
	if _, err := hexOfLength(f.RecordUID, RecordUIDSize); err != nil {
		return nil, fmt.Errorf("record_uid: %w", err)
	}
	if f.SealedUnderGeneration < 1 {
		return nil, errors.New("generations are numbered from 1 and this grant names 0")
	}
	if f.Segments == 0 || f.Segments > MaxRecordSegments {
		return nil, fmt.Errorf("this grant is for a record of %d segments and a record has 1 to %d",
			f.Segments, uint64(MaxRecordSegments))
	}
	if f.Granted > f.Segments {
		return nil, fmt.Errorf("this grant says it opens %d segments of a record that has %d", f.Granted, f.Segments)
	}
	if _, err := hexOfLength(f.DescriptorsRoot, sha256.Size); err != nil {
		return nil, fmt.Errorf("descriptors_root: %w", err)
	}
	if _, err := hexOfLength(f.KDF.Salt, CaseKeySaltSize); err != nil {
		return nil, fmt.Errorf("kdf.salt: %w", err)
	}
	if _, err := hexOfLength(f.Nonce, chacha20poly1305.NonceSizeX); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	if f.Runs == nil {
		return nil, errors.New("this grant file carries no run list; a grant of nothing carries an empty one")
	}
	var counted uint64
	for i, run := range f.Runs {
		if run.First > run.Last {
			return nil, fmt.Errorf("run %d starts at segment %d and ends at %d", i, run.First, run.Last)
		}
		if run.Last >= f.Segments {
			return nil, fmt.Errorf("run %d reaches segment %d of a record numbered 0 to %d", i, run.Last, f.Segments-1)
		}
		// Strictly past the previous run's end plus one: ascending, disjoint
		// and maximal together. Two runs that touch are one run spelled twice.
		if i > 0 && run.First <= f.Runs[i-1].Last+1 {
			return nil, fmt.Errorf("run %d begins at segment %d, which overlaps or adjoins run %d; runs are "+
				"ascending and maximal, so a granted set has exactly one spelling", i, run.First, i-1)
		}
		// Bounded by Segments, itself bounded by MaxRecordSegments, so the
		// sum cannot wrap.
		counted += run.Last - run.First + 1
	}
	if counted != f.Granted {
		return nil, fmt.Errorf("the runs cover %d segments and the grant says it opens %d", counted, f.Granted)
	}
	// Measured as hex before it is decoded, so the file's own count is what
	// decides whether the blob is the right size -- never the blob.
	wantBlob := 2 * (f.Granted*GrantMaterialSize + chacha20poly1305.Overhead)
	if uint64(len(f.Blob)) != wantBlob {
		return nil, fmt.Errorf("the sealed material is %d hex characters and a grant of %d segments is %d",
			len(f.Blob), f.Granted, wantBlob)
	}
	return &f, nil
}
