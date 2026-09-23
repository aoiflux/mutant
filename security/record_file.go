package security

// The `.mrec` container.
//
// This file does no I/O either. It turns a record's public structure into the
// bytes that go on disk and back, and it says what a reader can establish from
// those bytes alone. Where the file lives, how it is created and whether the
// write is atomic are decided in builtin/record.go, beside the other decisions
// of that kind.
//
// # The shape
//
//	off      size  field
//	  0         8  magic "MUTMREC\x01"
//	  8         4  header length, big endian
//	 12         H  header, JSON, UTF-8 -- SIGNED AS THESE EXACT BYTES
//	 12+H       D  segment ciphertexts, index order, no padding between them
//	 12+H+D     4  footer length, big endian
//	 12+H+D+4   F  footer, JSON
//
// D is derived from the header and is not stored. A file whose length does not
// match what its own header describes is refused before anything in it is
// believed, which is one detection a stored length would have cost.
//
// # Why the header stores spans and not segments
//
// A segment is the AEAD unit, the key-derivation unit and the smallest
// disclosable unit, so a 1 GiB record has 16384 of them and a large one has far
// more. A segment table would put the header's size on the data volume for no
// gain, because a segment table is derivable: spans partition the plaintext,
// each span splits into segments of at most SegmentSize, and each segment's
// ciphertext is its plaintext plus a fixed tag laid down in order. Spans are
// what the examiner actually declared, and there are usually a handful.
//
// Deriving also removes a second source of truth. A stored table could disagree
// with the spans it was built from, and then two readers of one file would be
// looking at two different records.
//
// # What a reader with no key can establish
//
// Everything a segment descriptor binds is public -- case uid, record uid,
// index, count, offset, length, generation and class tag -- so this file can
// rebuild every descriptor, recompute every segment digest from the stored
// ciphertext, recompute the root and check the signature, holding nothing. That
// is the property record_verify exists for and the reason the class TAG is here
// while the class LABEL is not: the label's meaning lives in the signed case
// manifest, which is deliberately not in this file. See
// docs/DISCLOSURE_POLICY.md, "A record without its case is evidentially mute".
//
// Descriptors are struct literals here because this is package security. No
// package outside it can spell one, so builtin/record.go still cannot invent a
// descriptor; it can only ask a header for the ones that header describes.
//
// # What it cannot establish
//
// Who signed it. The public key is in the footer and the footer names it, so an
// altered record re-signed under a fresh keypair verifies perfectly -- as a
// record signed by that keypair, which is all a signature ever says. Identity
// in this tree is examiner-asserted and recorded, and the honest surface is to
// report the key, report whether it was created during this run, and let a
// reader compare it with a key they already trusted. The signature
// authenticates the document, not the names in it.
//
// Nor whether the plaintext is the evidence it claims to be. The whole-record
// plaintext digest is in the header ENCRYPTED, not in the clear: a digest over
// the plaintext, published beside the ciphertext, confirms any plaintext an
// adversary can guess, which for a short or formulaic segment is the whole
// secret. So a holder of the case key can check the record decrypts to the
// evidence that was sealed, and a holder of nothing cannot, and record_verify
// says which of those it did.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// aeadOverhead is the Poly1305 tag every sealed segment carries. Named rather
// than spelled inline because the segment layout arithmetic uses it four times
// and a record whose stored offsets are out by 16 bytes is a record that opens
// nothing.
const aeadOverhead = chacha20poly1305.Overhead

const (
	// RecordFileMagic opens every .mrec. The trailing version byte is part of
	// the magic so that a later format is not merely refused by a field check
	// after its header has already been parsed.
	RecordFileMagic = "MUTMREC\x01"
	// RecordFileFormat is the header's "format" field, spelled out for a reader
	// looking at the JSON rather than the bytes.
	RecordFileFormat = "mutant-record"
	// RecordFileVersion is the version this build writes and the only one it
	// reads.
	RecordFileVersion uint32 = 1

	// RecordSignatureDomain opens the message the record signature covers. It
	// is not the file magic: signing a message that begins with the file's own
	// first bytes invites a cross-protocol confusion where some other
	// document's signature is presented as this one's.
	RecordSignatureDomain = "MRECSIG1"
	// RecordSegmentsRootDomain prefixes the segment-digest root so the root of
	// a record cannot be replayed as any other digest this tree computes.
	RecordSegmentsRootDomain = "mutant-record-segments-root-v1"
	// HKDFInfoRecordMeta derives the key that encrypts the header's private
	// block -- today the whole-plaintext digest.
	HKDFInfoRecordMeta = "mutant-record-meta-v1"

	// DefaultSegmentSize is 64 KiB: small enough that a disclosure is granular,
	// large enough that the per-segment tag and key derivation are noise.
	DefaultSegmentSize uint32 = 64 << 10

	// MaxRecordSpans bounds the classification ranges one record may carry. A
	// span list is read by a person deciding whether a disclosure is fair, and
	// past a few thousand rows nobody is reading it.
	MaxRecordSpans = 4096

	// MaxRecordSegments bounds the DERIVED segment table, which is the number
	// MaxRecordSpans does not bound and the one a hostile header controls.
	//
	// Spans are few, but a span's segment count is its length divided by the
	// segment size, and both of those are header fields. A 499-byte header
	// declaring one span of 40 MiB at a segment size of 1 derives 41,943,040
	// segments: seconds of work and gigabytes of table, asked for by a file
	// that is smaller than this comment and authenticated by nothing. Every
	// other length this tree reads off a wire or a disk is bounded before it is
	// allocated against -- ws_read_frame against maxHTTPBodyBytes, the debug
	// adapter against maxMessageBytes -- and a derived count needs the same
	// treatment as a stored one.
	//
	// A million segments is 64 GiB of plaintext at the default segment size and
	// 1 TiB at the largest, so a record that hits this is a record that should
	// raise its segment size rather than one this format cannot hold.
	MaxRecordSegments = 1 << 20

	// MaxRecordHeader and MaxRecordFooter bound what is read and parsed before
	// a signature has been checked. Neither is a limit an honest record meets.
	MaxRecordHeader = 8 << 20
	MaxRecordFooter = 1 << 20

	// RecordFilePrefixSize is the magic plus the header length.
	RecordFilePrefixSize = len(RecordFileMagic) + 4
	// RecordFooterPrefixSize is the footer length that precedes the footer. It
	// carries no magic of its own: by the time it is read, the header has
	// already said this is a record and said where the footer begins.
	RecordFooterPrefixSize = 4
)

// ErrRecordFormat is returned for a file that is not a record this build can
// read. It is deliberately distinct from a signature failure: "this is not one
// of ours" and "this is one of ours and it has been edited" are different
// things to tell an examiner.
var ErrRecordFormat = errors.New("this is not a mutant record file this build can read")

// ErrRecordSignature is returned when a record's signature does not cover the
// bytes that are there.
var ErrRecordSignature = errors.New("the record's signature does not match its header and segments")

// RecordSpan is one run of uniform classification over the plaintext.
//
// Spans partition [0, PlaintextLength) exactly: no gaps, no overlaps, in
// ascending order. Overlaps are refused rather than resolved because which
// label wins where two ranges disagree is a legal question and not an
// engineering one, and a tool that picked silently would be answering it.
type RecordSpan struct {
	Offset uint64 `json:"offset"`
	Length uint64 `json:"length"`
	// Class is the class tag, 64 hex characters, HMAC'd under the case key. The
	// LABEL is not here; see the file header.
	Class string `json:"class"`
}

// RecordSealedBlock is an AEAD blob inside the header: a nonce and a
// ciphertext, both hex.
type RecordSealedBlock struct {
	Nonce string `json:"nonce"`
	Blob  string `json:"blob"`
}

// RecordHeader is everything about a record that is public.
//
// Two generation fields, never one. SealedUnderGeneration is bound into every
// segment descriptor and must never change; WrappedUnderGeneration is the
// generation whose case key currently wraps the record key and is the only one
// a rotation migration may touch. Confusing them makes every segment of a
// migrated record permanently unopenable, which is why they are named at length
// rather than shortened to something a reader could skim past.
type RecordHeader struct {
	Format  string `json:"format"`
	Version uint32 `json:"version"`

	RecordUID string `json:"record_uid"`
	CaseUID   string `json:"case_uid"`
	// CaseKeyID is the short public name of the case key, for a reader matching
	// a record to a case. It is derived through HKDF and is not a secret.
	CaseKeyID string `json:"case_key_id"`

	SealedUnderGeneration  uint32 `json:"sealed_under_generation"`
	WrappedUnderGeneration uint32 `json:"wrapped_under_generation"`

	RecordKeyNonce   string `json:"record_key_nonce"`
	RecordKeyWrapped string `json:"record_key_wrapped"`
	SealSalt         string `json:"seal_salt"`

	PlaintextLength uint64 `json:"plaintext_length"`
	SegmentSize     uint32 `json:"segment_size"`
	// Quantum is 0 for a record sealed at the classification boundaries the
	// examiner gave, and the rounding unit for one sealed by
	// record_seal_quantised.
	//
	// QuantisedExtra is how many bytes that rounding MOVED between classes, and
	// RoundsTo is the class tag they moved into -- the class the examiner named
	// as the one rounding was permitted to grow. Two fields and not one,
	// because a count with no direction cannot be read: rounding takes bytes
	// out of the default class and puts them in RoundsTo, which withholds more
	// only when RoundsTo is the more sensitive of the two, and nothing in this
	// format orders classes. A recipient reading this learns that spans tagged
	// RoundsTo may be up to Quantum-1 bytes wider at each end than the
	// classification the examiner actually drew, and how many bytes that came
	// to in total. What that means for them is theirs to judge.
	//
	// An earlier version of this comment said a quantised record "withholds
	// MORE than was asked". That is true when the rounded class is the
	// sensitive one and false when it is the released one, and a record that
	// asserts it unconditionally is a record making a claim it cannot back.
	Quantum        uint32 `json:"quantum"`
	QuantisedExtra uint64 `json:"quantised_extra"`
	RoundsTo       string `json:"rounds_to"`

	Created string `json:"created"`
	// Examiner is asserted and recorded. Nothing authenticates it.
	Examiner string `json:"examiner"`
	// Source is what the examiner said this record was made from. It is a note,
	// not a link: nothing here opens it or checks it.
	Source string `json:"source"`

	Spans []RecordSpan `json:"spans"`
}

// RecordFooter is what can only be written once every segment is sealed.
//
// The private block lives here rather than in the header for one practical
// reason: it holds a digest over the whole plaintext, the header is written
// before any segment is, and a digest in the header would therefore force a
// sealer to read its source twice. On a disk image that is minutes of I/O to
// buy a field that is just as safe written last. The signature covers it, so
// moving it here costs nothing in what can be checked.
type RecordFooter struct {
	// SealedMeta holds what would confirm guessed plaintext if it were in the
	// clear. Today: the whole-plaintext SHA-256, encrypted under a key derived
	// from the record key. A holder of the case key can check the record
	// decrypts to the evidence that was sealed; a holder of nothing cannot, and
	// that asymmetry is the whole point of not publishing the digest.
	SealedMeta RecordSealedBlock `json:"sealed_meta"`

	// SegmentsRoot is over every segment's digest, in index order, so it binds
	// the count and the order as well as the bytes.
	SegmentsRoot string `json:"segments_root"`
	// Signed is false for a record written on a machine with no key store. That
	// is a normal outcome and is reported as its own bit rather than folded
	// into a failed verification, which is the shape this tree uses everywhere
	// a signature is optional.
	Signed          bool   `json:"signed"`
	SignatureReason string `json:"signature_reason,omitempty"`
	PublicKey       string `json:"public_key,omitempty"`
	Signature       string `json:"signature,omitempty"`
	// KeyCreatedForThisRun is true when the signing key did not exist until
	// this process asked for one. A signature under a key born seconds before
	// the evidence it vouches for is not the same thing as a signature under a
	// key an organisation has held, and a document that does not distinguish
	// them invites a reading it cannot support.
	KeyCreatedForThisRun bool `json:"key_created_for_this_run"`
}

// RecordSegment is one derived segment. Nothing stores these; Segments builds
// them from the spans every time, so they cannot drift from what they describe.
type RecordSegment struct {
	Index  uint64
	Offset uint64
	Length uint32
	Class  ClassTag
	// StoredOffset is relative to the start of the segment data area, not to
	// the start of the file, so a caller adds the data offset once and a
	// mistake there is one mistake rather than one per segment.
	StoredOffset uint64
	StoredLength uint64
}

// RecordMeta is the JSON inside SealedMeta.
type RecordMeta struct {
	PlaintextSHA256 string `json:"plaintext_sha256"`
}

// ---------------------------------------------------------------------------
// Deriving the segment table
// ---------------------------------------------------------------------------

// SegmentCount validates the span list and reports how many segments it
// derives, in time proportional to the number of SPANS and with no allocation.
//
// It exists apart from Segments because validating a header and materialising
// its table are two different needs, and conflating them is what let a header
// smaller than a paragraph ask a parser for a table of tens of millions of
// rows. Every caller that only wants to know whether a header is coherent --
// ParseRecordHeader, and any future one -- asks this; only a caller that is
// about to read or write the segments builds them.
func (h *RecordHeader) SegmentCount() (uint64, error) {
	if h.SegmentSize == 0 || h.SegmentSize > MaxSegmentPlaintext {
		return 0, fmt.Errorf("a segment size of %d is outside 1..%d", h.SegmentSize, MaxSegmentPlaintext)
	}
	if len(h.Spans) == 0 {
		return 0, errors.New("a record has at least one classification span")
	}
	if len(h.Spans) > MaxRecordSpans {
		return 0, fmt.Errorf("a record carries at most %d classification spans, this one declares %d",
			MaxRecordSpans, len(h.Spans))
	}

	size := uint64(h.SegmentSize)
	var nextOffset, count uint64
	for i, span := range h.Spans {
		if span.Offset != nextOffset {
			return 0, fmt.Errorf(
				"span %d starts at %d and the span before it ended at %d; spans partition the plaintext "+
					"with no gap and no overlap, because which label wins where two ranges disagree is not "+
					"a question this tool may answer for you",
				i, span.Offset, nextOffset)
		}
		if span.Length == 0 {
			return 0, fmt.Errorf("span %d is empty; a classification that covers nothing is a mistake, "+
				"not a range", i)
		}
		if _, err := classTagFromHex(span.Class); err != nil {
			return 0, fmt.Errorf("span %d: %w", i, err)
		}
		end := span.Offset + span.Length
		if end < span.Offset || end > h.PlaintextLength {
			return 0, fmt.Errorf("span %d runs to %d, past the %d bytes the record says it holds",
				i, end, h.PlaintextLength)
		}
		// Divide-then-adjust rather than (length + size - 1) / size: the
		// rounding form overflows for a length near the top of a uint64, which
		// is exactly the length a hostile header would choose.
		n := span.Length / size
		if span.Length%size != 0 {
			n++
		}
		// Accumulated inside the loop so that the refusal happens on the span
		// that crosses the line, and so the sum itself cannot wrap on the way
		// to being checked.
		count += n
		if count > MaxRecordSegments {
			return 0, fmt.Errorf(
				"this header describes at least %d segments and a record holds at most %d. Its %d bytes at "+
					"a segment size of %d is more segments than a record can have; seal it with a larger "+
					"segment_size, up to %d",
				count, uint64(MaxRecordSegments), h.PlaintextLength, h.SegmentSize, MaxSegmentPlaintext)
		}
		nextOffset = end
	}
	if nextOffset != h.PlaintextLength {
		return 0, fmt.Errorf("the spans cover %d bytes and the record says it holds %d; a record with an "+
			"unclassified tail would disclose that tail to everyone", nextOffset, h.PlaintextLength)
	}
	return count, nil
}

// Segments derives the whole segment table from the spans.
//
// Validation is here and not in the parser because these are the same checks a
// sealer needs before it writes, and one implementation of "what is a valid
// span list" is the only way the writer and the reader agree.
func (h *RecordHeader) Segments() ([]RecordSegment, error) {
	count, err := h.SegmentCount()
	if err != nil {
		return nil, err
	}

	// Allocated once, to the count that was just bounded. The old form grew
	// from len(spans), so the size of the allocation was decided by the loop
	// rather than before it.
	segments := make([]RecordSegment, 0, count)
	var (
		stored uint64
		index  uint64
	)
	for _, span := range h.Spans {
		// Re-derived rather than carried out of SegmentCount: this loop runs
		// only on a span list that has already been validated whole, so there
		// is nothing left here to check and nothing to get out of step.
		tag, err := classTagFromHex(span.Class)
		if err != nil {
			return nil, err
		}
		end := span.Offset + span.Length
		for offset := span.Offset; offset < end; {
			length := uint64(h.SegmentSize)
			if remaining := end - offset; remaining < length {
				length = remaining
			}
			segments = append(segments, RecordSegment{
				Index:        index,
				Offset:       offset,
				Length:       uint32(length),
				Class:        tag,
				StoredOffset: stored,
				StoredLength: length + aeadOverhead,
			})
			stored += length + aeadOverhead
			offset += length
			index++
		}
	}
	return segments, nil
}

// StoredDataSize is the size of the segment data area, derived the same way.
func (h *RecordHeader) StoredDataSize(segments []RecordSegment) uint64 {
	var total uint64
	for _, segment := range segments {
		total += segment.StoredLength
	}
	return total
}

// SegmentAAD rebuilds one segment's descriptor from public header fields.
//
// This is the function that lets a reader holding no key check a record. The
// descriptor's fields are unexported and stay that way -- this is package
// security -- so what a caller outside can do is ask a header for the
// descriptors of the record that header describes, and nothing else.
func (h *RecordHeader) SegmentAAD(segment RecordSegment, total uint64) (SegmentAAD, error) {
	caseUID, err := caseUIDFromHex(h.CaseUID)
	if err != nil {
		return SegmentAAD{}, err
	}
	recordUID, err := recordUIDFromHex(h.RecordUID)
	if err != nil {
		return SegmentAAD{}, err
	}
	return SegmentAAD{
		caseUID:    caseUID,
		recordUID:  recordUID,
		index:      segment.Index,
		total:      total,
		offset:     segment.Offset,
		length:     segment.Length,
		generation: h.SealedUnderGeneration,
		classTag:   segment.Class,
	}, nil
}

// ---------------------------------------------------------------------------
// The private block
// ---------------------------------------------------------------------------

// SealMeta encrypts the header's private block under a key derived from the
// record key.
//
// The nonce is drawn here and returned; there is no parameter through which a
// caller could reuse one.
func (r *RecordKeys) SealMeta(meta []byte) (nonce XNonce, blob []byte, err error) {
	key, err := r.metaKey()
	if err != nil {
		return nonce, nil, err
	}
	defer SecureZero(key)
	raw, err := randomBytes(len(nonce))
	if err != nil {
		return nonce, nil, err
	}
	copy(nonce[:], raw)
	blob, err = sealWith(key, nonce, meta, r.metaAAD())
	return nonce, blob, err
}

// OpenMeta decrypts the header's private block. The additional data is rebuilt
// from the record's own identity, so a block moved to another record fails.
func (r *RecordKeys) OpenMeta(nonce XNonce, blob []byte) ([]byte, error) {
	key, err := r.metaKey()
	if err != nil {
		return nil, err
	}
	defer SecureZero(key)
	return openWith(key, nonce, blob, r.metaAAD(), ErrSegmentAuth)
}

func (r *RecordKeys) metaKey() ([]byte, error) {
	if r == nil || r.prk == nil {
		return nil, errors.New("the record key schedule has been zeroed")
	}
	return hkdf.Expand(sha256.New, r.prk, HKDFInfoRecordMeta, KeySize)
}

func (r *RecordKeys) metaAAD() []byte {
	aad := make([]byte, 0, len(HKDFInfoRecordMeta)+CaseUIDSize+RecordUIDSize+4)
	aad = append(aad, HKDFInfoRecordMeta...)
	aad = append(aad, r.caseUID[:]...)
	aad = append(aad, r.uid[:]...)
	var generation [4]byte
	binary.BigEndian.PutUint32(generation[:], r.generation)
	return append(aad, generation[:]...)
}

// ---------------------------------------------------------------------------
// The root and the signature
// ---------------------------------------------------------------------------

// SegmentsRoot folds every segment digest into one, in index order.
//
// A plain ordered fold and not a Merkle tree, deliberately: a tree buys
// per-segment inclusion proofs against the root, and a record already has a
// better one -- the segment's own AEAD tag, which a recipient checks with the
// key they were granted. What the root is for is binding the COUNT and the
// ORDER, so that dropping a trailing segment or transposing two is not a record
// that still verifies. The count goes in explicitly because a fold over zero
// digests and a fold over none are otherwise the same value.
func SegmentsRoot(digests [][sha256.Size]byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(RecordSegmentsRootDomain))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(digests)))
	h.Write(count[:])
	for _, digest := range digests {
		h.Write(digest[:])
	}
	var root [sha256.Size]byte
	copy(root[:], h.Sum(nil))
	return root
}

// RecordSigningMessage is what the signature covers: the header exactly as it
// is stored, the root over every segment, and the footer's private block.
//
// Every variable-length part is length-prefixed inside the message as well as
// wherever it sits in the file, so that two parts cannot be re-split at a
// different boundary to make one signature cover a different pair. The private
// block is included so that stripping it from a record is detectable; it cannot
// be REPLACED without the record key in any case, but deleting a field needs no
// key at all, and a record that quietly lost its plaintext digest would still
// have verified.
func RecordSigningMessage(header []byte, root [sha256.Size]byte, sealedMeta []byte) []byte {
	message := make([]byte, 0, len(RecordSignatureDomain)+16+len(header)+sha256.Size+len(sealedMeta))
	message = append(message, RecordSignatureDomain...)
	message = appendLengthPrefixed(message, header)
	message = append(message, root[:]...)
	return appendLengthPrefixed(message, sealedMeta)
}

func appendLengthPrefixed(dst, field []byte) []byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(field)))
	return append(append(dst, length[:]...), field...)
}

// footerMetaBytes is the private block in the exact form the signature covers.
//
// The hex strings and not the decoded bytes, so that there is no decode that
// could fail and turn two different malformed blocks into one signed message.
func footerMetaBytes(f *RecordFooter) []byte {
	return []byte(f.SealedMeta.Nonce + "|" + f.SealedMeta.Blob)
}

// SignRecordFooter fills in the footer's signature fields, or records why there
// is none.
//
// A machine with no key store is a normal place to seal a record, so the
// absence of a signature is reported and is not an error. What would be an
// error is a document that looked signed when it was not.
func SignRecordFooter(footer *RecordFooter, header []byte, root [sha256.Size]byte, sign bool) error {
	footer.SegmentsRoot = hex.EncodeToString(root[:])
	if !sign {
		footer.Signed = false
		footer.SignatureReason = "the record was sealed with sign:false"
		return nil
	}
	private, public, generated, reason, err := EnsureLocalSigningKeyPair()
	if err != nil {
		footer.Signed = false
		footer.SignatureReason = err.Error()
		return nil
	}
	footer.Signed = true
	footer.SignatureReason = reason
	footer.KeyCreatedForThisRun = generated
	footer.PublicKey = hex.EncodeToString(public)
	footer.Signature = hex.EncodeToString(
		ed25519.Sign(private, RecordSigningMessage(header, root, footerMetaBytes(footer))))
	return nil
}

// VerifyRecordSignature reports two bits and not one.
//
// signed says whether the record claims a signature at all; valid says whether
// that claim holds. Collapsing them would report an unsigned record and a
// forged one identically, and those call for opposite responses: one is a
// record to treat with the care an unsigned document deserves, the other is a
// record to stop using.
func VerifyRecordSignature(footer *RecordFooter, header []byte, root [sha256.Size]byte) (signed, valid bool, detail string) {
	if !footer.Signed && strings.TrimSpace(footer.Signature) == "" {
		reason := footer.SignatureReason
		if strings.TrimSpace(reason) == "" {
			reason = "the record carries no signature"
		}
		return false, false, reason
	}
	signed = true
	public, err := hex.DecodeString(footer.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return signed, false, "the named signer is not an Ed25519 public key"
	}
	signature, err := hex.DecodeString(footer.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return signed, false, "the signature is not an Ed25519 signature"
	}
	want, err := hex.DecodeString(footer.SegmentsRoot)
	if err != nil || len(want) != sha256.Size {
		return signed, false, "the footer's segment root is not a SHA-256 digest"
	}
	if !bytes.Equal(want, root[:]) {
		return signed, false, "the segments do not fold to the root the footer names, so the record's " +
			"contents have changed since it was signed"
	}
	if !ed25519.Verify(public, RecordSigningMessage(header, root, footerMetaBytes(footer)), signature) {
		return signed, false, "the signature does not cover this header and these segments"
	}
	// Said plainly, because a valid signature is the point at which a reader is
	// most likely to conclude more than it says.
	return signed, true, "the signature authenticates the document, not the names in it"
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

// MarshalRecordHeader renders the header. These exact bytes are what the
// signature covers, so nothing may reformat them between here and the file.
func MarshalRecordHeader(h *RecordHeader) ([]byte, error) { return json.Marshal(h) }

// MarshalRecordFooter renders the footer.
func MarshalRecordFooter(f *RecordFooter) ([]byte, error) { return json.Marshal(f) }

// ParseRecordHeader reads a header and refuses anything it does not fully
// understand.
//
// Unknown fields are rejected rather than ignored. A field this build does not
// know is either a later format's -- in which case reading the rest as if it
// were this format is exactly the wrong move -- or somebody's addition, and
// silently dropping an addition is how a document comes to mean less than it
// says.
func ParseRecordHeader(data []byte) (*RecordHeader, error) {
	header := &RecordHeader{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(header); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrRecordFormat, err.Error())
	}
	if decoder.More() {
		return nil, fmt.Errorf("%w: the header is followed by more JSON", ErrRecordFormat)
	}
	if header.Format != RecordFileFormat {
		return nil, fmt.Errorf("%w: its format is %q", ErrRecordFormat, header.Format)
	}
	if header.Version != RecordFileVersion {
		return nil, fmt.Errorf("%w: it is version %d and this build reads version %d",
			ErrRecordFormat, header.Version, RecordFileVersion)
	}
	if _, err := caseUIDFromHex(header.CaseUID); err != nil {
		return nil, err
	}
	if _, err := recordUIDFromHex(header.RecordUID); err != nil {
		return nil, err
	}
	if _, err := hexOfLength(header.SealSalt, SealSaltSize); err != nil {
		return nil, errors.New("the record's seal salt is not " + fmt.Sprint(SealSaltSize) + " bytes of hex")
	}
	if header.SealedUnderGeneration < 1 || header.WrappedUnderGeneration < 1 {
		return nil, fmt.Errorf("%w: generations are numbered from 1 and this record names %d and %d",
			ErrRecordFormat, header.SealedUnderGeneration, header.WrappedUnderGeneration)
	}
	if err := header.validateQuantisation(); err != nil {
		return nil, err
	}
	// The span list is validated here as well as by the caller, so that a
	// header which cannot describe a coherent record is refused at the parse
	// and not at the first read. Counted and not built: parsing is the first
	// thing done to bytes that have been authenticated by nothing, and it must
	// not be the place that allocates on their say-so.
	if _, err := header.SegmentCount(); err != nil {
		return nil, err
	}
	return header, nil
}

// validateQuantisation refuses the shapes of the rounding triple that cannot be
// read.
//
// Quantum, QuantisedExtra and RoundsTo are three fields describing one event,
// and only some combinations of them describe anything. A record claiming a
// rounding but naming no class it rounded into states a count with no
// direction, which the field comment above says cannot be read -- and a reader
// who cannot read it is a reader who will guess, in one of the two directions,
// with even odds of concluding that bytes were withheld when they were
// released. A record naming a direction for a rounding that did not happen
// invites the same guess from the other side.
//
// None of this is reachable from `record_seal_quantised`, which requires the
// option and writes all three together. It is reachable from a file, and a
// header is the part of a record that is authenticated by nothing at the point
// it is parsed. The point of checking here is that every later reader -- the
// loader, `record_verify`, `view_preview` -- may then treat the triple as
// coherent rather than each re-deriving what to do about a header that is not.
func (h *RecordHeader) validateQuantisation() error {
	if h.RoundsTo != "" {
		if _, err := classTagFromHex(h.RoundsTo); err != nil {
			return fmt.Errorf("%w: the class this record says its rounding grew is not a class tag", ErrRecordFormat)
		}
	}
	if h.Quantum == 0 {
		if h.QuantisedExtra != 0 || h.RoundsTo != "" {
			return fmt.Errorf("%w: this record says it was sealed at the boundaries it was given and "+
				"also describes a rounding, which cannot both be true", ErrRecordFormat)
		}
		return nil
	}
	if h.RoundsTo == "" {
		return fmt.Errorf("%w: this record says its boundaries were rounded to %d bytes and does not "+
			"name the class the rounding grew. Every byte a rounding grows over changes class, so a "+
			"count with no direction does not say whether those bytes were withheld or released",
			ErrRecordFormat, h.Quantum)
	}
	// Bounded against the record's own length rather than against anything
	// derived, because this runs before the segment table is counted and must
	// not depend on it. A rounding cannot move bytes a record does not hold.
	if h.QuantisedExtra > h.PlaintextLength {
		return fmt.Errorf("%w: this record says its rounding moved %d bytes between classes and holds "+
			"%d bytes in total", ErrRecordFormat, h.QuantisedExtra, h.PlaintextLength)
	}
	return nil
}

// ParseRecordFooter reads a footer under the same rule.
func ParseRecordFooter(data []byte) (*RecordFooter, error) {
	footer := &RecordFooter{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(footer); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrRecordFormat, err.Error())
	}
	if decoder.More() {
		return nil, fmt.Errorf("%w: the footer is followed by more JSON", ErrRecordFormat)
	}
	if _, err := hexOfLength(footer.SegmentsRoot, sha256.Size); err != nil {
		return nil, fmt.Errorf("%w: the footer's segment root is not a SHA-256 digest", ErrRecordFormat)
	}
	return footer, nil
}

// RecordFilePrefix is the magic and the header length, the first bytes of every
// record.
func RecordFilePrefix(headerLength int) []byte {
	prefix := make([]byte, RecordFilePrefixSize)
	copy(prefix, RecordFileMagic)
	binary.BigEndian.PutUint32(prefix[len(RecordFileMagic):], uint32(headerLength))
	return prefix
}

// RecordFooterPrefix is the four bytes that precede the footer.
func RecordFooterPrefix(footerLength int) []byte {
	prefix := make([]byte, RecordFooterPrefixSize)
	binary.BigEndian.PutUint32(prefix, uint32(footerLength))
	return prefix
}

// ParseRecordFooterPrefix reads it back under the same bound as the header.
func ParseRecordFooterPrefix(prefix []byte) (int, error) {
	if len(prefix) < RecordFooterPrefixSize {
		return 0, ErrRecordFormat
	}
	length := binary.BigEndian.Uint32(prefix)
	if length == 0 || length > MaxRecordFooter {
		return 0, fmt.Errorf("%w: it declares a %d-byte footer", ErrRecordFormat, length)
	}
	return int(length), nil
}

// SegmentDigest is what the footer's root is folded from: SHA-256 over the
// segment's additional data followed by its ciphertext.
//
// It lives here so that the AAD's encoded form never leaves this package. A
// caller outside can ask a header for a descriptor and ask this for a digest,
// and at no point holds the 104 bytes it would need to compute one for a
// descriptor the record does not describe.
func SegmentDigest(aad SegmentAAD, ciphertext []byte) [sha256.Size]byte {
	encoded := aad.encode()
	h := sha256.New()
	h.Write(encoded[:])
	h.Write(ciphertext)
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// ParseRecordFilePrefix reads it back, bounding the header length before a
// caller allocates for it.
func ParseRecordFilePrefix(prefix []byte) (headerLength int, err error) {
	if len(prefix) < RecordFilePrefixSize {
		return 0, ErrRecordFormat
	}
	if !bytes.Equal(prefix[:len(RecordFileMagic)], []byte(RecordFileMagic)) {
		return 0, ErrRecordFormat
	}
	length := binary.BigEndian.Uint32(prefix[len(RecordFileMagic):])
	if length == 0 || length > MaxRecordHeader {
		return 0, fmt.Errorf("%w: it declares a %d-byte header", ErrRecordFormat, length)
	}
	return int(length), nil
}

// ---------------------------------------------------------------------------
// Small conversions, kept here so their error messages read the same way
// ---------------------------------------------------------------------------

func classTagFromHex(s string) (ClassTag, error) {
	var tag ClassTag
	raw, err := hexOfLength(s, sha256.Size)
	if err != nil {
		return tag, errors.New("a class tag is 64 hex characters keyed to the case key")
	}
	copy(tag[:], raw)
	return tag, nil
}

func caseUIDFromHex(s string) (CaseUID, error) {
	raw, err := hexOfLength(s, CaseUIDSize)
	if err != nil {
		var zero CaseUID
		return zero, errors.New("the record's case uid is not 32 hex characters")
	}
	return CaseUIDFromSlice(raw)
}

func recordUIDFromHex(s string) (RecordUID, error) {
	raw, err := hexOfLength(s, RecordUIDSize)
	if err != nil {
		var zero RecordUID
		return zero, errors.New("the record's uid is not 32 hex characters")
	}
	return RecordUIDFromSlice(raw)
}
