package builtin

// Reading a record: record_read, record_read_partial and record_prove_segment.
//
// The split between the first two is the point of this file. A read that
// touches a segment which does not open is an ERROR, naming those segments,
// because the caller who wrote `record_read(r, 0, n)` is a caller who believes
// they are getting n bytes of evidence. Returning a buffer with zeros where the
// withheld spans were -- quietly, under the same name -- would hand them
// something that looks exactly like evidence and is not.
//
// record_read_partial is that buffer, under a name that says so, with a `holes`
// list beside it. The holes are zero-filled rather than removed so that offsets
// still line up with the record's own numbering, which is the same reason the
// format refuses to pad: a recipient who cannot place their fragments at their
// true positions cannot reconstruct the document they were given.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"mutant/object"
	"mutant/security"
)

// recordHole is one span a read could not decrypt.
type recordHole struct {
	index  uint64
	offset uint64
	length uint64
	class  string
	reason string
}

// recordReadSpan is the shared body of both reads.
//
// It always produces the full buffer and the full hole list; the two builtins
// differ only in what they do with a non-empty hole list. One implementation,
// so the two contracts can never disagree about what was readable.
//
// It also returns the class tags of the segments it actually decrypted, in
// the order it met them, which is what the returned buffer is marked with. A
// hole contributes no class: there is no plaintext of it in the buffer.
func recordReadSpan(op string, session *recordSession, offset, length uint64) ([]byte, []recordHole, []string, *object.Error) {
	end := offset + length
	if end < offset || end > session.header.PlaintextLength {
		return nil, nil, nil, newError("%s: %d+%d runs past the %d bytes this record holds",
			op, offset, length, session.header.PlaintextLength)
	}
	out := make([]byte, length)
	var holes []recordHole
	var tags []string
	seenTag := map[string]bool{}

	ciphertext := make([]byte, 0, session.header.SegmentSize+64)
	for _, segment := range session.segments {
		segmentEnd := segment.Offset + uint64(segment.Length)
		if segmentEnd <= offset || segment.Offset >= end {
			continue
		}
		if uint64(cap(ciphertext)) < segment.StoredLength {
			ciphertext = make([]byte, segment.StoredLength)
		}
		chunk := ciphertext[:segment.StoredLength]

		// The overlap between this segment and the requested span, in plaintext
		// coordinates. Computed before the decrypt so that a hole can be
		// reported at exactly the bytes a successful read would have filled.
		from, to := segment.Offset, segmentEnd
		if from < offset {
			from = offset
		}
		if to > end {
			to = end
		}
		hole := func(reason string) {
			holes = append(holes, recordHole{
				index:  segment.Index,
				offset: from,
				length: to - from,
				class:  hex.EncodeToString(segment.Class[:]),
				reason: reason,
			})
		}

		if _, err := session.file.ReadAt(chunk, int64(session.dataOffset+segment.StoredOffset)); err != nil {
			hole("the segment's bytes could not be read from the file")
			continue
		}
		aad, err := session.header.SegmentAAD(segment, uint64(len(session.segments)))
		if err != nil {
			return nil, nil, nil, newError("%s: %s", op, err.Error())
		}
		plaintext, err := session.openSegment(aad, chunk)
		if err != nil {
			// "does not open" and not "is not authentic": after any disclosure a
			// segment key is held by its recipient too, so a segment that opens
			// proves only that somebody holding that key wrote it.
			//
			// A segment the grant does not cover is said as that. It is the
			// ordinary case for a recipient and the reason is public -- the
			// granted set is in the grant file and the manifest -- whereas a
			// granted segment that fails its tag is a different finding and
			// must not read like one.
			switch {
			case errors.Is(err, security.ErrSegmentNotGranted):
				hole("this record was opened under a grant that does not include this segment")
			case session.grant != nil:
				hole("the segment does not open under the material granted for it")
			default:
				hole("the segment does not open under this record's key")
			}
			continue
		}
		copy(out[from-offset:to-offset], plaintext[from-segment.Offset:to-segment.Offset])
		security.SecureZero(plaintext)
		if tag := hex.EncodeToString(segment.Class[:]); !seenTag[tag] {
			seenTag[tag] = true
			tags = append(tags, tag)
		}
	}
	return out, holes, tags, nil
}

// recordClassification is the mark a read's output carries: the record, and
// the classes of the segments that went into it, named where the open case
// can name them. It holds no plaintext.
func recordClassification(session *recordSession, tags []string) *object.Classification {
	labels := make([]string, len(tags))
	custodyStore.RLock()
	if open := custodyStore.session; open != nil {
		for i, tag := range tags {
			for _, class := range open.classes {
				if strings.EqualFold(class.Tag, tag) {
					labels[i] = class.Label
				}
			}
		}
	}
	custodyStore.RUnlock()
	return &object.Classification{RecordUID: session.header.RecordUID, Tags: tags, Labels: labels}
}

func recordReadArgs(op string, args []object.Object) (*recordSession, uint64, uint64, *object.Error) {
	if len(args) != 3 {
		return nil, 0, 0, newError("wrong number of arguments. got=%d, want=3", len(args))
	}
	session, errObj := recordHandleArg(op, args, 3)
	if errObj != nil {
		return nil, 0, 0, errObj
	}
	offset, errObj := requireIntArg(op, args[1], 2)
	if errObj != nil {
		return nil, 0, 0, errObj
	}
	length, errObj := requireIntArg(op, args[2], 3)
	if errObj != nil {
		return nil, 0, 0, errObj
	}
	if offset < 0 {
		return nil, 0, 0, newError("%s: an offset of %d is before the start of the record", op, offset)
	}
	if length < 0 {
		return nil, 0, 0, newError("%s: a length of %d is not a number of bytes", op, length)
	}
	return session, uint64(offset), uint64(length), nil
}

// RecordRead returns a span of plaintext, or refuses and says which segments
// stood in the way.
func RecordRead(args ...object.Object) object.Object {
	op := BuiltinNameRecordRead
	session, offset, length, errObj := recordReadArgs(op, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	out, holes, tags, errObj := recordReadSpan(op, session, offset, length)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if len(holes) > 0 {
		security.SecureZero(out)
		return resultAndError(nil, newError("%s: %d of the segments under %d+%d %s. %s. Use `%s` for the "+
			"bytes that are readable, which returns the holes as data rather than as an error",
			op, len(holes), offset, length,
			map[bool]string{true: "does not open", false: "do not open"}[len(holes) == 1],
			recordHoleSummary(holes), BuiltinNameRecordReadPartial))
	}
	// A *object.Bytes and never a STRING: a Go string cannot be zeroed and the
	// runtime copies one at will. See object/bytesObj.go. Marked, so that the
	// builtins that send a value out of the process refuse it; see
	// builtin/classified.go.
	return resultAndError(&object.Bytes{Value: out, Classified: recordClassification(session, tags)}, nil)
}

// RecordReadPartial returns what is readable, plus exactly what is not.
func RecordReadPartial(args ...object.Object) object.Object {
	op := BuiltinNameRecordReadPartial
	session, offset, length, errObj := recordReadArgs(op, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	out, holes, tags, errObj := recordReadSpan(op, session, offset, length)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	rows := make([]object.Object, 0, len(holes))
	var withheld uint64
	for _, hole := range holes {
		withheld += hole.length
		rows = append(rows, makeHashObject(map[string]object.Object{
			"segment": intObj(int64(hole.index)),
			"offset":  intObj(int64(hole.offset)),
			"length":  intObj(int64(hole.length)),
			"class":   stringObj(hole.class),
			"reason":  stringObj(hole.reason),
		}))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"bytes": &object.Bytes{Value: out, Classified: recordClassification(session, tags)},
		"holes": &object.Array{Elements: rows},
		// Both numbers, because "how much did I get" and "how much is missing"
		// are different questions and a caller should not have to subtract.
		"length":   intObj(int64(length)),
		"withheld": intObj(int64(withheld)),
		"complete": boolObj(len(holes) == 0),
		// Said plainly: the holes are zeros in the buffer, and zeros are also a
		// thing evidence contains.
		"holes_are_zero_filled": boolObj(true),
	}), nil)
}

func recordHoleSummary(holes []recordHole) string {
	const show = 4
	summary := ""
	for i, hole := range holes {
		if i == show {
			summary += fmt.Sprintf(", and %d more", len(holes)-show)
			break
		}
		if i > 0 {
			summary += ", "
		}
		summary += fmt.Sprintf("segment %d at %d+%d", hole.index, hole.offset, hole.length)
	}
	return summary
}

// RecordProveSegment cites one segment of a record in a form a third party can
// check against the copy they hold.
//
// It is deliberately NOT a Merkle inclusion proof. A tree would buy a compact
// path to the root, and compactness is worth having only when the verifier does
// not have the data -- but a disclosure hands over a record that is
// byte-identical to the one under custody, so every recipient already holds
// every segment and can recompute the whole fold themselves. What they lack is
// not data but a citation: a statement of which segment, at which offset, under
// which class, with which digest, folding into which signed root.
//
// `does_not_prove` is a field and not a comment because that is the difference
// between this and a claim it cannot back.
func RecordProveSegment(args ...object.Object) object.Object {
	op := BuiltinNameRecordProveSegment
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := recordHandleArg(op, args, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	index, errObj := requireIntArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if index < 0 || index >= int64(len(session.segments)) {
		return resultAndError(nil, newError("%s: this record has %d segments, numbered from 0, and %d is "+
			"not one of them", op, len(session.segments), index))
	}
	segment := session.segments[index]

	ciphertext := make([]byte, segment.StoredLength)
	if _, err := session.file.ReadAt(ciphertext, int64(session.dataOffset+segment.StoredOffset)); err != nil {
		return resultAndError(nil, newError("%s: reading segment %d: %s", op, index, err.Error()))
	}
	aad, err := session.header.SegmentAAD(segment, uint64(len(session.segments)))
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	digest := security.SegmentDigest(aad, ciphertext)

	// Recomputed now rather than read from the footer, so that the answer is
	// about the bytes on disk and not about what the document says of them.
	root, errObj := recordRecomputeRoot(op, session)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	rootHex := hex.EncodeToString(root[:])

	return resultAndError(makeHashObject(map[string]object.Object{
		"record_uid":    stringObj(session.header.RecordUID),
		"segment":       intObj(index),
		"offset":        intObj(int64(segment.Offset)),
		"length":        intObj(int64(segment.Length)),
		"class":         stringObj(hex.EncodeToString(segment.Class[:])),
		"digest":        stringObj(hex.EncodeToString(digest[:])),
		"segments_root": stringObj(rootHex),
		// Whether the record on disk still folds to the root its footer names.
		"root_matches":    boolObj(rootHex == session.footer.SegmentsRoot),
		"signed":          boolObj(session.signed),
		"signature_valid": boolObj(session.signatureValid),
		"content_free":    boolObj(true),
		"proves": stringArrayObj([]string{
			"that these exact ciphertext bytes sit at this offset, under this class, in this record",
			"that they fold into the root the record's footer names, if root_matches is true",
		}),
		"does_not_prove": stringArrayObj([]string{
			"what the segment contains: this citation is content-free and reveals no plaintext",
			"who wrote the segment: a segment opens for anyone holding its key, which after a " +
				"disclosure includes the recipient",
			"that the class applied to the segment was the correct one",
		}),
	}), nil)
}
