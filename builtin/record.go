package builtin

// The `record_*` family: sealing evidence into a `.mrec` and reading it back.
//
// This file owns the decisions security/record_file.go deliberately does not:
// where a record lives, that it is created with O_EXCL and never over an
// existing file, what a handle is, and what a program is told when a segment
// does not open. The format itself -- what the bytes mean, what a reader with
// no key can establish -- is next door, in one place a reviewer can read whole.
//
// # Every byte carries a classification
//
// `record_seal` requires a `default` class and applies it to everything the
// declared ranges do not cover. There is no implicit "unclassified": a record
// with an unlabelled remainder is a record whose remainder is disclosed to
// everyone who is disclosed anything, and the difference between "the examiner
// decided this is open" and "the examiner did not think about this" is exactly
// the difference a document like this exists to record.
//
// Overlapping ranges are refused rather than resolved. Which label wins where
// two ranges disagree is a legal question, and a tool that picked silently
// would be answering it.
//
// # A handle, and a reason for one
//
// record_open returns a handle because a record is a file that stays open and
// holds a key schedule, and because the alternative -- a path passed to every
// read -- would re-derive that schedule per call and leave nothing to close.
// The handles live in a map of their own, not in dbHandles and not in
// ledgerHandles, so that no db_* or ledger_* builtin can resolve a record and
// no record_* builtin can resolve a graph.
//
// # What record_read refuses to do
//
// A read whose span touches a segment that does not open is an ERROR naming
// those segments, not a short read and not a buffer with holes in it silently.
// `record_read_partial` is a separate builtin with a separate contract for the
// caller who genuinely wants what is readable: it returns the bytes with the
// unreadable spans zero-filled, so offsets still line up, and a `holes` list
// saying exactly which spans those were. Two contracts, because a caller who
// has not thought about holes should not get them by default.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mutant/object"
	"mutant/security"
)

var (
	recordHandleCounter int64

	// recordHandles maps int64 -> *recordSession, in a map of its own. See the
	// file header for why it is not dbHandles.
	recordHandles sync.Map
)

// recordSession is one open record: the file, its public structure, and the key
// schedule that opens its segments.
type recordSession struct {
	path       string
	file       *os.File
	header     *security.RecordHeader
	headerRaw  []byte
	footer     *security.RecordFooter
	segments   []security.RecordSegment
	dataOffset uint64

	// keys is the schedule this record's segments open under. It can only ever
	// open: OpenRecordKeys returns a handle that cannot seal, which is what
	// stops a program re-sealing a position and putting two plaintexts under
	// one keystream.
	//
	// Exactly one of keys and grant is set. A record opened with the case key
	// holds the schedule and can issue a disclosure; a record opened under a
	// grant holds the granted material and nothing else, and can issue
	// nothing -- a recipient cannot re-disclose, because there is no schedule
	// on their side of the disclosure to derive a grant from.
	keys  *security.RecordKeys
	grant *security.RecordGrant
	// disclosureUID names the disclosure a grant-opened record came from.
	disclosureUID string

	signed         bool
	signatureValid bool
	signatureNote  string
	openedAt       time.Time
}

// openSegment decrypts one segment under whatever this record was opened with.
func (s *recordSession) openSegment(aad security.SegmentAAD, ciphertext []byte) ([]byte, error) {
	if s.grant != nil {
		return s.grant.OpenSegment(aad, ciphertext)
	}
	return s.keys.OpenSegment(aad, ciphertext)
}

// zero releases the key material, whichever kind it is. Both are nil-safe.
func (s *recordSession) zero() {
	s.keys.Zero()
	s.grant.Zero()
}

// openedWith names the material, for a reader deciding what a hole means.
func (s *recordSession) openedWith() string {
	if s.grant != nil {
		return "grant"
	}
	return "case_key"
}

const (
	recordDefaultOption  = "default"
	recordSignOption     = "sign"
	recordSegmentOption  = "segment_size"
	recordSourceOption   = "source"
	recordQuantumOption  = "quantum"
	recordRoundsToOption = "rounds_to"
	recordMaxRangesInArg = security.MaxRecordSpans
)

var (
	recordSealOptions          = []string{recordDefaultOption, recordSignOption, recordSegmentOption, recordSourceOption}
	recordSealQuantisedOptions = append([]string{recordQuantumOption, recordRoundsToOption},
		recordSealOptions...)
)

// ---------------------------------------------------------------------------
// record_classify_range
// ---------------------------------------------------------------------------

// RecordClassifyRange describes one run of bytes and the class it carries.
//
// It is a builtin rather than a hash a program writes out because it resolves
// the label to its tag, and a label that was never declared is refused HERE --
// at the line that named it -- rather than at the seal, by which point the
// program has usually built a list and lost track of which entry was wrong.
func RecordClassifyRange(args ...object.Object) object.Object {
	op := BuiltinNameRecordClassifyRange
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	offset, errObj := requireIntArg(op, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	length, errObj := requireIntArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	label, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if offset < 0 {
		return resultAndError(nil, newError("%s: an offset of %d is before the start of the record", op, offset))
	}
	if length <= 0 {
		return resultAndError(nil, newError("%s: a range of %d bytes classifies nothing; a classification "+
			"that covers no bytes is a mistake, not a range", op, length))
	}

	class, errObj := recordLookupClass(op, label)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"offset": intObj(offset),
		"length": intObj(length),
		"label":  stringObj(class.Label),
		// The tag, not only the label, so that a range carries the thing the
		// segment will actually be bound to. A reader comparing a range against
		// a sealed record compares tags; labels are for the report.
		"class": stringObj(class.Tag),
	}), nil)
}

// recordLookupClass resolves a label against the classes declared for this
// case. It takes the read lock itself and holds it for no longer than the scan.
func recordLookupClass(op, label string) (caseClass, *object.Error) {
	canonical, errObj := canonicalClassLabel(op, label)
	if errObj != nil {
		return caseClass{}, errObj
	}
	custodyStore.RLock()
	defer custodyStore.RUnlock()
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return caseClass{}, errObj
	}
	if session.classTagKey == nil {
		return caseClass{}, newError("%s: no case key is open; call `case_key_open(path)` first, because "+
			"a classification is tagged under the case key", op)
	}
	for _, class := range session.classes {
		if class.Canonical == canonical {
			return class, nil
		}
	}
	declared := make([]string, 0, len(session.classes))
	for _, class := range session.classes {
		declared = append(declared, class.Label)
	}
	if len(declared) == 0 {
		return caseClass{}, newError("%s: %q is not a declared classification, and this case has declared "+
			"none. Call `class_define(label)` first, so that a typo is an error rather than a new secret "+
			"class nobody recognises", op, label)
	}
	return caseClass{}, newError("%s: %q is not a declared classification. This case declares %s",
		op, label, strings.Join(declared, ", "))
}

// ---------------------------------------------------------------------------
// record_seal and record_seal_quantised
// ---------------------------------------------------------------------------

// RecordSeal encrypts a file into a record at the classification boundaries it
// was given.
func RecordSeal(args ...object.Object) object.Object {
	return recordSealImpl(BuiltinNameRecordSeal, args, false)
}

// RecordSealQuantised seals with span boundaries rounded OUTWARD to a quantum.
//
// The reason is in docs/DISCLOSURE_POLICY.md: a withheld span advertises its
// own length, and there are four-byte secrets. Rounding outward hides a short
// one inside a larger span -- and costs exactly what it hides, because the
// record then withholds more than the classification called for. How much more
// is recorded in the header and reported here, because a recipient is entitled
// to know that some of what they cannot read was never classified.
func RecordSealQuantised(args ...object.Object) object.Object {
	return recordSealImpl(BuiltinNameRecordSealQuantised, args, true)
}

func recordSealImpl(op string, args []object.Object, quantised bool) object.Object {
	// Four and never three. The options hash is not optional because `default`
	// is not optional: every byte of a record carries a classification, and the
	// one that covers what no range names has to be chosen by the examiner
	// rather than by this file.
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	source, errObj := requireStringArg(op, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	dest, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ranges, errObj := recordRangesArg(op, args[2])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	allowed := recordSealOptions
	if quantised {
		allowed = recordSealQuantisedOptions
	}
	opts, errObj := formatOptionsArg(op, args, 4, allowed...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	defaultLabel, errObj := opts.str(recordDefaultOption, "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(defaultLabel) == "" {
		return resultAndError(nil, newError("%s: option %q is required and names the class every byte no "+
			"declared range covers will carry. There is no implicit unclassified: a record with an "+
			"unlabelled remainder discloses that remainder to everyone who is disclosed anything",
			op, recordDefaultOption))
	}
	defaultClass, errObj := recordLookupClass(op, defaultLabel)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	sign, errObj := opts.boolean(recordSignOption, true)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	sourceNote, errObj := opts.str(recordSourceOption, "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	segmentSize, errObj := recordSizeOption(op, opts, recordSegmentOption,
		uint64(security.DefaultSegmentSize), 1, security.MaxSegmentPlaintext)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	var quantum uint64
	var roundsTo caseClass
	if quantised {
		quantum, errObj = recordSizeOption(op, opts, recordQuantumOption, 0, 1, security.MaxSegmentPlaintext)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		if quantum == 0 {
			return resultAndError(nil, newError("%s: option %q is required and is the unit span boundaries "+
				"are rounded outward to. Use `%s` for a record sealed at the boundaries you gave",
				op, recordQuantumOption, BuiltinNameRecordSeal))
		}
		// Required for the same reason `default` is: rounding moves bytes
		// between classes, and there is no implicit answer to which class they
		// should land in. Naming it is what makes the examiner look at the
		// direction, because the tool cannot -- a class is a label and a tag,
		// and nothing here orders one above another.
		roundsToLabel, errObj := opts.str(recordRoundsToOption, "")
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		if strings.TrimSpace(roundsToLabel) == "" {
			return resultAndError(nil, newError("%s: option %q is required and names the one class rounding "+
				"may grow. A range that is widened takes the bytes it grows over out of %q and into its own "+
				"class, which withholds more only if its class is the more sensitive of the two -- and "+
				"nothing here knows which that is. Name the class you are rounding, or use `%s` to seal at "+
				"the boundaries you gave",
				op, recordRoundsToOption, defaultLabel, BuiltinNameRecordSeal))
		}
		roundsTo, errObj = recordLookupClass(op, roundsToLabel)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
	}

	identity, errObj := recordCaseIdentity(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	info, err := os.Stat(source)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	if info.IsDir() {
		return resultAndError(nil, newError("%s: %s is a directory", op, source))
	}
	total := uint64(info.Size())
	if total == 0 {
		return resultAndError(nil, newError("%s: %s is empty. Sealing nothing protects nothing -- a record's "+
			"length is public by construction -- and an empty record cannot carry a classification",
			op, source))
	}

	spans, extra, errObj := recordAssembleSpans(op, ranges, total, defaultClass, quantum, roundsTo)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	header, segments, keys, errObj := recordBuildHeader(op, identity, spans, total,
		uint32(segmentSize), uint32(quantum), extra, roundsTo.Tag, sourceNote)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	defer keys.Zero()

	footer, written, errObj := recordWriteFile(op, source, dest, header, segments, keys, sign)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyRecordArtifact(op,
		fmt.Sprintf("sealed %s into record %s (%d segments over %d spans)",
			source, dest, len(segments), len(spans)),
		map[string]any{
			"record_uid":       header.RecordUID,
			"source":           source,
			"record":           dest,
			"segments":         int64(len(segments)),
			"spans":            int64(len(spans)),
			"plaintext_length": int64(total),
			"signed":           footer.Signed,
			"quantum":          int64(quantum),
			"quantised_extra":  int64(extra),
			"rounds_to":        roundsTo.Label,
		})

	result := map[string]object.Object{
		"record_uid":       stringObj(header.RecordUID),
		"path":             stringObj(dest),
		"case_uid":         stringObj(header.CaseUID),
		"case_key_id":      stringObj(header.CaseKeyID),
		"generation":       intObj(int64(header.SealedUnderGeneration)),
		"plaintext_length": intObj(int64(total)),
		"file_length":      intObj(int64(written)),
		"segments":         intObj(int64(len(segments))),
		"segment_size":     intObj(int64(segmentSize)),
		"spans":            recordSpanRows(spans),
		"signed":           boolObj(footer.Signed),
		"segments_root":    stringObj(footer.SegmentsRoot),
		"public_key":       stringObj(footer.PublicKey),
		// A signature under a key born seconds before the evidence it vouches
		// for is not the same thing as one under a key an organisation holds.
		"key_created_for_this_run": boolObj(footer.KeyCreatedForThisRun),
		"quantum":                  intObj(int64(quantum)),
		// How many bytes rounding moved out of the default class and into the
		// class named by rounds_to. NOT "how many bytes were withheld": whether
		// moving them withholds or releases depends on which of the two classes
		// is the more sensitive, and nothing in this tree orders classes. The
		// field says what happened; what it means is the examiner's to read.
		// Zero for record_seal, and reported anyway so one field answers the
		// question for both builtins.
		"quantised_extra": intObj(int64(extra)),
		"rounds_to":       stringObj(roundsTo.Label),
	}
	return resultAndError(makeHashObject(result), nil)
}

// recordCaseIdentity reads what a record needs from the open case, under one
// lock, and refuses early if no key is open.
type recordIdentity struct {
	caseUID    string
	caseKeyID  string
	generation uint32
	caseKey    []byte
	examiner   string
}

func recordCaseIdentity(op string) (recordIdentity, *object.Error) {
	custodyStore.RLock()
	defer custodyStore.RUnlock()
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return recordIdentity{}, errObj
	}
	if session.caseKey == nil {
		return recordIdentity{}, newError("%s: no case key is open; call `case_key_open(path)` first. A "+
			"record's key is wrapped under the case key, and without one there is nothing to wrap it to", op)
	}
	if _, err := hex.DecodeString(session.caseUID); err != nil || len(session.caseUID) != security.CaseUIDSize*2 {
		return recordIdentity{}, newError("%s: the open case key does not carry a usable case uid", op)
	}
	// The case key is copied rather than referenced: case_close zeroes the
	// session's copy, and a record seal that outlived a close would otherwise be
	// wrapping to a buffer being cleared underneath it.
	caseKey := make([]byte, len(session.caseKey))
	copy(caseKey, session.caseKey)
	return recordIdentity{
		caseUID:    session.caseUID,
		caseKeyID:  custodyKeyID(session.keyFingerprint),
		generation: session.keyGeneration,
		caseKey:    caseKey,
		examiner:   session.Examiner,
	}, nil
}

// recordRange is one entry of the array record_seal is given.
type recordRange struct {
	offset uint64
	length uint64
	label  string
	tag    string
}

func recordRangesArg(op string, arg object.Object) ([]recordRange, *object.Error) {
	array, errObj := requireArrayArg(op, arg, 3)
	if errObj != nil {
		return nil, errObj
	}
	if len(array.Elements) > recordMaxRangesInArg {
		return nil, newError("%s: %d classification ranges is more than the %d a record may carry. A span "+
			"list is read by a person deciding whether a disclosure is fair",
			op, len(array.Elements), recordMaxRangesInArg)
	}
	ranges := make([]recordRange, 0, len(array.Elements))
	for i, element := range array.Elements {
		hash, ok := element.(*object.Hash)
		if !ok {
			return nil, newError("%s: range %d is %s, and every range must be the HASH that `%s` returns",
				op, i+1, element.Type(), BuiltinNameRecordClassifyRange)
		}
		entry := recordRange{}
		for _, field := range []struct {
			name string
			into *uint64
		}{{"offset", &entry.offset}, {"length", &entry.length}} {
			value, present := hashValue(hash, field.name)
			if !present {
				return nil, recordRangeShapeError(op, i, field.name)
			}
			number, ok := value.(*object.Integer)
			if !ok || number.Value < 0 {
				return nil, newError("%s: range %d has a %s that is not a whole number of bytes",
					op, i+1, field.name)
			}
			*field.into = uint64(number.Value)
		}
		for _, field := range []struct {
			name string
			into *string
		}{{"label", &entry.label}, {"class", &entry.tag}} {
			value, present := hashValue(hash, field.name)
			if !present {
				return nil, recordRangeShapeError(op, i, field.name)
			}
			text, ok := value.(*object.String)
			if !ok {
				return nil, newError("%s: range %d has a %s that is not a STRING", op, i+1, field.name)
			}
			*field.into = text.Value
		}
		if entry.length == 0 {
			return nil, newError("%s: range %d covers no bytes", op, i+1)
		}
		ranges = append(ranges, entry)
	}
	return ranges, nil
}

func recordRangeShapeError(op string, index int, field string) *object.Error {
	return newError("%s: range %d has no %q. Build ranges with `%s(offset, length, label)` rather than "+
		"writing the hash by hand, so that a label is resolved to its tag at the line that named it",
		op, index+1, field, BuiltinNameRecordClassifyRange)
}

// recordAssembleSpans turns the declared ranges into a partition of the whole
// plaintext, and reports how many bytes quantisation withheld beyond them.
//
// The order is deliberate: sort, refuse overlaps as GIVEN, then quantise, then
// refuse overlaps the rounding created. Checking only once, after rounding,
// would report a conflict the program did not write; checking only before would
// let the rounding silently merge two classes.
func recordAssembleSpans(op string, ranges []recordRange, total uint64, def caseClass, quantum uint64,
	roundsTo caseClass) (
	[]security.RecordSpan, uint64, *object.Error,
) {
	sorted := append([]recordRange(nil), ranges...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].offset < sorted[j].offset })

	var classified uint64
	for i, entry := range sorted {
		end := entry.offset + entry.length
		if end < entry.offset || end > total {
			return nil, 0, newError("%s: the range at %d+%d runs past the %d bytes of the source",
				op, entry.offset, entry.length, total)
		}
		if i > 0 {
			previous := sorted[i-1]
			if entry.offset < previous.offset+previous.length {
				return nil, 0, newError("%s: the range at %d+%d overlaps the range at %d+%d. Which label "+
					"wins where two ranges disagree is a legal question, not one this tool may answer "+
					"for you", op, entry.offset, entry.length, previous.offset, previous.length)
			}
		}
		classified += entry.length
	}

	if quantum > 0 {
		for i := range sorted {
			start := sorted[i].offset - sorted[i].offset%quantum
			end := sorted[i].offset + sorted[i].length
			if remainder := end % quantum; remainder != 0 {
				end += quantum - remainder
			}
			if end > total {
				end = total
			}
			// Widening a span means the bytes it grows over stop carrying the
			// default class and start carrying this one. That is the same
			// reclassification this function refuses to perform a few lines
			// below when it would merge two NAMED classes -- the default is a
			// class the examiner declared too, and rounding was quietly
			// merging into it on every call.
			//
			// Which direction that moves a byte in is not knowable here: a
			// class is a label and a tag and nothing orders them, so "wider
			// means more withheld" is true when the rounded class is the
			// sensitive one and false when it is the released one. With
			// default `restricted` and a four-byte `open` passage, rounding to
			// 16 hands out twelve bytes nobody cleared. So the examiner names
			// the class rounding may grow, and a span of any other class is
			// sealed at the boundary they gave it.
			if start != sorted[i].offset || end != sorted[i].offset+sorted[i].length {
				if sorted[i].tag != roundsTo.Tag {
					return nil, 0, newError("%s: rounding to %d bytes would widen the range at %d+%d, which "+
						"carries %q, and option %q names %q as the one class rounding may grow. Widening a "+
						"range moves every byte it grows over into that range's class, and whether that "+
						"withholds those bytes or releases them depends on which class is the more "+
						"sensitive -- which nothing here knows, because a class is a label and a tag and "+
						"nothing orders them. Seal this range at the boundary you gave it, or name %q in %q",
						op, quantum, sorted[i].offset, sorted[i].length, sorted[i].label,
						recordRoundsToOption, roundsTo.Label, sorted[i].label, recordRoundsToOption)
				}
			}
			sorted[i].offset, sorted[i].length = start, end-start
		}
		for i := 1; i < len(sorted); i++ {
			previous, entry := sorted[i-1], sorted[i]
			if entry.offset >= previous.offset+previous.length {
				continue
			}
			if previous.tag != entry.tag {
				return nil, 0, newError("%s: rounding to %d bytes makes the range at %d carry both %q and "+
					"%q, and merging two classifications is a legal decision. Use a smaller quantum, or "+
					"separate the ranges", op, quantum, entry.offset, previous.label, entry.label)
			}
			// Same class either side: the rounding merely joined one span to the
			// next, which changes nothing about what is withheld.
			merged := previous
			if end := entry.offset + entry.length; end > previous.offset+previous.length {
				merged.length = end - previous.offset
			}
			sorted[i-1] = merged
			sorted = append(sorted[:i], sorted[i+1:]...)
			i--
		}
	}

	spans := make([]security.RecordSpan, 0, len(sorted)*2+1)
	appendSpan := func(offset, length uint64, tag string) {
		if length == 0 {
			return
		}
		// Adjacent spans of one class are one span. Two rows that say the same
		// thing about touching bytes are noise in a document a person reads.
		if n := len(spans); n > 0 && spans[n-1].Class == tag && spans[n-1].Offset+spans[n-1].Length == offset {
			spans[n-1].Length += length
			return
		}
		spans = append(spans, security.RecordSpan{Offset: offset, Length: length, Class: tag})
	}

	var cursor, covered uint64
	for _, entry := range sorted {
		appendSpan(cursor, entry.offset-cursor, def.Tag)
		appendSpan(entry.offset, entry.length, entry.tag)
		covered += entry.length
		cursor = entry.offset + entry.length
	}
	appendSpan(cursor, total-cursor, def.Tag)

	var extra uint64
	if covered > classified {
		extra = covered - classified
	}
	return spans, extra, nil
}

func recordSpanRows(spans []security.RecordSpan) *object.Array {
	elements := make([]object.Object, 0, len(spans))
	for _, span := range spans {
		elements = append(elements, makeHashObject(map[string]object.Object{
			"offset": intObj(int64(span.Offset)),
			"length": intObj(int64(span.Length)),
			"class":  stringObj(span.Class),
		}))
	}
	return &object.Array{Elements: elements}
}

func recordSizeOption(op string, opts *formatOptions, key string, def, low, high uint64) (uint64, *object.Error) {
	value, present := opts.pairs[key]
	if !present {
		return def, nil
	}
	number, ok := value.(*object.Integer)
	if !ok {
		return 0, newError("%s: option %q must be INTEGER, got %s", op, key, value.Type())
	}
	if number.Value < int64(low) || uint64(number.Value) > high {
		return 0, newError("%s: option %q is %d and must be between %d and %d",
			op, key, number.Value, low, high)
	}
	return uint64(number.Value), nil
}

// recordBuildHeader mints the record's key schedule and the header that
// describes it. The returned handle can seal and the caller must zero it.
func recordBuildHeader(op string, identity recordIdentity, spans []security.RecordSpan, total uint64,
	segmentSize, quantum uint32, extra uint64, roundsTo, sourceNote string) (
	*security.RecordHeader, []security.RecordSegment, *security.RecordKeys, *object.Error,
) {
	defer security.SecureZero(identity.caseKey)

	caseUID, err := hex.DecodeString(identity.caseUID)
	if err != nil {
		return nil, nil, nil, newError("%s: the open case key does not carry a usable case uid", op)
	}
	caseID, err := security.CaseUIDFromSlice(caseUID)
	if err != nil {
		return nil, nil, nil, newError("%s: %s", op, err.Error())
	}
	recordUID, err := security.RandomRecordUID()
	if err != nil {
		return nil, nil, nil, newError("%s: %s", op, err.Error())
	}

	header := &security.RecordHeader{
		Format:                 security.RecordFileFormat,
		Version:                security.RecordFileVersion,
		RecordUID:              hex.EncodeToString(recordUID[:]),
		CaseUID:                identity.caseUID,
		CaseKeyID:              identity.caseKeyID,
		SealedUnderGeneration:  identity.generation,
		WrappedUnderGeneration: identity.generation,
		PlaintextLength:        total,
		SegmentSize:            segmentSize,
		Quantum:                quantum,
		QuantisedExtra:         extra,
		RoundsTo:               roundsTo,
		Created:                custodyNow().UTC().Format(time.RFC3339Nano),
		Examiner:               identity.examiner,
		Source:                 sourceNote,
		Spans:                  spans,
	}
	segments, err := header.Segments()
	if err != nil {
		return nil, nil, nil, newError("%s: %s", op, err.Error())
	}

	keys, recordKey, sealSalt, err := security.NewRecordKeysForSeal(caseID, recordUID,
		identity.generation, uint64(len(segments)))
	if err != nil {
		return nil, nil, nil, newError("%s: %s", op, err.Error())
	}
	defer security.SecureZero(recordKey)

	nonce, wrapped, err := security.WrapRecordKey(identity.caseKey, recordUID, recordKey)
	if err != nil {
		keys.Zero()
		return nil, nil, nil, newError("%s: %s", op, err.Error())
	}
	header.RecordKeyNonce = hex.EncodeToString(nonce[:])
	header.RecordKeyWrapped = hex.EncodeToString(wrapped)
	header.SealSalt = hex.EncodeToString(sealSalt)
	return header, segments, keys, nil
}

// recordWriteFile streams the source through the seal and lays the record down.
//
// One pass over the source. The whole-plaintext digest goes in the FOOTER, not
// the header, precisely so that this can be one pass -- a digest in the header
// would have to be known before the first segment was written.
//
// The destination is created with O_EXCL. Overwriting is not offered: the
// lesson is next door in case_key.go, where a builtin that would have
// overwritten a private key was the defect that made the rule.
func recordWriteFile(op, source, dest string, header *security.RecordHeader,
	segments []security.RecordSegment, keys *security.RecordKeys, sign bool) (
	*security.RecordFooter, uint64, *object.Error,
) {
	in, err := os.Open(source)
	if err != nil {
		return nil, 0, newError("%s: %s", op, err.Error())
	}
	defer in.Close()

	if directory := filepath.Dir(dest); directory != "" {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, 0, newError("%s: %s", op, err.Error())
		}
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, 0, newError("%s: %s already exists. A record is never written over: if this is a "+
				"re-seal, the record it would replace is the only copy of what it held", op, dest)
		}
		return nil, 0, newError("%s: %s", op, err.Error())
	}
	// Anything that goes wrong from here leaves no half-written record behind.
	// A file that looks like evidence and is not is worse than no file.
	abandon := func(format string, args ...any) *object.Error {
		out.Close()
		_ = os.Remove(dest)
		return newError(format, args...)
	}

	headerBytes, err := security.MarshalRecordHeader(header)
	if err != nil {
		return nil, 0, abandon("%s: %s", op, err.Error())
	}
	var written uint64
	write := func(b []byte) error {
		n, err := out.Write(b)
		written += uint64(n)
		return err
	}
	if err := write(security.RecordFilePrefix(len(headerBytes))); err != nil {
		return nil, 0, abandon("%s: %s", op, err.Error())
	}
	if err := write(headerBytes); err != nil {
		return nil, 0, abandon("%s: %s", op, err.Error())
	}

	plaintextDigest := sha256.New()
	digests := make([][sha256.Size]byte, 0, len(segments))
	buffer := make([]byte, header.SegmentSize)
	// Deferred rather than called after the loop: every `abandon` below is a
	// return out of the middle of this function with a segment of evidence
	// plaintext still sitting in the buffer. Zeroing only on the happy path
	// means the one case where plaintext is left in a discarded buffer is the
	// case where something already went wrong.
	defer security.SecureZero(buffer)
	for _, segment := range segments {
		chunk := buffer[:segment.Length]
		if _, err := io.ReadFull(in, chunk); err != nil {
			return nil, 0, abandon("%s: reading %s at %d: %s", op, source, segment.Offset, err.Error())
		}
		plaintextDigest.Write(chunk)
		aad, err := header.SegmentAAD(segment, uint64(len(segments)))
		if err != nil {
			return nil, 0, abandon("%s: %s", op, err.Error())
		}
		ciphertext, digest, err := keys.SealSegment(aad, chunk)
		if err != nil {
			return nil, 0, abandon("%s: segment %d: %s", op, segment.Index, err.Error())
		}
		if err := write(ciphertext); err != nil {
			return nil, 0, abandon("%s: %s", op, err.Error())
		}
		digests = append(digests, digest)
	}
	if !keys.SealComplete() {
		return nil, 0, abandon("%s: the record sealed %d of its %d segments", op,
			keys.SealedCount(), keys.Total())
	}

	meta, err := json.Marshal(security.RecordMeta{
		PlaintextSHA256: hex.EncodeToString(plaintextDigest.Sum(nil)),
	})
	if err != nil {
		return nil, 0, abandon("%s: %s", op, err.Error())
	}
	nonce, blob, err := keys.SealMeta(meta)
	if err != nil {
		return nil, 0, abandon("%s: %s", op, err.Error())
	}
	footer := &security.RecordFooter{SealedMeta: security.RecordSealedBlock{
		Nonce: hex.EncodeToString(nonce[:]),
		Blob:  hex.EncodeToString(blob),
	}}
	if err := security.SignRecordFooter(footer, headerBytes, security.SegmentsRoot(digests), sign); err != nil {
		return nil, 0, abandon("%s: %s", op, err.Error())
	}
	footerBytes, err := security.MarshalRecordFooter(footer)
	if err != nil {
		return nil, 0, abandon("%s: %s", op, err.Error())
	}
	if err := write(security.RecordFooterPrefix(len(footerBytes))); err != nil {
		return nil, 0, abandon("%s: %s", op, err.Error())
	}
	if err := write(footerBytes); err != nil {
		return nil, 0, abandon("%s: %s", op, err.Error())
	}
	if err := out.Sync(); err != nil {
		return nil, 0, abandon("%s: %s", op, err.Error())
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dest)
		return nil, 0, newError("%s: %s", op, err.Error())
	}
	return footer, written, nil
}

// ---------------------------------------------------------------------------
// Reading a record back
// ---------------------------------------------------------------------------

// recordLoad reads and checks everything about a record that needs no key.
//
// The file stays open and is returned, because record_open holds it for the
// life of the handle. A caller that only wanted to look -- record_verify --
// closes it itself.
func recordLoad(op, path string) (*recordSession, *object.Error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, newError("%s: %s", op, err.Error())
	}
	fail := func(format string, args ...any) *object.Error {
		file.Close()
		return newError(format, args...)
	}
	info, err := file.Stat()
	if err != nil {
		return nil, fail("%s: %s", op, err.Error())
	}
	size := uint64(info.Size())

	prefix := make([]byte, security.RecordFilePrefixSize)
	if _, err := file.ReadAt(prefix, 0); err != nil {
		return nil, fail("%s: %s is too short to be a record", op, path)
	}
	headerLength, err := security.ParseRecordFilePrefix(prefix)
	if err != nil {
		return nil, fail("%s: %s", op, err.Error())
	}
	headerRaw := make([]byte, headerLength)
	if _, err := file.ReadAt(headerRaw, int64(security.RecordFilePrefixSize)); err != nil {
		return nil, fail("%s: %s declares a %d-byte header it does not contain", op, path, headerLength)
	}
	header, err := security.ParseRecordHeader(headerRaw)
	if err != nil {
		return nil, fail("%s: %s", op, err.Error())
	}
	// Checked before the segment table is built, not after. A record's segment
	// data is its plaintext plus a tag per segment, so a file can never hold
	// more plaintext than it has bytes -- and the table costs one row per
	// segment, which is a number this header chose. Doing the cheap
	// impossibility check first is what stops a hand-written header being a way
	// to spend an examiner's memory on a file that is a few hundred bytes long.
	if header.PlaintextLength > size {
		return nil, fail("%s: %s says it holds %d bytes of plaintext and the whole file is %d bytes",
			op, path, header.PlaintextLength, size)
	}
	segments, err := header.Segments()
	if err != nil {
		return nil, fail("%s: %s", op, err.Error())
	}

	dataOffset := uint64(security.RecordFilePrefixSize + headerLength)
	dataSize := header.StoredDataSize(segments)
	footerPrefixAt := dataOffset + dataSize
	if size < footerPrefixAt+uint64(security.RecordFooterPrefixSize) {
		return nil, fail("%s: %s describes %d bytes of segment data and is only %d bytes long",
			op, path, dataSize, size)
	}
	footerPrefix := make([]byte, security.RecordFooterPrefixSize)
	if _, err := file.ReadAt(footerPrefix, int64(footerPrefixAt)); err != nil {
		return nil, fail("%s: %s", op, err.Error())
	}
	footerLength, err := security.ParseRecordFooterPrefix(footerPrefix)
	if err != nil {
		return nil, fail("%s: %s", op, err.Error())
	}
	// Checked exactly, not as a lower bound. Trailing bytes after a record are
	// bytes somebody added, and a reader that ignored them would be reading a
	// different file from the one the signature covers.
	want := footerPrefixAt + uint64(security.RecordFooterPrefixSize) + uint64(footerLength)
	if size != want {
		return nil, fail("%s: %s should be %d bytes by its own description and is %d", op, path, want, size)
	}
	footerRaw := make([]byte, footerLength)
	if _, err := file.ReadAt(footerRaw, int64(footerPrefixAt+uint64(security.RecordFooterPrefixSize))); err != nil {
		return nil, fail("%s: %s", op, err.Error())
	}
	footer, err := security.ParseRecordFooter(footerRaw)
	if err != nil {
		return nil, fail("%s: %s", op, err.Error())
	}

	session := &recordSession{
		path:       path,
		file:       file,
		header:     header,
		headerRaw:  headerRaw,
		footer:     footer,
		segments:   segments,
		dataOffset: dataOffset,
		openedAt:   custodyNow(),
	}
	root, errObj := recordRecomputeRoot(op, session)
	if errObj != nil {
		file.Close()
		return nil, errObj
	}
	session.signed, session.signatureValid, session.signatureNote =
		security.VerifyRecordSignature(footer, headerRaw, root)
	return session, nil
}

// recordRecomputeRoot folds the record's segment digests from the stored
// ciphertext. It uses no key: this is what a recipient granted nothing can do.
func recordRecomputeRoot(op string, session *recordSession) ([sha256.Size]byte, *object.Error) {
	var root [sha256.Size]byte
	digests := make([][sha256.Size]byte, 0, len(session.segments))
	buffer := make([]byte, 0, session.header.SegmentSize+64)
	for _, segment := range session.segments {
		if uint64(cap(buffer)) < segment.StoredLength {
			buffer = make([]byte, segment.StoredLength)
		}
		chunk := buffer[:segment.StoredLength]
		if _, err := session.file.ReadAt(chunk, int64(session.dataOffset+segment.StoredOffset)); err != nil {
			return root, newError("%s: reading segment %d: %s", op, segment.Index, err.Error())
		}
		aad, err := session.header.SegmentAAD(segment, uint64(len(session.segments)))
		if err != nil {
			return root, newError("%s: %s", op, err.Error())
		}
		digests = append(digests, security.SegmentDigest(aad, chunk))
	}
	return security.SegmentsRoot(digests), nil
}

// RecordVerify checks a record holding no key at all.
//
// This is the property the format is arranged around: a recipient who was
// granted nothing can still establish that the file they hold is the file that
// was sealed. What it does NOT establish is who sealed it -- see the
// `does_not_prove` field, which is not decoration.
func RecordVerify(args ...object.Object) object.Object {
	op := BuiltinNameRecordVerify
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg(op, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	session, errObj := recordLoad(op, path)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	defer session.file.Close()

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":             stringObj(path),
		"record_uid":       stringObj(session.header.RecordUID),
		"case_uid":         stringObj(session.header.CaseUID),
		"case_key_id":      stringObj(session.header.CaseKeyID),
		"generation":       intObj(int64(session.header.SealedUnderGeneration)),
		"plaintext_length": intObj(int64(session.header.PlaintextLength)),
		"segments":         intObj(int64(len(session.segments))),
		"spans":            recordSpanRows(session.header.Spans),
		"examiner":         stringObj(session.header.Examiner),
		"created":          stringObj(session.header.Created),
		"quantum":          intObj(int64(session.header.Quantum)),
		"quantised_extra":  intObj(int64(session.header.QuantisedExtra)),
		// The class rounding grew, as a tag. Reported beside the count because
		// the count alone does not say which way the bytes went, and "12 bytes
		// moved" reads as "12 more bytes withheld" to anyone who does not know
		// that nothing here orders one class above another.
		"rounds_to": stringObj(session.header.RoundsTo),
		// Two bits and never one: an unsigned record is not a forged one.
		"signed":                   boolObj(session.signed),
		"signature_valid":          boolObj(session.signatureValid),
		"signature_note":           stringObj(session.signatureNote),
		"public_key":               stringObj(session.footer.PublicKey),
		"key_created_for_this_run": boolObj(session.footer.KeyCreatedForThisRun),
		"segments_root":            stringObj(session.footer.SegmentsRoot),
		"verified_without_key":     boolObj(true),
		"does_not_prove": stringArrayObj([]string{
			"who sealed it: the signature authenticates the document, not the names in it",
			"that the classification applied to any span was correct",
			"that this record is all the evidence there is",
			"that the plaintext is what it claims to be, which needs the case key",
		}),
	}), nil)
}

// ---------------------------------------------------------------------------
// record_open, record_layout, record_close
// ---------------------------------------------------------------------------

// recordOpenOptions is the whole option surface of record_open.
var recordOpenOptions = []string{"grant"}

// RecordOpen opens a record for reading and returns a handle.
//
// Under the case key by default. With `{"grant": path}` it opens under a
// disclosure grant instead -- the recipient's side of a disclosure -- which
// needs no case and no case key, and opens exactly the segments the grant
// carries material for.
func RecordOpen(args ...object.Object) object.Object {
	op := BuiltinNameRecordOpen
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	path, errObj := requireStringArg(op, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	opts, errObj := formatOptionsArg(op, args, 2, recordOpenOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	grantPath, errObj := opts.str("grant", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if _, given := opts.pairs["grant"]; given {
		if strings.TrimSpace(grantPath) == "" {
			return resultAndError(nil, newError("%s: the grant path must not be empty", op))
		}
		return recordOpenUnderGrant(op, path, grantPath)
	}
	identity, errObj := recordCaseIdentity(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	defer security.SecureZero(identity.caseKey)

	session, errObj := recordLoad(op, path)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	fail := func(format string, args ...any) object.Object {
		session.file.Close()
		return resultAndError(nil, newError(format, args...))
	}
	if !strings.EqualFold(session.header.CaseUID, identity.caseUID) {
		return fail("%s: %s belongs to case %s and the open case is %s. A record's segments are bound to "+
			"the case that sealed them, so this key cannot open it and could not have sealed it",
			op, path, session.header.CaseUID[:16], identity.caseUID[:16])
	}

	recordUID, err := security.RecordUIDFromSlice(mustHexBytes(session.header.RecordUID))
	if err != nil {
		return fail("%s: %s", op, err.Error())
	}
	nonceBytes := mustHexBytes(session.header.RecordKeyNonce)
	nonce, err := security.XNonceFromSlice(nonceBytes)
	if err != nil {
		return fail("%s: the record's wrapping nonce is not %d bytes", op, len(nonceBytes))
	}
	recordKey, err := security.UnwrapRecordKey(identity.caseKey, recordUID, nonce,
		mustHexBytes(session.header.RecordKeyWrapped))
	if err != nil {
		return fail("%s: this case key does not open %s. The record names generation %d and the open key "+
			"is generation %d; if those differ, open the key at the generation the record was sealed under",
			op, path, session.header.WrappedUnderGeneration, identity.generation)
	}
	defer security.SecureZero(recordKey)

	caseID, err := security.CaseUIDFromSlice(mustHexBytes(session.header.CaseUID))
	if err != nil {
		return fail("%s: %s", op, err.Error())
	}
	// OpenRecordKeys and never NewRecordKeysForSeal: the handle this returns
	// can open and cannot seal, so nothing reachable from a program can re-seal
	// a position and put two plaintexts under one keystream.
	keys, err := security.OpenRecordKeys(caseID, recordUID, session.header.SealedUnderGeneration,
		uint64(len(session.segments)), recordKey, mustHexBytes(session.header.SealSalt))
	if err != nil {
		return fail("%s: %s", op, err.Error())
	}
	session.keys = keys
	return recordRegister(op, path, session, len(session.segments))
}

// recordRegister stores an opened record under a new handle, records it, and
// renders what record_open returns -- one shape for both kinds of opening, so
// a program reads `opened_with` rather than guessing from which fields exist.
func recordRegister(op, path string, session *recordSession, granted int) object.Object {
	handle := atomic.AddInt64(&recordHandleCounter, 1)
	recordHandles.Store(handle, session)

	custodyRecordArtifact(op, fmt.Sprintf("opened record %s (%d segments, under a %s)",
		path, len(session.segments), strings.ReplaceAll(session.openedWith(), "_", " ")),
		map[string]any{
			"record_uid":       session.header.RecordUID,
			"path":             path,
			"segments":         int64(len(session.segments)),
			"signed":           session.signed,
			"signature_valid":  session.signatureValid,
			"opened_with":      session.openedWith(),
			"granted_segments": int64(granted),
			"disclosure_uid":   session.disclosureUID,
		})

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle":                   intObj(handle),
		"path":                     stringObj(path),
		"record_uid":               stringObj(session.header.RecordUID),
		"case_uid":                 stringObj(session.header.CaseUID),
		"generation":               intObj(int64(session.header.SealedUnderGeneration)),
		"plaintext_length":         intObj(int64(session.header.PlaintextLength)),
		"segments":                 intObj(int64(len(session.segments))),
		"segment_size":             intObj(int64(session.header.SegmentSize)),
		"signed":                   boolObj(session.signed),
		"signature_valid":          boolObj(session.signatureValid),
		"signature_note":           stringObj(session.signatureNote),
		"key_created_for_this_run": boolObj(session.footer.KeyCreatedForThisRun),
		// What the segments open under, and how many of them that is. Under
		// the case key it is all of them; under a grant it is the ones the
		// grant carries, and a read that touches any other is refused by
		// record_read and reported as a hole by record_read_partial.
		"opened_with":      stringObj(session.openedWith()),
		"granted_segments": intObj(int64(granted)),
		"disclosure_uid":   stringObj(session.disclosureUID),
	}), nil)
}

// recordOpenUnderGrant is the recipient's side of a disclosure.
//
// Everything that needs no passphrase is checked first: that the grant file is
// one, that the record is one, and that the grant names this record -- its
// uid, its case, the generation it was sealed under and its segment count. A
// grant for another record is refused by name before the examiner is asked
// for anything, because a passphrase typed for the wrong file is a passphrase
// typed for nothing.
//
// Then the grant is opened and checked against the header once more, this
// time over every granted segment's full descriptor. A header that describes a
// granted segment differently from the one the grant was issued against is
// refused as that, here, rather than surfacing later as segments that do not
// open.
func recordOpenUnderGrant(op, path, grantPath string) object.Object {
	file, errObj := disclosureReadGrantFile(op, grantPath)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	session, errObj := recordLoad(op, path)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	fail := func(errObj *object.Error) object.Object {
		session.file.Close()
		return resultAndError(nil, errObj)
	}
	if errObj := disclosureGrantNamesRecord(op, file, session); errObj != nil {
		return fail(errObj)
	}

	request := security.PassphraseRequest{Purpose: op, Path: grantPath, Confirm: false}
	passphrase, err := security.RequestPassphrase(request)
	if err != nil {
		return fail(passphraseError(op, err))
	}
	grant, err := security.OpenGrantFile(file, passphrase)
	security.SecureZero(passphrase)
	if err != nil {
		security.ForgetPassphrase(request)
		return fail(newError("%s: %s: %s", op, grantPath, err.Error()))
	}
	if err := grant.MatchesRecord(recordDescriber(session)); err != nil {
		grant.Zero()
		return fail(newError("%s: %s does not describe the segments %s grants: %s",
			op, path, grantPath, err.Error()))
	}
	session.grant = grant
	session.disclosureUID = file.DisclosureUID
	return recordRegister(op, path, session, grant.Count())
}

// recordDescriber returns the descriptor the record's own header gives for a
// segment index, which is what a grant is checked against.
func recordDescriber(session *recordSession) func(uint64) (security.SegmentAAD, error) {
	total := uint64(len(session.segments))
	return func(index uint64) (security.SegmentAAD, error) {
		if index >= total {
			return security.SegmentAAD{}, fmt.Errorf("this record has %d segments and no segment %d", total, index)
		}
		return session.header.SegmentAAD(session.segments[index], total)
	}
}

// RecordLayout reports the record's public structure: what is where, and under
// which class. It needs the handle but reads no plaintext.
func RecordLayout(args ...object.Object) object.Object {
	op := BuiltinNameRecordLayout
	session, errObj := recordHandleArg(op, args, 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	rows := make([]object.Object, 0, len(session.segments))
	for _, segment := range session.segments {
		rows = append(rows, makeHashObject(map[string]object.Object{
			"index":         intObj(int64(segment.Index)),
			"offset":        intObj(int64(segment.Offset)),
			"length":        intObj(int64(segment.Length)),
			"class":         stringObj(hex.EncodeToString(segment.Class[:])),
			"stored_offset": intObj(int64(session.dataOffset + segment.StoredOffset)),
			"stored_length": intObj(int64(segment.StoredLength)),
		}))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"record_uid":       stringObj(session.header.RecordUID),
		"plaintext_length": intObj(int64(session.header.PlaintextLength)),
		"segment_size":     intObj(int64(session.header.SegmentSize)),
		"spans":            recordSpanRows(session.header.Spans),
		"segments":         &object.Array{Elements: rows},
		// Stated here because a reader of a layout is exactly the reader who
		// might otherwise conclude the opposite: the boundaries and the lengths
		// are public by construction, for everyone, with no key.
		"boundaries_are_public": boolObj(true),
	}), nil)
}

// RecordClose releases a record handle.
func RecordClose(args ...object.Object) object.Object {
	op := BuiltinNameRecordClose
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `%s` must be INTEGER, got %s", op, args[0].Type()))
	}
	// Claimed atomically, so two concurrent closes cannot both reach the file.
	value, found := recordHandles.LoadAndDelete(handle.Value)
	if !found {
		return resultAndError(nil, newError("%s: unknown record handle %d", op, handle.Value))
	}
	session, ok := value.(*recordSession)
	if !ok {
		return resultAndError(nil, newError("%s: unknown record handle %d", op, handle.Value))
	}
	session.zero()
	if err := session.file.Close(); err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

func recordGet(handle int64) (*recordSession, bool) {
	value, ok := recordHandles.Load(handle)
	if !ok {
		return nil, false
	}
	session, ok := value.(*recordSession)
	return session, ok
}

// recordHandleArg resolves argument one of every builtin that takes a handle.
//
// The refusal names the family, because the likeliest reason a handle does not
// resolve here is that it came from ledger_open or db_open_disk, and a program
// that mixed them up needs to be told which space it is in.
func recordHandleArg(op string, args []object.Object, want int) (*recordSession, *object.Error) {
	// The exact count and not a lower bound. A builtin that accepts an argument
	// its own signature does not name is a builtin whose documentation is
	// wrong, which the arity conformance probe treats as a failure -- rightly,
	// because the signature is what hover and completion show.
	if len(args) != want {
		return nil, newError("wrong number of arguments. got=%d, want=%d", len(args), want)
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return nil, newError("argument 1 to `%s` must be INTEGER, got %s", op, args[0].Type())
	}
	session, found := recordGet(handle.Value)
	if !found {
		return nil, newError("%s: %d is not an open record handle. Record handles come from `%s` and are "+
			"not ledger or database handles, which are numbered in spaces of their own",
			op, handle.Value, BuiltinNameRecordOpen)
	}
	return session, nil
}

// resetRecordsForTesting drops every open record handle. Mirrors
// resetLedgerForTesting: the map is process-global, so a test that opens a
// record and does not close it would leave a file open on a temp directory the
// test framework is about to remove.
func resetRecordsForTesting() {
	recordHandles.Range(func(key, value any) bool {
		if session, ok := value.(*recordSession); ok {
			session.zero()
			_ = session.file.Close()
		}
		recordHandles.Delete(key)
		return true
	})
}

func mustHexBytes(s string) []byte {
	raw, _ := hex.DecodeString(s)
	return raw
}
