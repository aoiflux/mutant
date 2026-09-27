package builtin

// record_search: finding a literal in a classified record, reading only what
// one reader of it could read.
//
// A search is a read, and the reads in record_read.go already settle what a
// reader may see. This answers the next question: where does this pattern
// occur in what a given reader could see? The reader is named, never assumed.
// A record opened under a grant is searched as its recipient holds it -- the
// segments the grant opens, and no others. A record opened with the case key
// opens everything, so a search of it must name a view, and then reads exactly
// the segments a grant under that view would open: the partition view_preview
// reports and disclose_to_passphrase grants. A segment outside that set is
// never read from the file, let alone decrypted.
//
// Three rules follow from "what that reader could compute", and each is easy
// to break without noticing:
//
//   - A match that would need even one byte the reader cannot read is not
//     reported. The matcher runs over each stretch of contiguous readable
//     segments and starts again after every gap, so nothing it finds spans
//     one; it carries its state across the boundary between two readable
//     segments, which is where a pattern the segmenting happened to split
//     would otherwise be missed.
//   - The context around a hit stops where the readable bytes stop. It is
//     clipped, never zero-filled: a zero in a context is a zero in the record.
//   - The context is plaintext, and carries the mark a read's output carries
//     (builtin/classified.go), so the builtins that send a value out of the
//     process refuse it.
//
// The search is literal. A regular expression over a record read a segment at
// a time either holds unbounded state across segments or silently misses a
// match longer than its window, and a search that misses without saying so is
// worse than one that cannot be asked. Every offset the pattern occurs at is
// reported, overlapping ones included, by a matcher (Knuth-Morris-Pratt) whose
// work is proportional to the bytes it reads whatever the pattern and the
// record hold: a run of zeros searched for a run of zeros costs what any other
// search costs.
//
// A search is written into the open case's timeline -- the record, the view,
// what was found -- and the pattern is not, because a search term is often the
// most sensitive thing about a search. It is written as a digest keyed to the
// case key (security.SearchPatternDigest): a holder of that key can check a
// candidate against it, and nobody else learns anything from it, where a bare
// SHA-256 of a name or a number would confirm every guess made against it.

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"mutant/object"
	"mutant/security"
)

// recordSearchOptions is record_search's whole option surface.
var recordSearchOptions = []string{"view", "max_hits", "context", "ignore_ascii_case"}

const (
	// maxSearchPattern bounds the literal a search looks for. The matcher
	// keeps a table as long as the pattern and every hit's context holds it,
	// so an unbounded pattern is an unbounded allocation per hit; a page is
	// room for any search term.
	//
	//mutant:limit bytes
	maxSearchPattern = 4096

	// defaultSearchContext is how much plaintext a hit hands back on each side
	// of the match unless the search asks otherwise: about a line, which is
	// enough to recognise what was found.
	//
	//mutant:limit bytes
	defaultSearchContext = 32

	// maxSearchContext bounds the context at a page. A context is for
	// recognising a hit; the passage around one is record_read's to return.
	//
	//mutant:limit bytes
	maxSearchContext = 4096

	// defaultSearchHits is how many hits a search hands back unless it asks
	// for more or fewer. Every match is counted whatever this is.
	//
	//mutant:limit count
	defaultSearchHits = 100

	// maxSearchHits bounds the hits one search hands back. It bounds the
	// plaintext a result holds -- up to a context on each side of every hit --
	// and not the count, which covers every match in what was searched.
	//
	//mutant:limit count
	maxSearchHits = 1000
)

// searchPiece is one decrypted segment of the run being searched.
type searchPiece struct {
	index  uint64
	offset uint64
	length uint64
	class  string
}

// searchHit is one match, before it is rendered.
type searchHit struct {
	offset uint64
	// segments are the segments the match's bytes lie in, and classes their
	// classes, each named once in the order met.
	segments []uint64
	classes  []string
	// context is a copy of the readable bytes around the match, beginning at
	// contextOffset; contextClasses are the classes those bytes carry, which
	// is what the context is marked with.
	context        []byte
	contextOffset  uint64
	contextClasses []string
}

// recordSearcher is one search in progress. It sees each readable segment
// once, in order, and holds no more plaintext than a match and its context can
// still need.
type recordSearcher struct {
	session  *recordSession
	readable func(index uint64) bool

	// needle is the pattern, with ASCII capitals folded when the search
	// ignores ASCII case; fail is its Knuth-Morris-Pratt failure table.
	needle []byte
	fail   []int
	fold   bool
	width  uint64
	limit  int

	// The readable run being searched, as far as it has been decrypted: buf
	// holds its plaintext at [start, start+len(buf)), and pieces are the
	// segments those bytes came from. next is the first byte the matcher has
	// not read, and matched how many of the pattern's bytes end just before
	// it.
	inRun   bool
	buf     []byte
	start   uint64
	pieces  []searchPiece
	next    uint64
	matched int

	hits          []searchHit
	count         int64
	searched      int64
	withheld      int64
	searchedBytes uint64
	withheldBytes uint64
	failures      []recordHole
}

func newRecordSearcher(session *recordSession, pattern []byte, fold bool, width uint64, limit int,
	readable func(uint64) bool) *recordSearcher {

	needle := make([]byte, len(pattern))
	copy(needle, pattern)
	if fold {
		for i, c := range needle {
			needle[i] = searchFold(c)
		}
	}
	// fail[i] is the length of the longest proper prefix of needle[:i+1]
	// that is also a suffix of it: how much of a match survives when the
	// byte after it is not the one the pattern needs next.
	fail := make([]int, len(needle))
	for i, k := 1, 0; i < len(needle); i++ {
		for k > 0 && needle[i] != needle[k] {
			k = fail[k-1]
		}
		if needle[i] == needle[k] {
			k++
		}
		fail[i] = k
	}
	return &recordSearcher{session: session, readable: readable, needle: needle, fail: fail, fold: fold,
		width: width, limit: limit}
}

// searchFold lowers an ASCII capital and leaves every other byte as it is. No
// byte of a multi-byte UTF-8 sequence is an ASCII letter, so folding never
// turns one character into another.
func searchFold(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// run searches the record's segments in order. It fails only on a record
// whose own header cannot describe one of them; a segment that cannot be read
// or does not open is a finding, recorded and stepped over.
func (s *recordSearcher) run(op string) *object.Error {
	defer s.release()
	session := s.session
	total := uint64(len(session.segments))
	ciphertext := make([]byte, 0, session.header.SegmentSize+64)
	for _, segment := range session.segments {
		class := hex.EncodeToString(segment.Class[:])
		if !s.readable(segment.Index) {
			// Never read from the file, let alone decrypted: what this reader
			// cannot read, the search does not read either.
			s.withheld++
			s.withheldBytes += uint64(segment.Length)
			s.endRun()
			continue
		}
		failed := func(reason string) {
			s.failures = append(s.failures, recordHole{index: segment.Index, offset: segment.Offset,
				length: uint64(segment.Length), class: class, reason: reason})
			s.endRun()
		}
		if uint64(cap(ciphertext)) < segment.StoredLength {
			ciphertext = make([]byte, segment.StoredLength)
		}
		chunk := ciphertext[:segment.StoredLength]
		if _, err := session.file.ReadAt(chunk, int64(session.dataOffset+segment.StoredOffset)); err != nil {
			failed("the segment's bytes could not be read from the file")
			continue
		}
		aad, err := session.header.SegmentAAD(segment, total)
		if err != nil {
			return newError("%s: %s", op, err.Error())
		}
		plaintext, err := session.openSegment(aad, chunk)
		if err != nil {
			// A segment this reader should be able to open and cannot is not
			// a withheld one, and is not counted as one: it is a finding.
			if session.grant != nil {
				failed("the segment does not open under the material granted for it")
			} else {
				failed("the segment does not open under this record's key")
			}
			continue
		}
		s.searched++
		s.searchedBytes += uint64(len(plaintext))
		s.extend(segment, class, plaintext)
	}
	s.endRun()
	return nil
}

// extend adds one decrypted segment to the run and matches every byte whose
// context after it is now in hand. It zeroes the plaintext it is handed once
// the run holds a copy.
func (s *recordSearcher) extend(segment security.RecordSegment, class string, plaintext []byte) {
	// A run never bridges a gap. The segment table is derived from spans that
	// partition the plaintext, so there is none today -- which is why it is
	// checked rather than assumed, as viewPartition checks it.
	if s.inRun && segment.Offset != s.start+uint64(len(s.buf)) {
		s.endRun()
	}
	// A new run starts with nothing matched: endRun left it so.
	if !s.inRun {
		s.inRun = true
		s.start, s.next = segment.Offset, segment.Offset
	}
	s.buf = searchAppend(s.buf, plaintext)
	s.pieces = append(s.pieces, searchPiece{index: segment.Index, offset: segment.Offset,
		length: uint64(len(plaintext)), class: class})
	security.SecureZero(plaintext)
	// A match ending at byte p has a whole context once the width bytes after
	// p are in hand, so the matcher stops that far short of what is decrypted;
	// the next segment, or the end of the run, lets it finish.
	if end := s.start + uint64(len(s.buf)); end-s.next > s.width {
		s.scan(end - s.width)
	}
	s.trim()
}

// endRun finishes the run being searched: every byte left is matched, with a
// hit's context clipped where the readable bytes stop, and the plaintext is
// zeroed.
func (s *recordSearcher) endRun() {
	if !s.inRun {
		return
	}
	s.scan(s.start + uint64(len(s.buf)))
	security.SecureZero(s.buf)
	s.buf = s.buf[:0]
	s.pieces = s.pieces[:0]
	s.matched = 0
	s.inRun = false
}

// scan runs the matcher over the run's bytes up to limit.
func (s *recordSearcher) scan(limit uint64) {
	for ; s.next < limit; s.next++ {
		c := s.buf[s.next-s.start]
		if s.fold {
			c = searchFold(c)
		}
		for s.matched > 0 && s.needle[s.matched] != c {
			s.matched = s.fail[s.matched-1]
		}
		if s.needle[s.matched] == c {
			s.matched++
		}
		if s.matched == len(s.needle) {
			s.found(s.next+1-uint64(len(s.needle)), s.next+1)
			// Resumed from the longest part of this match that could begin
			// another, so overlapping occurrences are each reported.
			s.matched = s.fail[s.matched-1]
		}
	}
}

// found counts a match at [start, end) and, while the result has room, keeps
// it with its context.
func (s *recordSearcher) found(start, end uint64) {
	s.count++
	if len(s.hits) >= s.limit {
		return
	}
	// Clipped to the run and never padded. A byte the reader cannot read is
	// not in the run, and a zero standing in for one would be a zero the
	// record does not hold. trim keeps every byte of the run within width of
	// any match still to be found, so the buffer's start is the run's own
	// start whenever it is nearer than that.
	from, to := s.start, s.start+uint64(len(s.buf))
	if start-from > s.width {
		from = start - s.width
	}
	if to-end > s.width {
		to = end + s.width
	}
	hit := searchHit{offset: start, contextOffset: from, context: make([]byte, to-from)}
	copy(hit.context, s.buf[from-s.start:to-s.start])
	for _, piece := range s.pieces {
		if piece.offset < end && piece.offset+piece.length > start {
			hit.segments = append(hit.segments, piece.index)
			hit.classes = searchAppendClass(hit.classes, piece.class)
		}
		if piece.offset < to && piece.offset+piece.length > from {
			hit.contextClasses = searchAppendClass(hit.contextClasses, piece.class)
		}
	}
	s.hits = append(s.hits, hit)
}

// trim lets go of what no later match can need: every byte further behind the
// matcher than the pattern's length less one plus the context width. The bytes
// are zeroed as they go. The buffer is compacted only once more of it is dead
// than live, so a run of many small segments is not copied once per segment.
func (s *recordSearcher) trim() {
	keep := uint64(len(s.needle)-1) + s.width
	if s.next-s.start <= keep {
		return
	}
	drop := s.next - keep - s.start
	if drop < uint64(len(s.buf))-drop {
		return
	}
	live := copy(s.buf, s.buf[drop:])
	security.SecureZero(s.buf[live:])
	s.buf = s.buf[:live]
	s.start += drop
	kept := s.pieces[:0]
	for _, piece := range s.pieces {
		if piece.offset+piece.length > s.start {
			kept = append(kept, piece)
		}
	}
	s.pieces = kept
}

// release zeroes what the search held.
func (s *recordSearcher) release() {
	security.SecureZero(s.buf[:cap(s.buf)])
	security.SecureZero(s.needle)
	s.buf, s.pieces = nil, nil
}

// searchAppend appends plaintext to the run. It never lets append grow the
// buffer: an outgrown array would go to the collector still holding
// plaintext, so the new one is made here and the old one zeroed.
func searchAppend(buf, more []byte) []byte {
	if len(buf)+len(more) <= cap(buf) {
		return append(buf, more...)
	}
	grown := make([]byte, len(buf), 2*(len(buf)+len(more)))
	copy(grown, buf)
	security.SecureZero(buf)
	return append(grown, more...)
}

// searchAppendClass adds a class to a list that names each once.
func searchAppendClass(classes []string, class string) []string {
	if slices.Contains(classes, class) {
		return classes
	}
	return append(classes, class)
}

// recordSearchReader decides whose reading a search stands for, and so which
// segments it may read at all. It returns the view's label, or "" for a grant.
func recordSearchReader(op string, session *recordSession, name string, given bool) (
	func(uint64) bool, string, *object.Error) {

	if session.grant != nil {
		if given {
			return nil, "", newError("%s: this record was opened under a grant, and a search of it reads exactly "+
				"the segments the grant opens; a view can neither widen nor narrow that. Search it without "+
				"the view option", op)
		}
		return session.grant.Granted, "", nil
	}
	if !given {
		return nil, "", newError("%s: a record opened with the case key opens every segment, so a search of it "+
			"has to say whose reading it stands for. Name a view declared with `%s`, as {\"view\": name}: the "+
			"search then reads exactly the segments a grant under that view would open", op, BuiltinNameViewDefine)
	}
	view, _, errObj := viewResolve(op, name)
	if errObj != nil {
		return nil, "", errObj
	}
	// The partition view_preview reports and a disclosure grants, so the
	// search reads what a grant under this view would open and nothing else.
	inView := make([]bool, len(session.segments))
	for _, index := range viewPartition(session, viewGrantedTags(view)).granted {
		inView[index] = true
	}
	return func(index uint64) bool { return index < uint64(len(inView)) && inView[index] }, view.Label, nil
}

// recordSearchLabels maps each class tag the case can name to its label,
// reading the case exactly as recordClassification does, so that a hit's
// classes and the mark on its context never name a class differently.
func recordSearchLabels() map[string]string {
	custodyStore.RLock()
	defer custodyStore.RUnlock()
	labels := map[string]string{}
	if open := custodyStore.session; open != nil {
		for _, class := range open.classes {
			labels[strings.ToLower(class.Tag)] = class.Label
		}
	}
	return labels
}

// recordSearchRecorded writes a search into the open case's timeline and
// returns the pattern's digest as written there, and whether it was written.
//
// The pattern itself is never written. With a case key open it is written as
// its digest keyed to that key; without one it is not written in any form,
// because the only digest left to write would be one anybody could check a
// guess against.
func recordSearchRecorded(op string, session *recordSession, view string, pattern []byte, fold bool,
	searcher *recordSearcher) (string, bool) {

	if !custodyActive.Load() {
		return "", false
	}
	custodyStore.Lock()
	defer custodyStore.Unlock()
	open := custodyStore.session
	if open == nil || open.Closed {
		return "", false
	}
	digest := ""
	if open.caseKey != nil {
		if sum, err := security.SearchPatternDigest(open.caseKey, pattern); err == nil {
			digest = hex.EncodeToString(sum[:])
		}
	}
	reader := "under its grant"
	if view != "" {
		reader = fmt.Sprintf("under view %q", view)
	}
	term := "a pattern written as its digest under the case key"
	if digest == "" {
		term = "a pattern not written in any form, as no case key is open to key its digest to"
	}
	open.appendEvent(custodyNow(), op, fmt.Sprintf("searched record %s %s for %s: %d found in %d of %d segments",
		session.header.RecordUID, reader, term, searcher.count, searcher.searched, len(session.segments)),
		map[string]any{
			"record_uid":        session.header.RecordUID,
			"view":              view,
			"opened_with":       session.openedWith(),
			"pattern_digest":    digest,
			"ignore_ascii_case": fold,
			"matches":           searcher.count,
			"searched_segments": searcher.searched,
			"withheld_segments": searcher.withheld,
			"failed_segments":   int64(len(searcher.failures)),
		})
	return digest, true
}

// RecordSearch finds a literal in what one reader of a record could read:
// record_search(record, pattern, options?).
func RecordSearch(args ...object.Object) object.Object {
	op := BuiltinNameRecordSearch
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	opts, errObj := secretOptionsArg(op, args, 3, recordSearchOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	session, errObj := recordHandleArg(op, args[:2], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	var pattern []byte
	switch value := args[1].(type) {
	case *object.Bytes:
		pattern = make([]byte, len(value.Value))
		copy(pattern, value.Value)
	case *object.String:
		pattern = []byte(value.Value)
	default:
		return resultAndError(nil, newError("argument 2 to `%s` must be BYTES or STRING, got %s", op, args[1].Type()))
	}
	defer security.SecureZero(pattern)
	if len(pattern) == 0 {
		return resultAndError(nil, newError("%s: an empty pattern occurs at every offset of every record, so a "+
			"search for it says nothing", op))
	}
	if len(pattern) > maxSearchPattern {
		return resultAndError(nil, newError("%s: a pattern is at most %d bytes and this one is %d. A search "+
			"term is a term; the passage around a hit is `%s`'s to return", op, maxSearchPattern, len(pattern),
			BuiltinNameRecordRead))
	}
	width, errObj := recordSizeOption(op, opts, "context", defaultSearchContext, 0, maxSearchContext)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	limit, errObj := recordSizeOption(op, opts, "max_hits", defaultSearchHits, 0, maxSearchHits)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	fold, errObj := opts.boolean("ignore_ascii_case", false)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	name, errObj := opts.str("view", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	_, given := opts.pairs["view"]
	readable, view, errObj := recordSearchReader(op, session, name, given)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	searcher := newRecordSearcher(session, pattern, fold, width, int(limit), readable)
	if errObj := searcher.run(op); errObj != nil {
		return resultAndError(nil, errObj)
	}

	labels := recordSearchLabels()
	rows := make([]object.Object, 0, len(searcher.hits))
	for _, hit := range searcher.hits {
		segments := make([]object.Object, len(hit.segments))
		for i, index := range hit.segments {
			segments[i] = intObj(int64(index))
		}
		classes := make([]object.Object, len(hit.classes))
		for i, tag := range hit.classes {
			label, named := labels[tag]
			classes[i] = makeHashObject(map[string]object.Object{
				"tag":      stringObj(tag),
				"label":    stringObj(label),
				"declared": boolObj(named),
			})
		}
		rows = append(rows, makeHashObject(map[string]object.Object{
			"offset":   intObj(int64(hit.offset)),
			"length":   intObj(int64(len(pattern))),
			"segments": &object.Array{Elements: segments},
			"classes":  &object.Array{Elements: classes},
			// Plaintext, marked as a read's output is, so that the builtins
			// that send a value out of the process refuse it.
			"context":        &object.Bytes{Value: hit.context, Classified: recordClassification(session, hit.contextClasses)},
			"context_offset": intObj(int64(hit.contextOffset)),
		}))
	}
	failures := make([]object.Object, 0, len(searcher.failures))
	for _, failure := range searcher.failures {
		failures = append(failures, makeHashObject(map[string]object.Object{
			"segment": intObj(int64(failure.index)),
			"offset":  intObj(int64(failure.offset)),
			"length":  intObj(int64(failure.length)),
			"class":   stringObj(failure.class),
			"reason":  stringObj(failure.reason),
		}))
	}
	digest, recorded := recordSearchRecorded(op, session, view, pattern, fold, searcher)

	total := int64(len(session.segments))
	return resultAndError(makeHashObject(map[string]object.Object{
		"record_uid":  stringObj(session.header.RecordUID),
		"view":        stringObj(view),
		"opened_with": stringObj(session.openedWith()),
		"hits":        &object.Array{Elements: rows},
		// Every match in the searched bytes; hits holds the first max_hits.
		"count":             intObj(searcher.count),
		"truncated":         boolObj(searcher.count > int64(len(rows))),
		"segments":          intObj(total),
		"searched_segments": intObj(searcher.searched),
		"withheld_segments": intObj(searcher.withheld),
		"failed_segments":   intObj(int64(len(searcher.failures))),
		"searched_bytes":    intObj(int64(searcher.searchedBytes)),
		"withheld_bytes":    intObj(int64(searcher.withheldBytes)),
		"failures":          &object.Array{Elements: failures},
		// Whether every segment of the record was searched. A count from a
		// search that was not complete is a statement about the bytes it read
		// and about nothing else.
		"complete":       boolObj(searcher.searched == total),
		"pattern_digest": stringObj(digest),
		"recorded":       boolObj(recorded),
		"does_not_say": stringArrayObj([]string{
			"whether the pattern occurs in a segment the search did not read: such a segment is never read " +
				"from the file, so the count covers the searched bytes and nothing else",
			"whether a match runs into a segment the search did not read: one that would need even one " +
				"byte of it is not reported, and nothing marks where one could have been",
			"whether the text is there in another form: the match is byte for byte -- with ASCII capitals " +
				"folded when ignore_ascii_case is set -- so the same words in UTF-16, under another Unicode " +
				"normalisation or broken by a line ending are not found",
		}),
	}), nil)
}
