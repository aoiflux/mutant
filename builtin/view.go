package builtin

// The `view_*` family: a named disclosure posture, and what it would disclose.
//
// A view is a name and a set of classifications. `disclose_*` issues grants
// under a view; `view_preview` says what a view would grant from a particular
// record, before anything is granted and without reading a byte of plaintext.
//
// # Why a view exists at all, rather than a list of classes per disclosure
//
// The same posture goes to every record bound for one recipient, and a posture
// spelled out again at each call is a posture that can differ at each call. A
// disclosure review asks "what does counsel get", once, about a name -- not
// about the fourth argument of the sixth call in a script. Declaring it once
// also puts it in the manifest as a row with a label on it, which is the form a
// person can actually review.
//
// # There is no negation
//
// A view grants the classes it names. It cannot say "everything except
// restricted", and that omission is the feature. A negated view widens by
// itself every time a class is declared after it: the script does not change,
// the manifest row does not change, and the set of bytes it releases grows. A
// disclosure posture that can change without anybody editing it is the one
// thing this family must not offer, because the document meant to record the
// change would record nothing.
//
// # What a preview reads, and what it therefore cannot tell you
//
// Segment boundaries, lengths and class tags are all in the record header,
// which is public by construction. A preview is arithmetic over that header and
// the case's class table; it opens no segment and needs no plaintext. So it can
// say exactly which bytes a view would release and exactly which it would hold
// back -- and it cannot say whether the classification that put them there was
// the right one. That judgement is the examiner's, and the preview's job is to
// put the numbers in front of them before they make it, not to make it for
// them.
//
// # The rounding, restated where it is about to matter
//
// A record sealed by `record_seal_quantised` has boundaries the examiner did
// not draw: rounding grew one class over its neighbours, and the header names
// which class and how many bytes. Whether that widening withholds more or
// releases more depends entirely on whether the view being previewed grants
// that class. The preview therefore reports the direction in the terms of the
// view in front of it rather than in the abstract, because "12 bytes were
// rounded", read without a direction, is a statement a reviewer will complete
// themselves -- correctly about half the time.

import (
	"encoding/hex"
	"fmt"
	"strings"

	"mutant/object"
)

// viewDefineOptions is the whole option surface. A description is prose for the
// manifest and is never part of what the view grants.
var viewDefineOptions = []string{"description"}

// maxViewClasses bounds one view's grant list. A view cannot usefully grant
// more classes than a case would ever declare, and a list longer than this is a
// list with repeats in it, which is refused on its own account anyway.
const maxViewClasses = 256

// ViewDefine declares one named disclosure posture: view_define(label, classes, options?).
func ViewDefine(args ...object.Object) object.Object {
	op := BuiltinNameViewDefine
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	label, errObj := requireStringArg(op, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	list, errObj := requireArrayArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	opts, errObj := formatOptionsArg(op, args, 3, viewDefineOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	description, errObj := opts.str("description", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	canonical, errObj := canonicalLabel(op, "view name", label)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if len(list.Elements) > maxViewClasses {
		return resultAndError(nil, newError("%s: a view names at most %d classes and this one names %d",
			op, maxViewClasses, len(list.Elements)))
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()

	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if session.classTagKey == nil {
		return resultAndError(nil, newError("%s: no case key is open; call `case_key_open(path)` first, "+
			"because a view names classes and a class is tagged under the case key", op))
	}
	for _, existing := range session.views {
		if existing.Canonical == canonical {
			return resultAndError(nil, newError("%s: %q is already defined as %q. Two views whose names "+
				"differ only in case or spacing are two postures nobody could tell apart in a "+
				"disclosure record", op, label, existing.Label))
		}
	}

	labels := make([]string, 0, len(list.Elements))
	tags := make([]string, 0, len(list.Elements))
	seen := make(map[string]string, len(list.Elements))
	for i, element := range list.Elements {
		name, ok := element.(*object.String)
		if !ok {
			return resultAndError(nil, newError("%s: entry %d of the class list must be STRING, got %s. "+
				"A view names classes by the label `class_define` declared them under",
				op, i+1, element.Type()))
		}
		// Canonicalised through the same rule that produced the tag, so that a
		// view written with different spacing or casing than the declaration
		// still resolves. A view that silently granted nothing would be the
		// worst failure available to this family.
		wanted, errObj := canonicalLabel(op, "classification label", name.Value)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		if first, repeated := seen[wanted]; repeated {
			return resultAndError(nil, newError("%s: entry %d names %q, which this view already grants "+
				"as %q. A repeated class is a list whose author lost track of it, and collapsing it "+
				"quietly would hide exactly that", op, i+1, name.Value, first))
		}
		class, found := classByCanonicalLocked(session, wanted)
		if !found {
			return resultAndError(nil, viewUndeclaredClass(op, session, i+1, name.Value))
		}
		seen[wanted] = name.Value
		labels = append(labels, class.Label)
		tags = append(tags, class.Tag)
	}

	view := caseView{
		Label:       label,
		Canonical:   canonical,
		Description: description,
		Classes:     labels,
		Tags:        tags,
		Index:       len(session.views),
		DefinedAt:   custodyNow(),
	}
	session.views = append(session.views, view)

	// Appended directly under the lock this function already holds, for the
	// same reason class_define does it: custodyRecordArtifact takes the same
	// lock and would deadlock.
	now := view.DefinedAt
	session.timeline = append(session.timeline, custodyEvent{
		At:      now,
		Elapsed: now.Sub(session.OpenedAt),
		Event:   op,
		Detail:  fmt.Sprintf("view %q declared over %d classes", label, len(labels)),
		Data: map[string]any{
			"label":       label,
			"canonical":   canonical,
			"grants":      strings.Join(labels, ", "),
			"grant_count": int64(len(labels)),
			"index":       int64(view.Index),
		},
	})

	return resultAndError(makeHashObject(map[string]object.Object{
		"label":       stringObj(view.Label),
		"canonical":   stringObj(view.Canonical),
		"description": stringObj(view.Description),
		"grants":      viewGrantRows(view),
		"grant_count": intObj(int64(len(view.Classes))),
		"index":       intObj(int64(view.Index)),
		// A view granting no class is legal and is not a mistake this refuses:
		// it discloses the record's existence, its signature and its shape, and
		// no content at all. It is said out loud because an empty array is also
		// what a typo produces.
		"grants_nothing": boolObj(len(view.Classes) == 0),
		"status":         stringObj("ok"),
	}), nil)
}

// ViewList reports the postures declared for this case: view_list().
//
// Same shape whether or not a case is open, for the reason class_list gives: a
// program asking "is there a posture declared" should read a field rather than
// catch an error.
func ViewList(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}

	custodyStore.RLock()
	defer custodyStore.RUnlock()

	session := custodyStore.session
	if session == nil || session.Closed {
		return resultAndError(makeHashObject(map[string]object.Object{
			"views":   &object.Array{Elements: []object.Object{}},
			"count":   intObj(0),
			"case_id": stringObj(""),
			"open":    boolObj(false),
			"tagged":  boolObj(false),
		}), nil)
	}
	rows := make([]object.Object, 0, len(session.views))
	for _, view := range session.views {
		rows = append(rows, makeHashObject(map[string]object.Object{
			"label":       stringObj(view.Label),
			"canonical":   stringObj(view.Canonical),
			"description": stringObj(view.Description),
			"grants":      viewGrantRows(view),
			"grant_count": intObj(int64(len(view.Classes))),
			"index":       intObj(int64(view.Index)),
		}))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"views":   &object.Array{Elements: rows},
		"count":   intObj(int64(len(session.views))),
		"case_id": stringObj(session.ID),
		"open":    boolObj(true),
		"tagged":  boolObj(session.classTagKey != nil),
	}), nil)
}

// viewGrantRows renders a view's grant list as label and tag pairs.
func viewGrantRows(view caseView) *object.Array {
	rows := make([]object.Object, 0, len(view.Classes))
	for i, label := range view.Classes {
		rows = append(rows, makeHashObject(map[string]object.Object{
			"label": stringObj(label),
			"tag":   stringObj(view.Tags[i]),
		}))
	}
	return &object.Array{Elements: rows}
}

// classByCanonicalLocked finds a declared class by its canonical label. The
// caller holds the store lock.
func classByCanonicalLocked(session *custodySession, canonical string) (caseClass, bool) {
	for _, class := range session.classes {
		if class.Canonical == canonical {
			return class, true
		}
	}
	return caseClass{}, false
}

// viewUndeclaredClass is the refusal for a view naming a class nobody declared.
//
// It names the position in the list, because a view is written as one argument
// and a program that got one entry wrong has no other way to find which.
func viewUndeclaredClass(op string, session *custodySession, position int, label string) *object.Error {
	declared := make([]string, 0, len(session.classes))
	for _, class := range session.classes {
		declared = append(declared, class.Label)
	}
	if len(declared) == 0 {
		return newError("%s: entry %d names %q, which is not a declared classification -- this case has "+
			"declared none. Call `class_define(label)` first, so that a typo is an error rather than a "+
			"view which grants nothing and says so nowhere", op, position, label)
	}
	return newError("%s: entry %d names %q, which is not a declared classification. This case declares %s",
		op, position, label, strings.Join(declared, ", "))
}

// ---------------------------------------------------------------------------
// view_preview
// ---------------------------------------------------------------------------

// viewRun is one contiguous stretch of segments that a view treats alike.
type viewRun struct {
	offset uint64
	length uint64
	first  uint64
	last   uint64
	tag    string
}

// viewClassTally is what one class amounts to inside one record.
type viewClassTally struct {
	segments int64
	bytes    uint64
}

// ViewPreview says what a view would disclose from a record: view_preview(record, view).
func ViewPreview(args ...object.Object) object.Object {
	op := BuiltinNameViewPreview
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := recordHandleArg(op, args, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	name, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	view, labels, errObj := viewResolve(op, name)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	granted := viewGrantedTags(view)
	split := viewPartition(session, granted)
	grantedRuns, withheldRuns := split.grantedRuns, split.withheldRuns
	grantedBytes, withheldBytes, grantedCount := split.grantedBytes, split.withheldBytes, split.grantedCount
	tallies, order := split.tallies, split.order

	classRows := make([]object.Object, 0, len(order))
	var unnamed int64
	for _, tag := range order {
		tally := tallies[tag]
		class, named := labels[tag]
		if !named {
			unnamed++
		}
		classRows = append(classRows, makeHashObject(map[string]object.Object{
			"tag":      stringObj(tag),
			"label":    stringObj(class.Label),
			"declared": boolObj(named),
			"granted":  boolObj(granted[tag]),
			"segments": intObj(tally.segments),
			"bytes":    intObj(int64(tally.bytes)),
		}))
	}

	total := int64(len(session.segments))
	result := map[string]object.Object{
		"record_uid":        stringObj(session.header.RecordUID),
		"view":              stringObj(view.Label),
		"plaintext_length":  intObj(int64(session.header.PlaintextLength)),
		"segments":          intObj(total),
		"granted_segments":  intObj(grantedCount),
		"withheld_segments": intObj(total - grantedCount),
		"granted_bytes":     intObj(int64(grantedBytes)),
		"withheld_bytes":    intObj(int64(withheldBytes)),
		"granted_runs":      viewRunRows(grantedRuns, labels),
		"withheld_runs":     viewRunRows(withheldRuns, labels),
		"classes":           &object.Array{Elements: classRows},
		// A class the record carries whose tag this case cannot name. It means
		// the label was declared in some earlier session and not in this one:
		// the binding is cryptographic and survives, the naming is documentary
		// and does not. A reviewer looking at a row with no label is looking at
		// bytes whose classification nothing here can read back.
		"unnamed_classes":        intObj(unnamed),
		"discloses_whole_record": boolObj(grantedCount == total),
		"discloses_nothing":      boolObj(grantedCount == 0),
		"reads_no_plaintext":     boolObj(true),
		"does_not_say": stringArrayObj([]string{
			"whether the classification that put these bytes where they are was the correct one",
			"what the granted bytes contain: a preview opens no segment and needs no key",
			"that the recipient receives only these bytes -- a disclosure hands over the whole " +
				"record file, so they hold every ciphertext and learn every boundary and length " +
				"whether or not they can open it",
		}),
	}
	for key, value := range viewRoundingReport(session, view, granted, labels) {
		result[key] = value
	}
	return resultAndError(makeHashObject(result), nil)
}

// viewSplit is a record divided by a view: every segment on one side or the
// other, as runs, as totals, per class, and as the plain list of granted
// indices a grant carries material for.
type viewSplit struct {
	grantedRuns   []viewRun
	withheldRuns  []viewRun
	grantedBytes  uint64
	withheldBytes uint64
	grantedCount  int64
	tallies       map[string]*viewClassTally
	order         []string
	granted       []uint64
}

// viewPartition divides a record by a set of granted tags.
//
// It is the one computation behind view_preview and every disclose_* builtin,
// so that what a preview says a view would release and what a disclosure
// under that view does release cannot differ -- a preview that was computed
// one way and a grant that was issued another would make the preview a
// statement about a different disclosure from the one that happened.
func viewPartition(session *recordSession, granted map[string]bool) viewSplit {
	split := viewSplit{tallies: map[string]*viewClassTally{}}
	for _, segment := range session.segments {
		tag := hex.EncodeToString(segment.Class[:])
		tally, seen := split.tallies[tag]
		if !seen {
			tally = &viewClassTally{}
			split.tallies[tag] = tally
			split.order = append(split.order, tag)
		}
		tally.segments++
		tally.bytes += uint64(segment.Length)

		into := &split.withheldRuns
		if granted[tag] {
			into = &split.grantedRuns
			split.grantedBytes += uint64(segment.Length)
			split.grantedCount++
			split.granted = append(split.granted, segment.Index)
		} else {
			split.withheldBytes += uint64(segment.Length)
		}
		// Extended rather than appended when this segment carries the same
		// class as the last run on the same side AND begins exactly where that
		// run ended. The offsets are compared rather than assumed contiguous:
		// the table is derived from spans that partition the plaintext today,
		// and a run list that quietly bridged a gap would misstate the one
		// thing it exists to state.
		if n := len(*into); n > 0 && (*into)[n-1].tag == tag &&
			(*into)[n-1].offset+(*into)[n-1].length == segment.Offset {
			(*into)[n-1].length += uint64(segment.Length)
			(*into)[n-1].last = segment.Index
			continue
		}
		*into = append(*into, viewRun{
			offset: segment.Offset,
			length: uint64(segment.Length),
			first:  segment.Index,
			last:   segment.Index,
			tag:    tag,
		})
	}
	return split
}

// viewGrantedTags is a view's grant list as a set, lowercased once so that a
// tag compared against it cannot miss on case alone.
func viewGrantedTags(view caseView) map[string]bool {
	granted := make(map[string]bool, len(view.Tags))
	for _, tag := range view.Tags {
		granted[strings.ToLower(tag)] = true
	}
	return granted
}

// viewRunRows renders a run list, naming each run's class where the case can.
func viewRunRows(runs []viewRun, labels map[string]caseClass) *object.Array {
	rows := make([]object.Object, 0, len(runs))
	for _, run := range runs {
		class, named := labels[run.tag]
		rows = append(rows, makeHashObject(map[string]object.Object{
			"offset":        intObj(int64(run.offset)),
			"length":        intObj(int64(run.length)),
			"first_segment": intObj(int64(run.first)),
			"last_segment":  intObj(int64(run.last)),
			"class":         stringObj(run.tag),
			"label":         stringObj(class.Label),
			"declared":      boolObj(named),
		}))
	}
	return &object.Array{Elements: rows}
}

// viewRoundingReport states what this record's rounding did, in the terms of
// the view in front of it.
//
// The direction is the whole content of this block. A quantised record moved
// QuantisedExtra bytes out of the classes they were drawn in and into RoundsTo.
// If the view grants RoundsTo, the recipient gets bytes the examiner's own
// boundaries placed elsewhere; if it does not, bytes the examiner's boundaries
// placed elsewhere are held back. Reporting the count without the direction
// leaves a reviewer to supply it, and there are two directions.
func viewRoundingReport(session *recordSession, view caseView, granted map[string]bool,
	labels map[string]caseClass) map[string]object.Object {

	header := session.header
	out := map[string]object.Object{
		"quantised":       boolObj(header.Quantum != 0),
		"quantum":         intObj(int64(header.Quantum)),
		"quantised_extra": intObj(int64(header.QuantisedExtra)),
		"rounds_to":       stringObj(header.RoundsTo),
	}
	if header.Quantum == 0 {
		out["rounds_to_label"] = stringObj("")
		out["rounds_to_granted"] = boolObj(false)
		out["rounding_effect"] = stringObj("this record was sealed at the boundaries the examiner drew")
		return out
	}
	// ParseRecordHeader has already refused a quantum with no class named
	// beside it, so RoundsTo is a tag here. Whether this case can put a NAME to
	// that tag is a separate question, and the answer may be no.
	tag := strings.ToLower(header.RoundsTo)
	class, named := labels[tag]
	grows := granted[tag]
	out["rounds_to_label"] = stringObj(class.Label)
	out["rounds_to_granted"] = boolObj(grows)

	name := fmt.Sprintf("%q", class.Label)
	if !named {
		name = "the class it rounded into, which this case cannot put a name to"
	}
	switch {
	case header.QuantisedExtra == 0:
		out["rounding_effect"] = stringObj(fmt.Sprintf(
			"boundaries were rounded to %d bytes and every one of them already fell on a boundary, so "+
				"no byte changed class", header.Quantum))
	case grows:
		out["rounding_effect"] = stringObj(fmt.Sprintf(
			"rounding to %d bytes moved %d bytes into %s, and %q grants that class -- so this view "+
				"releases up to %d bytes that the examiner's own boundaries placed elsewhere",
			header.Quantum, header.QuantisedExtra, name, view.Label, header.QuantisedExtra))
	default:
		out["rounding_effect"] = stringObj(fmt.Sprintf(
			"rounding to %d bytes moved %d bytes into %s, and %q does not grant that class -- so this "+
				"view holds back up to %d bytes that the examiner's own boundaries placed elsewhere",
			header.Quantum, header.QuantisedExtra, name, view.Label, header.QuantisedExtra))
	}
	return out
}

// viewResolve returns a declared view and a tag-to-class table for naming what
// a record carries, taking the store's read lock once for both.
//
// One lock and one pass: a preview that looked the view up, released the lock,
// and then looked classes up again could be reading a table a concurrent
// class_define had grown in between, and would report as undeclared a class
// that the view it just read grants.
func viewResolve(op, name string) (caseView, map[string]caseClass, *object.Error) {
	canonical, errObj := canonicalLabel(op, "view name", name)
	if errObj != nil {
		return caseView{}, nil, errObj
	}

	custodyStore.RLock()
	defer custodyStore.RUnlock()

	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return caseView{}, nil, errObj
	}
	labels := make(map[string]caseClass, len(session.classes))
	for _, class := range session.classes {
		labels[strings.ToLower(class.Tag)] = class
	}
	for _, view := range session.views {
		if view.Canonical == canonical {
			return view, labels, nil
		}
	}
	declared := make([]string, 0, len(session.views))
	for _, view := range session.views {
		declared = append(declared, view.Label)
	}
	if len(declared) == 0 {
		return caseView{}, nil, newError("%s: %q is not a declared view, and this case has declared none. "+
			"Call `view_define(label, classes)` first, so that what a recipient gets is a named posture "+
			"in the manifest rather than a list assembled at the call", op, name)
	}
	return caseView{}, nil, newError("%s: %q is not a declared view. This case declares %s",
		op, name, strings.Join(declared, ", "))
}
