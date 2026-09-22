package builtin

// Classification labels.
//
// A classification is a name and a tag. The name is what an examiner writes in
// a report; the tag is what a record segment carries, and it is an HMAC keyed
// to the case key, so two investigations that both declare "restricted"
// produce different tags and nobody holding both records can link them.
//
// # Why labels are declared before they are used
//
// `class_define` exists so that `record_classify_range` can refuse a label
// nobody declared. Without it a typo is not an error, it is a new
// classification with no name anybody recognises and no row in the manifest --
// which is the failure mode this whole family is built to prevent. Declaring
// first turns a silent new secret class into an error at the line that made it.
//
// # Where the set lives, and what that costs
//
// On the case session, sealed into the manifest, which is signed. Not in the
// key file: the key is the thing an examiner keeps away from the handover, and
// a scheme written into it would either travel with the key or not travel at
// all. Not in graphene: that arrives with the disclosure schema, and a class
// table is small, ordered and read far more often than it is written.
//
// The cost is stated plainly in docs/DISCLOSURE_POLICY.md and repeated here
// because it is the kind of thing a reader should meet twice. A `.mrec`
// separated from its case manifest holds tags whose meaning is not recoverable
// from anything its holder has. The binding is cryptographic; the naming is
// documentary. That is deliberate -- the manifest is the case document and it
// is signed -- but it means a record without its case is evidentially mute
// even when it is cryptographically openable.

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"mutant/object"
	"mutant/security"
)

// classDefineOptions is the whole option surface. A description is prose for
// the manifest and is never part of the tag.
var classDefineOptions = []string{"description"}

// maxClassLabel is a display limit rather than a cryptographic one. HMAC takes
// any length; a label nobody can read in a table is the actual failure.
const maxClassLabel = 64

// ClassDefine declares one classification label and returns its tag.
func ClassDefine(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	label, errObj := requireStringArg(BuiltinNameClassDefine, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	opts, errObj := formatOptionsArg(BuiltinNameClassDefine, args, 2, classDefineOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	description, errObj := opts.str("description", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	canonical, errObj := canonicalClassLabel(BuiltinNameClassDefine, label)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()

	session, errObj := openSessionLocked(BuiltinNameClassDefine)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if session.classTagKey == nil {
		return resultAndError(nil, newError("%s: no case key is open; call `case_key_open(path)` "+
			"first, because a class label is tagged under the case key",
			BuiltinNameClassDefine))
	}
	for _, existing := range session.classes {
		if existing.Canonical == canonical {
			return resultAndError(nil, newError("%s: %q is already defined as %q. Two labels that "+
				"differ only in case or spacing would carry the same tag and mean two different "+
				"things in the same report",
				BuiltinNameClassDefine, label, existing.Label))
		}
	}

	tag, err := security.TagForClass(session.classTagKey, canonical)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameClassDefine, err.Error()))
	}
	class := caseClass{
		Label:       label,
		Canonical:   canonical,
		Description: description,
		Tag:         hex.EncodeToString(tag[:]),
		Index:       len(session.classes),
		DefinedAt:   custodyNow(),
	}
	session.classes = append(session.classes, class)

	// Recorded under the lock this function already holds, which is why it
	// appends directly rather than calling custodyRecordArtifact -- that takes
	// the same lock and would deadlock.
	now := class.DefinedAt
	session.timeline = append(session.timeline, custodyEvent{
		At:      now,
		Elapsed: now.Sub(session.OpenedAt),
		Event:   BuiltinNameClassDefine,
		Detail:  fmt.Sprintf("classification %q declared", label),
		Data: map[string]any{
			"label":     label,
			"canonical": canonical,
			"tag":       class.Tag,
			"index":     int64(class.Index),
		},
	})

	return resultAndError(makeHashObject(map[string]object.Object{
		"label":       stringObj(class.Label),
		"canonical":   stringObj(class.Canonical),
		"description": stringObj(class.Description),
		"index":       intObj(int64(class.Index)),
		"tag":         stringObj(class.Tag),
		"status":      stringObj("ok"),
	}), nil)
}

// ClassList reports the scheme in force.
//
// It answers with the same keys whether or not a case is open, because a
// program that branches on "is there a scheme" should read a field rather than
// an error. `open` says a case is open; `tagged` says a key is open, which is
// what makes a tag possible at all.
func ClassList(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}

	custodyStore.RLock()
	defer custodyStore.RUnlock()

	session := custodyStore.session
	if session == nil || session.Closed {
		return resultAndError(makeHashObject(map[string]object.Object{
			"classes": &object.Array{Elements: []object.Object{}},
			"count":   intObj(0),
			"case_id": stringObj(""),
			"open":    boolObj(false),
			"tagged":  boolObj(false),
		}), nil)
	}

	classes := make([]object.Object, 0, len(session.classes))
	for _, class := range session.classes {
		classes = append(classes, makeHashObject(map[string]object.Object{
			"label":       stringObj(class.Label),
			"canonical":   stringObj(class.Canonical),
			"description": stringObj(class.Description),
			"index":       intObj(int64(class.Index)),
			"tag":         stringObj(class.Tag),
		}))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"classes": &object.Array{Elements: classes},
		"count":   intObj(int64(len(classes))),
		"case_id": stringObj(session.ID),
		"open":    boolObj(true),
		"tagged":  boolObj(session.classTagKey != nil),
	}), nil)
}

// canonicalClassLabel is what the tag is computed over.
//
// NFC, then trim, then fold. The order matters: folding before normalising
// would make two labels that normalise together fold apart. The tag is over
// the canonical form so that "Restricted", "restricted" and " restricted "
// are one class rather than three, which is the mistake an examiner actually
// makes at two in the morning.
//
// The limit of this, stated where the code is rather than only in the policy:
// two labels differing by a homoglyph, a zero-width joiner or a bidi control
// character are two classes with two tags and no warning. Control and format
// characters are refused outright, which removes the worst of it; the rest is
// mitigated by a class table being short and an examiner reading it. That is a
// human mitigation and it is the only one available -- a tool cannot decide
// that Cyrillic "с" was meant to be Latin "c".
func canonicalClassLabel(op, label string) (string, *object.Error) {
	trimmed := strings.TrimSpace(norm.NFC.String(label))
	if trimmed == "" {
		return "", newError("%s: a classification label must not be empty", op)
	}
	if len([]rune(trimmed)) > maxClassLabel {
		return "", newError("%s: %q is longer than %d characters. A label is read in a table and "+
			"quoted in a report", op, label, maxClassLabel)
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", newError("%s: %q contains a control or formatting character. Two labels "+
				"that look identical and tag differently would be two classes nobody could tell "+
				"apart in a report", op, label)
		}
	}
	// Internal whitespace is collapsed so that "top secret" and "top  secret"
	// are one label. strings.Fields splits on any Unicode space.
	return strings.ToLower(strings.Join(strings.Fields(trimmed), " ")), nil
}
