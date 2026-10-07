package builtin

// Classified plaintext, and the places it is not allowed to leave by accident.
//
// `record_read` and `record_read_partial` return plaintext out of a classified
// record, and so does `record_search`, as the context around each hit. From
// that moment the plaintext is an ordinary buffer: one
// `putln(secret)` prints all of it, because Inspect renders a buffer as its
// entire hex. So the buffer carries a mark -- object.Bytes.Classified -- and the
// builtins that send a value out of the process refuse one that carries it:
// putln and putf, fs_write and fs_append, http_post and http_request,
// report_write and report_render, report_table and report_list (which render a
// cell as it is added, so the check has to happen there), case_note,
// cache_put, and ledger_add_node, ledger_add_edge, db_add_artifact and
// db_add_relation (graphene must never hold evidence plaintext: its property
// blobs sit in the write-ahead log, and a ledger is written to be handed
// over).
//
// A builtin whose parameter is STRING alone -- net_conn_write, ws_write_frame,
// exec_string, cmd_add, net_dns_query, lua_run_string -- cannot be handed a
// buffer at all, so the only way plaintext reaches one is a conversion, which
// is the limit stated below. sqlite_query is not a sink: it runs against a
// copy it deletes, and binding a buffer as a parameter sends it nowhere.
//
// The check walks arrays, hashes, struct fields and the values an error
// carries, so a buffer inside a container is caught too. It never renders what
// it finds: the refusal names the record, the classes and the length, and not
// one byte.
//
// The sinks are not the only way out. The runtime prints values nobody called a
// builtin to print -- a traceback's arguments, the debugger's variables pane,
// and the value a finished program is echoed as -- and those reach no sink, so
// refuseClassified never sees them. FindClassified and DescribeClassified are
// exported for them, so that "does this hold classified plaintext" has one
// definition rather than four that drift.
//
// # What this does not do, said as loudly as what it does
//
// The mark survives being held -- a variable is stored encrypted at rest,
// and object.Encrypted carries the mark beside the ciphertext -- and an array
// or a hash holding the buffer holds the same buffer, mark and all. It travels
// to a new buffer through bytes_slice and through `a + b` of two buffers
// (object.JoinClassification), and nothing else. A conversion to a string, to
// hex, to base64 or to JSON produces a value without it, and so does a loop
// that rebuilds the buffer byte by byte. Nor is an integer marked: the offset
// of a record_search hit, beside the pattern that matched there, says what the
// record holds at that offset. This catches accidents, not adversaries --
// which is the agreed enforcement: at run time, with no taint analysis in the
// compiler.
//
// The deliberate path out is `record_release(buffer, reason)`, which returns
// an unmarked copy and records in the case timeline that the examiner chose to
// let those bytes go, and why. An accident is caught; a decision is recorded.

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"mutant/object"
)

// classifiedWalkDepth bounds how far into nested containers the check looks.
// A value nested deeper than this is refused as unknown rather than passed as
// clean: a guard that gives up in the permissive direction is not a guard.
const classifiedWalkDepth = 64

// FindClassified returns the first classified buffer inside a value, or nil.
// deep reports that the value was nested past classifiedWalkDepth and could
// not be looked at all the way down.
//
// A nil Value on the returned buffer means the mark was found on a value still
// sealed, where the plaintext length is not knowable from here;
// DescribeClassified says so rather than reporting zero bytes.
func FindClassified(value object.Object) (found *object.Bytes, deep bool) {
	seen := map[uintptr]bool{}
	var walk func(object.Object, int) *object.Bytes
	walk = func(v object.Object, depth int) *object.Bytes {
		if v == nil {
			return nil
		}
		if depth > classifiedWalkDepth {
			deep = true
			return nil
		}
		switch o := v.(type) {
		case *object.Bytes:
			if o.Classified != nil {
				return o
			}
		case *object.Array:
			if !classifiedVisit(seen, o) {
				return nil
			}
			for _, element := range o.Elements {
				if hit := walk(element, depth+1); hit != nil {
					return hit
				}
			}
		case *object.Hash:
			if !classifiedVisit(seen, o) {
				return nil
			}
			for _, pair := range o.Pairs {
				if hit := walk(pair.Key, depth+1); hit != nil {
					return hit
				}
				if hit := walk(pair.Value, depth+1); hit != nil {
					return hit
				}
			}
		case *object.Struct:
			if !classifiedVisit(seen, o) {
				return nil
			}
			for _, field := range o.Fields {
				if hit := walk(field, depth+1); hit != nil {
					return hit
				}
			}
		// An error carries whatever the raiser knew, and errorObj.go names
		// "the bytes actually read, the record that was being parsed" among
		// the things Related is for. Inspect renders each of those through the
		// value's own Inspect, and a buffer's Inspect is its entire hex, so
		// one `putln(err)` printed the whole of a classified buffer and no
		// sink saw it: this walk had no arm for an error at all
		// (M26-REC-007). Names are walked in sorted order, so which buffer a
		// refusal names does not change from run to run.
		case *object.Error:
			if !classifiedVisit(seen, o) {
				return nil
			}
			names := make([]string, 0, len(o.Related))
			for name := range o.Related {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if hit := walk(o.Related[name], depth+1); hit != nil {
					return hit
				}
			}

		// A value still at rest. encObj.go keeps the mark beside the
		// ciphertext for exactly this reason, in its own words: "without this
		// a buffer lost its mark the moment it was bound to a name, and every
		// sink check downstream passed it." Nothing here read it. That matters
		// because DecryptObject recurses into an array, a hash and a struct,
		// so their elements arrive as plaintext objects -- but it hands a cell
		// back by pointer without touching what is inside, since a cell is a
		// storage location that OpSetFree writes through. So a captured
		// variable reaches a sink as a cell whose value is still sealed, and
		// `Cell -> Encrypted` was a hole straight through the check. The mark
		// is enough to refuse on; the length is not ours to state, so the
		// buffer handed back carries the mark and a nil Value.
		case *object.Encrypted:
			if o.Classified != nil {
				return &object.Bytes{Classified: o.Classified}
			}

		case *object.MultiValue:
			for _, element := range o.Values {
				if hit := walk(element, depth+1); hit != nil {
					return hit
				}
			}
		// The three one-value wrappers: an enum's payload, a captured
		// variable's box, and a value on its way out of a function. Each is
		// the value it holds as far as a sink is concerned.
		case *object.EnumValue:
			return walk(o.Value, depth+1)
		case *object.Cell:
			return walk(o.Value, depth+1)
		case *object.ReturnValue:
			return walk(o.Value, depth+1)
		}
		return nil
	}
	return walk(value, 0), deep
}

// classifiedVisit marks a container seen and reports whether it was new, so
// that a container holding itself is walked once.
func classifiedVisit(seen map[uintptr]bool, container any) bool {
	key := reflect.ValueOf(container).Pointer()
	if seen[key] {
		return false
	}
	seen[key] = true
	return true
}

// DescribeClassified names where a classified buffer came from, and nothing
// about what it holds. Exported alongside FindClassified, and for the same
// reason.
func DescribeClassified(b *object.Bytes) string {
	c := b.Classified
	names := make([]string, 0, len(c.Tags))
	for i, tag := range c.Tags {
		label := ""
		if i < len(c.Labels) {
			label = c.Labels[i]
		}
		switch {
		case label != "":
			names = append(names, fmt.Sprintf("%q", label))
		case len(tag) >= 16:
			names = append(names, "a class this run cannot name ("+tag[:16]+")")
		default:
			names = append(names, "a class this run cannot name")
		}
	}
	// A nil Value is the mark found on a value still sealed. An empty buffer
	// read out of a record is a legitimate result and is []byte{}, not nil, so
	// the two do not collide.
	size := fmt.Sprintf("%d bytes of plaintext", len(b.Value))
	if b.Value == nil {
		size = "a sealed value"
	}
	return fmt.Sprintf("%s read from record %s, classified %s",
		size, c.RecordUID, strings.Join(names, " and "))
}

// WithheldEcho returns the line the runtime prints in place of a program's
// last value when that value holds classified plaintext, and false when the
// value may be echoed as it is.
//
// The echo is not a builtin call. `mutant prog.mu` prints what the program
// ended on, and so do the REPL and the debug adapter when a session steps to
// the end, and none of them passes through a sink -- so a program whose last
// expression was a buffer read out of a classified record printed the whole
// buffer as hex, through Inspect, having refused to print it through putln one
// line earlier (M26-REC-006). The three callers share this so that the three
// say the same thing.
//
// The replacement goes where the value would have gone rather than to a
// diagnostic stream, because the shape of the output is what tells a reader
// that something was withheld rather than absent.
func WithheldEcho(value object.Object) (string, bool) {
	found, deep := FindClassified(value)
	switch {
	case found != nil:
		return fmt.Sprintf("<%s; not echoed. `%s(buffer, reason)` returns a copy that may be>",
			DescribeClassified(found), BuiltinNameRecordRelease), true
	case deep:
		return fmt.Sprintf("<nested more than %d levels deep, too deep to check for classified "+
			"plaintext, and a value that could not be checked is not echoed>",
			classifiedWalkDepth), true
	}
	return "", false
}

// ClassifiedSinks returns the builtins that refuse classified plaintext
// anywhere in their arguments. The editor's classifiedPlaintext rule reads this
// list to warn at the call before it runs, and
// TestClassifiedSinksAreTheBuiltinsThatRefuse holds it to the builtins that
// actually call refuseClassified, so the warning and the refusal cannot drift
// apart.
func ClassifiedSinks() []string {
	return []string{
		BuiltinNamePutln, BuiltinNamePutf,
		BuiltinNameFsWrite, BuiltinNameFsAppend,
		BuiltinNameHttpPost, BuiltinNameHttpRequest,
		BuiltinNameReportWrite, BuiltinNameReportRender,
		BuiltinNameReportTable, BuiltinNameReportList,
		BuiltinNameCaseNote, BuiltinNameCachePut,
		BuiltinNameLedgerAddNode, BuiltinNameLedgerAddEdge,
		BuiltinNameDbAddArtifact, BuiltinNameDbAddRelation,
	}
}

// ClassifiedSources returns the builtins whose result carries the mark:
// record_read's buffer, the `bytes` entry of record_read_partial's hash, and
// the `context` of each of record_search's hits. Held to the code that sets
// the mark by TestClassifiedSourcesAreTheBuiltinsThatMark.
func ClassifiedSources() []string {
	return []string{BuiltinNameRecordRead, BuiltinNameRecordReadPartial, BuiltinNameRecordSearch}
}

// refuseClassified is the sink check: nil when no argument holds classified
// plaintext, and a refusal naming the first one that does.
func refuseClassified(op string, args ...object.Object) *object.Error {
	for i, arg := range args {
		found, deep := FindClassified(arg)
		if found != nil {
			return newError("%s: argument %d holds %s. Classified plaintext does not leave the process by "+
				"this route; `%s(buffer, reason)` returns a copy that may, and records that you released it",
				op, i+1, DescribeClassified(found), BuiltinNameRecordRelease)
		}
		if deep {
			return newError("%s: argument %d is nested more than %d levels deep, too deep to check for "+
				"classified plaintext, and a value that could not be checked is not sent", op, i+1,
				classifiedWalkDepth)
		}
	}
	return nil
}

// classifiedCopy stamps a classification onto a buffer derived from a
// classified one. Shared, not copied: it is the same provenance, and nothing
// mutates a Classification once it is made.
func classifiedCopy(from object.Object, to object.Object) object.Object {
	source, ok := from.(*object.Bytes)
	if !ok || source.Classified == nil {
		return to
	}
	if target, ok := to.(*object.Bytes); ok {
		target.Classified = source.Classified
	}
	return to
}

// RecordRelease returns an unmarked copy of classified plaintext and records
// that it was released: record_release(buffer, reason).
func RecordRelease(args ...object.Object) object.Object {
	op := BuiltinNameRecordRelease
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	buffer, ok := args[0].(*object.Bytes)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `%s` must be BYTES, got %s", op, args[0].Type()))
	}
	reasonArg, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	reason := strings.TrimSpace(reasonArg)
	if reason == "" {
		return resultAndError(nil, newError("%s: a release must state a reason; it is the only account the "+
			"case will have of why plaintext left the protection it was read under", op))
	}
	if errObj := custodyDocumentName(op, "reason", reason); errObj != nil {
		return resultAndError(nil, errObj)
	}
	if buffer.Classified == nil {
		// Nothing to release, and said so: a copy would be indistinguishable
		// from a release, and the timeline would record one that did not
		// happen.
		return resultAndError(nil, newError("%s: this buffer carries no classification, so there is nothing "+
			"to release. Only plaintext read by record_read or record_read_partial, and the context of a "+
			"record_search hit, is marked", op))
	}

	custodyStore.Lock()
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		custodyStore.Unlock()
		return resultAndError(nil, newError("%s: a release is recorded in the case timeline, and no case is "+
			"open to record it in. Open one with `case_open(id, examiner)`", op))
	}
	now := custodyNow()
	c := buffer.Classified
	// A class the open case cannot name is recorded by its tag, never as an
	// empty name that would read as no class at all.
	classes := make([]string, len(c.Tags))
	for i, tag := range c.Tags {
		classes[i] = "unnamed:" + tag
		if i < len(c.Labels) && c.Labels[i] != "" {
			classes[i] = c.Labels[i]
		}
	}
	session.appendEvent(now, op, fmt.Sprintf("released %s: %s", DescribeClassified(buffer), reason), map[string]any{
		"record_uid": c.RecordUID,
		"classes":    strings.Join(classes, ", "),
		"tags":       strings.Join(c.Tags, ","),
		"bytes":      int64(len(buffer.Value)),
		"reason":     reason,
	})
	custodyStore.Unlock()

	released := make([]byte, len(buffer.Value))
	copy(released, buffer.Value)
	return resultAndError(&object.Bytes{Value: released}, nil)
}
