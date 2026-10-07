package vm

// What the runtime prints about a value, and the one thing it must not print.
//
// Three places render a value for a person rather than for a program: a
// traceback's arguments, the debugger's variables pane, and the value a
// finished program is echoed as. None of them is a builtin call, so none goes
// through builtin.refuseClassified, and until now none of them asked whether
// what it was about to print had been read out of a classified record.
//
// They also did not ask it in four slightly different ways. renderArgValue and
// renderDebugValue were the same twenty lines twice, differing only in the cap,
// which is why a fix applied to one of them would have left the other leaking.
// There is one renderer here and both call it.

import (
	"strings"

	"mutant/builtin"
	"mutant/object"
)

// renderForDisplay renders one runtime value on one line, capped at limit, with
// a classified buffer named rather than shown.
//
// The classified check runs before anything is rendered, and not inside the
// type switch below, because the leak was never only the direct case. Four
// shapes reach Inspect without ever being an *object.Bytes: a cell (which is
// what a captured variable lives in), an array or hash holding the buffer, a
// struct field, and an error carrying it in Related. Each of those renders the
// buffer through the buffer's own Inspect, and a buffer's Inspect is its entire
// hex -- so guarding the *object.Bytes branch alone would have closed the one
// case that leaked least. The cell leaked most: 23 bytes of plaintext against
// the direct case's 12, because the bytes(N) prefix a preview spends its budget
// on is not there.
func renderForDisplay(value object.Object, limit int) string {
	if value == nil {
		return "<unset>"
	}

	// The same walk the sinks use, so there is one answer to "does this hold
	// classified plaintext" and a container shape added to one is added to
	// both. A value too deeply nested to check is not rendered either: the
	// sinks refuse one for the same reason, and a guard that gives up in the
	// permissive direction is not a guard.
	// Neither notice is capped, and that is deliberate. The cap is there to
	// bound a value whose size the program chose -- a buffer, a long string, a
	// deep array -- and a notice about a value that was not printed is bounded
	// by construction: a fixed sentence, a record uid and a class name. Capping
	// it cost the one thing it exists to say, because at the traceback's 48
	// characters `<31 bytes of plaintext read from record rec-0ea1, classified
	// "pii">` truncates to `...read from record rec-0...`, which names no
	// record. Both renderers therefore show the whole notice, which also makes
	// a traceback line and a pane row say exactly the same thing.
	if found, deep := builtin.FindClassified(value); found != nil {
		return "<" + builtin.DescribeClassified(found) + ">"
	} else if deep {
		return "<too deeply nested to check for classified plaintext>"
	}

	// Bytes renders as full hex deliberately, because Inspect doubles as the
	// identity function for equality and deduplication. A display is the one
	// caller that only ever wanted a preview, so it asks for one rather than
	// materialising a megabyte of hex to then cut it back.
	if buf, ok := value.(*object.Bytes); ok {
		return buf.Preview(limit / 4)
	}

	text := capped(strings.Join(strings.Fields(value.Inspect()), " "), limit)
	if text == "" {
		return string(value.Type())
	}
	return text
}

// capped shortens text to limit, truncating rather than summarising so that
// what is shown is a prefix of what is there.
func capped(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	if limit < 4 {
		return text[:limit]
	}
	return text[:limit-3] + "..."
}

// unwrapForDisplay turns a stored object into the value it stands for: with the
// cell a captured local lives in taken off, and then decrypted.
//
// The order is the whole of it. A cell is a storage location rather than a
// value, and mutil.DecryptObject hands one back by pointer without touching
// what is inside, because OpSetFree writes through it and a copy would lose the
// write. So decrypting a cell returns the same cell, still holding ciphertext,
// and Cell.Inspect renders that: a traceback printed a parameter an inner
// function closed over as `n=[153 72 150 254 248 119 238 27]` where n was 2999,
// and the bytes differed run to run, so the traceback was not reproducible
// either (M26-VM-024). Taking the cell off first and decrypting what was inside
// it is what the debugger already did; the traceback did not, and now both go
// through this.
func (vm *VM) unwrapForDisplay(raw object.Object) object.Object {
	if raw == nil {
		return nil
	}
	if cell, ok := raw.(*object.Cell); ok {
		if cell.Value == nil {
			return nil
		}
		raw = cell.Value
	}
	return vm.decryptForUse(raw)
}
