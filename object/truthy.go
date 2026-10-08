package object

// IsTruthy is what this language means by a value counting as true.
//
// There is one rule, and it is here because there were two. The same switch with
// the same comment was written separately in vm/vm.go and evaluator/evaluator.go,
// and `!` -- the operator whose entire job is to negate it -- consulted neither.
// `if`, `while`, `for`, `match`, `&&`, `||` and filter asked their own package's
// copy. `!` asked a list of three pointers in the VM and a rendered string in the
// evaluator, and answered false to anything it did not recognise. So 0 was falsy
// and !0 was falsy too: `if (x)` and `if (!x)` both skipped their branch, and !!x
// was not x (M26-VM-007).
//
// The rule itself is not new and not changed. false, null, the empty string, an
// empty buffer, 0 and 0.0 are falsy; everything else is truthy, including [], {},
// a function and an error value. What is new is that it is stated once.
// object.NumericInfix, object.BitwiseNot and object.IndexOf are in this package for
// the same reason: two engines implementing one semantic will drift, and the only
// fix that holds is for there to be one implementation to read.
//
// nil is falsy, and that arm is not defensive padding -- it is a decision with an
// authority. eval returns a Go nil for a function body that produces no value, and
// the VM's answer for the same call is NULL, which is falsy. Leaving nil to the
// default arm made the tree-walker call such a call truthy while the VM called it
// falsy, so `if (f())` depended on which engine ran it. The VM is the production
// engine; its answer is the one kept.
func IsTruthy(obj Object) bool {
	switch o := obj.(type) {
	case nil:
		return false
	case *Boolean:
		return o.Value
	case *Null:
		return false
	case *String:
		return len(o.Value) != 0
	case *Bytes:
		return len(o.Value) != 0
	case *Integer:
		return o.Value != 0
	case *Float:
		return o.Value != 0
	default:
		return true
	}
}
