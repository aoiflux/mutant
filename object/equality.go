package object

import "bytes"

// ValuesEqual reports whether two values are the same value.
//
// It is the one definition of "equal" for a value against another value, and
// deliberately not the whole of `==`. Each engine reaches `==` through its own
// comparison function, and those decide what an operand type admits before any
// of this is asked: whether `<` has a meaning, whether a type mismatch is an
// error or a false, which numeric promotions apply. What they do not each need
// to re-derive is when two values of one type hold the same thing -- and nor
// does a builtin asking that same question of an array's elements.
//
// Two rules hold throughout.
//
// A value is never equal to a value of another type. Comparing rendered forms
// is the fallback at the bottom, and it is how a string spelling `P { a: 1 }`
// came to be equal to the struct spelling it. The type guard decides, not the
// render.
//
// There is no numeric promotion here: the integer 1 is not the float 1.0. That
// is already what `contains`, `index_of` and `unique` answer, and widening it
// would silently reclassify an element a program had been told was absent. `==`
// does promote, through each engine's numeric path, which never arrives here.
func ValuesEqual(a, b Object) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Type() != b.Type() {
		return false
	}

	// The Type() guard above already rules out a mismatch, so each case below
	// asserts twice over. The second assertion is what keeps a type that one
	// day shares an ObjectType with another from panicking inside `==`.
	switch av := a.(type) {
	case *Integer:
		bv, ok := b.(*Integer)
		return ok && av.Value == bv.Value
	case *Float:
		bv, ok := b.(*Float)
		return ok && av.Value == bv.Value
	case *String:
		bv, ok := b.(*String)
		return ok && av.Value == bv.Value
	case *Boolean:
		bv, ok := b.(*Boolean)
		return ok && av.Value == bv.Value
	case *Null:
		return true
	case *Bytes:
		// Contents only. The Classified mark records where a buffer came from
		// rather than what it holds, and the VM's execBytesComparison ignores
		// it for the same reason.
		bv, ok := b.(*Bytes)
		return ok && bytes.Equal(av.Value, bv.Value)
	case *Struct:
		bv, ok := b.(*Struct)
		return ok && av.Equals(bv)
	case *EnumValue:
		// A variant identifies itself by type and tag. The payload is the
		// ordinal, which both engines already leave out of the comparison.
		bv, ok := b.(*EnumValue)
		return ok && av.TypeName == bv.TypeName && av.Tag == bv.Tag
	case *Error:
		bv, ok := b.(*Error)
		return ok && av.Equals(bv)
	default:
		// Arrays and hashes land here. Both render in a stable order -- an
		// array has one of its own, and Hash.Inspect sorts its keys -- so
		// comparing their renders is an answer rather than a coin toss. It is
		// still the weaker answer: two renders can agree where the values do
		// not, which is what walking them element by element would catch.
		return a.Inspect() == b.Inspect()
	}
}
