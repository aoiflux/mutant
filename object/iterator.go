package object

import "sort"

// Iterator is the cursor a `for (x in xs)` loop holds while it runs.
//
// It is a runtime object rather than compiler bookkeeping because the loop has
// to survive `break`, `continue`, a `return` out of the middle, and a nested
// loop over the same collection -- all of which the stack already handles for
// ordinary values. It is deliberately not reachable from a program: no literal
// makes one, no builtin returns one, and Inspect says so plainly in case one
// ever escapes onto the stack where a value was expected.
//
// Keys and values are materialised up front. For an array that costs nothing
// (the elements are already a slice); for a hash it is what makes the order
// definite, which decision 5 requires.
type Iterator struct {
	Keys   []Object
	Values []Object
	Index  int

	// KeyIsPrimary says which half a one-binding loop gets. A single binding
	// yields the thing the collection is made of, and that is the element for
	// an array, a string or a buffer, but the key for a hash -- `for (k in h)`
	// reads as the keys, as it does everywhere else. The compiler cannot decide
	// this, because what is being iterated is not known until the loop runs.
	KeyIsPrimary bool
}

// Primary returns the single value a one-binding loop binds.
func (it *Iterator) Primary(key, value Object) Object {
	if it.KeyIsPrimary {
		return key
	}
	return value
}

func (it *Iterator) Type() ObjectType { return ITERATOR_OBJ }

func (it *Iterator) Inspect() string { return "<iterator>" }

// Next returns the next key and value, and false once the iterator is spent.
func (it *Iterator) Next() (Object, Object, bool) {
	if it == nil || it.Index >= len(it.Values) {
		return nil, nil, false
	}
	key, value := it.Keys[it.Index], it.Values[it.Index]
	it.Index++
	return key, value, true
}

// NewIterator builds the cursor for one collection, or reports that the value
// cannot be iterated.
//
// The four cases are the four things a program here actually loops over. A
// string yields characters and bytes yields integers, which is the same
// distinction the bytes type was introduced to make: iterating text by byte
// would hand back half a rune, and iterating a buffer by rune would hand back
// U+FFFD for every byte that is not valid UTF-8.
func NewIterator(over Object) (*Iterator, bool) {
	switch src := over.(type) {
	case *Array:
		keys := make([]Object, len(src.Elements))
		for i := range src.Elements {
			keys[i] = &Integer{Value: int64(i)}
		}
		return &Iterator{Keys: keys, Values: src.Elements}, true

	case *Hash:
		pairs := make([]HashPair, 0, len(src.Pairs))
		for _, pair := range src.Pairs {
			pairs = append(pairs, pair)
		}
		// The same comparison Hash.Inspect uses, so a program that prints a
		// hash and a program that loops over it agree about its order. Ranging
		// the map directly would give a different order on every run.
		sort.Slice(pairs, func(i, j int) bool { return hashKeyLess(pairs[i].Key, pairs[j].Key) })

		keys := make([]Object, len(pairs))
		values := make([]Object, len(pairs))
		for i, pair := range pairs {
			keys[i], values[i] = pair.Key, pair.Value
		}
		return &Iterator{Keys: keys, Values: values, KeyIsPrimary: true}, true

	case *String:
		runes := []rune(src.Value)
		keys := make([]Object, len(runes))
		values := make([]Object, len(runes))
		for i, r := range runes {
			keys[i] = &Integer{Value: int64(i)}
			values[i] = &String{Value: string(r)}
		}
		return &Iterator{Keys: keys, Values: values}, true

	case *Bytes:
		keys := make([]Object, len(src.Value))
		values := make([]Object, len(src.Value))
		for i, b := range src.Value {
			keys[i] = &Integer{Value: int64(i)}
			values[i] = &Integer{Value: int64(b)}
		}
		return &Iterator{Keys: keys, Values: values}, true
	}

	return nil, false
}
