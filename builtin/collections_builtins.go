package builtin

import (
	"sort"

	"mutant/object"
)

// objectsEqual compares two objects by value for scalars, falling back to
// Inspect() for composite types.
func objectsEqual(a, b object.Object) bool {
	if a.Type() != b.Type() {
		return false
	}
	switch av := a.(type) {
	case *object.Integer:
		return av.Value == b.(*object.Integer).Value
	case *object.Float:
		return av.Value == b.(*object.Float).Value
	case *object.String:
		return av.Value == b.(*object.String).Value
	case *object.Boolean:
		return av.Value == b.(*object.Boolean).Value
	case *object.Null:
		return true
	default:
		return a.Inspect() == b.Inspect()
	}
}

func requireArrayArg(op string, arg object.Object, pos int) (*object.Array, *object.Error) {
	arr, ok := arg.(*object.Array)
	if !ok {
		return nil, newError("argument %d to `%s` must be ARRAY, got %s", pos, op, arg.Type())
	}
	return arr, nil
}

func requireHashArg(op string, arg object.Object, pos int) (*object.Hash, *object.Error) {
	h, ok := arg.(*object.Hash)
	if !ok {
		return nil, newError("argument %d to `%s` must be HASH, got %s", pos, op, arg.Type())
	}
	return h, nil
}

// --- array operations ---

func Sort(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	arr, errObj := requireArrayArg(BuiltinNameSort, args[0], 1)
	if errObj != nil {
		return errObj
	}
	out := make([]object.Object, len(arr.Elements))
	copy(out, arr.Elements)
	if len(out) < 2 {
		return &object.Array{Elements: out}
	}

	allNumeric, allString := true, true
	for _, el := range out {
		switch el.(type) {
		case *object.Integer, *object.Float:
			allString = false
		case *object.String:
			allNumeric = false
		default:
			allNumeric, allString = false, false
		}
	}
	switch {
	case allNumeric:
		sort.SliceStable(out, func(i, j int) bool { return numericValue(out[i]) < numericValue(out[j]) })
	case allString:
		sort.SliceStable(out, func(i, j int) bool {
			return out[i].(*object.String).Value < out[j].(*object.String).Value
		})
	default:
		return newError("sort: array must be all numbers or all strings")
	}
	return &object.Array{Elements: out}
}

func numericValue(o object.Object) float64 {
	switch v := o.(type) {
	case *object.Integer:
		return float64(v.Value)
	case *object.Float:
		return v.Value
	default:
		return 0
	}
}

func ReverseArray(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	arr, errObj := requireArrayArg(BuiltinNameReverseArray, args[0], 1)
	if errObj != nil {
		return errObj
	}
	out := make([]object.Object, len(arr.Elements))
	for i, el := range arr.Elements {
		out[len(arr.Elements)-1-i] = el
	}
	return &object.Array{Elements: out}
}

func Contains(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	arr, errObj := requireArrayArg(BuiltinNameContains, args[0], 1)
	if errObj != nil {
		return errObj
	}
	for _, el := range arr.Elements {
		if objectsEqual(el, args[1]) {
			return boolObj(true)
		}
	}
	return boolObj(false)
}

func IndexOf(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	arr, errObj := requireArrayArg(BuiltinNameIndexOf, args[0], 1)
	if errObj != nil {
		return errObj
	}
	for i, el := range arr.Elements {
		if objectsEqual(el, args[1]) {
			return intObj(int64(i))
		}
	}
	return intObj(-1)
}

func Slice(args ...object.Object) object.Object {
	if len(args) != 3 {
		return newError("wrong number of arguments. got=%d, want=3", len(args))
	}
	arr, errObj := requireArrayArg(BuiltinNameSlice, args[0], 1)
	if errObj != nil {
		return errObj
	}
	start, errObj := requireIntArg(BuiltinNameSlice, args[1], 2)
	if errObj != nil {
		return errObj
	}
	end, errObj := requireIntArg(BuiltinNameSlice, args[2], 3)
	if errObj != nil {
		return errObj
	}
	n := int64(len(arr.Elements))
	if start < 0 {
		start = 0
	}
	if end > n {
		end = n
	}
	if start > end {
		return &object.Array{Elements: []object.Object{}}
	}
	out := make([]object.Object, end-start)
	copy(out, arr.Elements[start:end])
	return &object.Array{Elements: out}
}

func Concat(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	a, errObj := requireArrayArg(BuiltinNameConcat, args[0], 1)
	if errObj != nil {
		return errObj
	}
	b, errObj := requireArrayArg(BuiltinNameConcat, args[1], 2)
	if errObj != nil {
		return errObj
	}
	out := make([]object.Object, 0, len(a.Elements)+len(b.Elements))
	out = append(out, a.Elements...)
	out = append(out, b.Elements...)
	return &object.Array{Elements: out}
}

func Flatten(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	arr, errObj := requireArrayArg(BuiltinNameFlatten, args[0], 1)
	if errObj != nil {
		return errObj
	}
	out := make([]object.Object, 0, len(arr.Elements))
	for _, el := range arr.Elements {
		if inner, ok := el.(*object.Array); ok {
			out = append(out, inner.Elements...)
		} else {
			out = append(out, el)
		}
	}
	return &object.Array{Elements: out}
}

func Unique(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	arr, errObj := requireArrayArg(BuiltinNameUnique, args[0], 1)
	if errObj != nil {
		return errObj
	}
	seen := make(map[string]struct{}, len(arr.Elements))
	out := make([]object.Object, 0, len(arr.Elements))
	for _, el := range arr.Elements {
		key := string(el.Type()) + "\x00" + el.Inspect()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, el)
	}
	return &object.Array{Elements: out}
}

func Range(args ...object.Object) object.Object {
	if len(args) != 2 && len(args) != 3 {
		return newError("wrong number of arguments. got=%d, want=2 or 3", len(args))
	}
	start, errObj := requireIntArg(BuiltinNameRange, args[0], 1)
	if errObj != nil {
		return errObj
	}
	end, errObj := requireIntArg(BuiltinNameRange, args[1], 2)
	if errObj != nil {
		return errObj
	}
	step := int64(1)
	if len(args) == 3 {
		step, errObj = requireIntArg(BuiltinNameRange, args[2], 3)
		if errObj != nil {
			return errObj
		}
	}
	if step == 0 {
		return newError("range: step must not be zero")
	}
	const maxRange = 10_000_000
	out := make([]object.Object, 0)
	if step > 0 {
		for i := start; i < end; i += step {
			out = append(out, intObj(i))
			if len(out) > maxRange {
				return newError("range: exceeds maximum length %d", maxRange)
			}
		}
	} else {
		for i := start; i > end; i += step {
			out = append(out, intObj(i))
			if len(out) > maxRange {
				return newError("range: exceeds maximum length %d", maxRange)
			}
		}
	}
	return &object.Array{Elements: out}
}

func Zip(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	a, errObj := requireArrayArg(BuiltinNameZip, args[0], 1)
	if errObj != nil {
		return errObj
	}
	b, errObj := requireArrayArg(BuiltinNameZip, args[1], 2)
	if errObj != nil {
		return errObj
	}
	n := len(a.Elements)
	if len(b.Elements) < n {
		n = len(b.Elements)
	}
	out := make([]object.Object, n)
	for i := 0; i < n; i++ {
		out[i] = &object.Array{Elements: []object.Object{a.Elements[i], b.Elements[i]}}
	}
	return &object.Array{Elements: out}
}

// --- hash operations ---

func hashSortedPairs(h *object.Hash) []object.HashPair {
	pairs := make([]object.HashPair, 0, len(h.Pairs))
	for _, p := range h.Pairs {
		pairs = append(pairs, p)
	}
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].Key.Inspect() < pairs[j].Key.Inspect() })
	return pairs
}

func Keys(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	h, errObj := requireHashArg(BuiltinNameKeys, args[0], 1)
	if errObj != nil {
		return errObj
	}
	pairs := hashSortedPairs(h)
	out := make([]object.Object, len(pairs))
	for i, p := range pairs {
		out[i] = p.Key
	}
	return &object.Array{Elements: out}
}

func Values(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	h, errObj := requireHashArg(BuiltinNameValues, args[0], 1)
	if errObj != nil {
		return errObj
	}
	pairs := hashSortedPairs(h)
	out := make([]object.Object, len(pairs))
	for i, p := range pairs {
		out[i] = p.Value
	}
	return &object.Array{Elements: out}
}

func Entries(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	h, errObj := requireHashArg(BuiltinNameEntries, args[0], 1)
	if errObj != nil {
		return errObj
	}
	pairs := hashSortedPairs(h)
	out := make([]object.Object, len(pairs))
	for i, p := range pairs {
		out[i] = &object.Array{Elements: []object.Object{p.Key, p.Value}}
	}
	return &object.Array{Elements: out}
}

func hashableKey(op string, key object.Object) (object.HashKey, *object.Error) {
	hashable, ok := key.(object.Hashable)
	if !ok {
		return object.HashKey{}, newError("`%s` key must be a hashable type (STRING/INTEGER/FLOAT/BOOLEAN), got %s", op, key.Type())
	}
	return hashable.HashKey(), nil
}

func HasKey(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	h, errObj := requireHashArg(BuiltinNameHasKey, args[0], 1)
	if errObj != nil {
		return errObj
	}
	hk, errObj := hashableKey(BuiltinNameHasKey, args[1])
	if errObj != nil {
		return errObj
	}
	_, ok := h.Pairs[hk]
	return boolObj(ok)
}

func Get(args ...object.Object) object.Object {
	if len(args) != 3 {
		return newError("wrong number of arguments. got=%d, want=3 (hash, key, default)", len(args))
	}
	h, errObj := requireHashArg(BuiltinNameGet, args[0], 1)
	if errObj != nil {
		return errObj
	}
	hk, errObj := hashableKey(BuiltinNameGet, args[1])
	if errObj != nil {
		return errObj
	}
	if pair, ok := h.Pairs[hk]; ok {
		return pair.Value
	}
	return args[2]
}

func Set(args ...object.Object) object.Object {
	if len(args) != 3 {
		return newError("wrong number of arguments. got=%d, want=3 (hash, key, value)", len(args))
	}
	h, errObj := requireHashArg(BuiltinNameSet, args[0], 1)
	if errObj != nil {
		return errObj
	}
	hk, errObj := hashableKey(BuiltinNameSet, args[1])
	if errObj != nil {
		return errObj
	}
	pairs := make(map[object.HashKey]object.HashPair, len(h.Pairs)+1)
	for k, v := range h.Pairs {
		pairs[k] = v
	}
	pairs[hk] = object.HashPair{Key: args[1], Value: args[2]}
	return &object.Hash{Pairs: pairs}
}

func Merge(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	a, errObj := requireHashArg(BuiltinNameMerge, args[0], 1)
	if errObj != nil {
		return errObj
	}
	b, errObj := requireHashArg(BuiltinNameMerge, args[1], 2)
	if errObj != nil {
		return errObj
	}
	pairs := make(map[object.HashKey]object.HashPair, len(a.Pairs)+len(b.Pairs))
	for k, v := range a.Pairs {
		pairs[k] = v
	}
	for k, v := range b.Pairs {
		pairs[k] = v
	}
	return &object.Hash{Pairs: pairs}
}

func Delete(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	h, errObj := requireHashArg(BuiltinNameDelete, args[0], 1)
	if errObj != nil {
		return errObj
	}
	hk, errObj := hashableKey(BuiltinNameDelete, args[1])
	if errObj != nil {
		return errObj
	}
	pairs := make(map[object.HashKey]object.HashPair, len(h.Pairs))
	for k, v := range h.Pairs {
		if k == hk {
			continue
		}
		pairs[k] = v
	}
	return &object.Hash{Pairs: pairs}
}
