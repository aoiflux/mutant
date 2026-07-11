package builtin

import (
	"strings"

	"mutant/object"
)

func TextContains(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	haystack, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `text_contains` must be STRING, got %s", args[0].Type()))
	}

	needle, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `text_contains` must be STRING, got %s", args[1].Type()))
	}

	return resultAndError(boolObj(strings.Contains(haystack.Value, needle.Value)), nil)
}

func TextIndex(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	haystack, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `text_index` must be STRING, got %s", args[0].Type()))
	}

	needle, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `text_index` must be STRING, got %s", args[1].Type()))
	}

	return resultAndError(intObj(int64(strings.Index(haystack.Value, needle.Value))), nil)
}

func TextCount(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	haystack, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `text_count` must be STRING, got %s", args[0].Type()))
	}

	needle, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `text_count` must be STRING, got %s", args[1].Type()))
	}

	return resultAndError(intObj(int64(strings.Count(haystack.Value, needle.Value))), nil)
}

func TextSplit(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	input, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `text_split` must be STRING, got %s", args[0].Type()))
	}

	sep, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `text_split` must be STRING, got %s", args[1].Type()))
	}

	parts := strings.Split(input.Value, sep.Value)
	elements := make([]object.Object, len(parts))
	for i, part := range parts {
		elements[i] = stringObj(part)
	}

	return resultAndError(&object.Array{Elements: elements}, nil)
}

func TextReplace(args ...object.Object) object.Object {
	if len(args) != 3 && len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3 or 4", len(args)))
	}

	input, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `text_replace` must be STRING, got %s", args[0].Type()))
	}

	oldValue, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `text_replace` must be STRING, got %s", args[1].Type()))
	}

	newValue, ok := args[2].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `text_replace` must be STRING, got %s", args[2].Type()))
	}

	n := -1
	if len(args) == 4 {
		countObj, ok := args[3].(*object.Integer)
		if !ok {
			return resultAndError(nil, newError("argument 4 to `text_replace` must be INTEGER, got %s", args[3].Type()))
		}
		n = int(countObj.Value)
	}

	return resultAndError(stringObj(strings.Replace(input.Value, oldValue.Value, newValue.Value, n)), nil)
}
