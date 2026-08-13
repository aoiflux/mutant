package builtin

import (
	"fmt"
	"strings"
	"unicode"

	"mutant/object"
)

func StrUpper(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("str_upper", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(strings.ToUpper(s))
}

func StrLower(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("str_lower", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(strings.ToLower(s))
}

func StrTrim(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("str_trim", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(strings.TrimSpace(s))
}

func StrTrimLeft(args ...object.Object) object.Object {
	s, cutset, errObj := strTwoStringArgs("str_trim_left", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(strings.TrimLeft(s, cutset))
}

func StrTrimRight(args ...object.Object) object.Object {
	s, cutset, errObj := strTwoStringArgs("str_trim_right", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(strings.TrimRight(s, cutset))
}

func StrTrimPrefix(args ...object.Object) object.Object {
	s, prefix, errObj := strTwoStringArgs("str_trim_prefix", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(strings.TrimPrefix(s, prefix))
}

func StrTrimSuffix(args ...object.Object) object.Object {
	s, suffix, errObj := strTwoStringArgs("str_trim_suffix", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(strings.TrimSuffix(s, suffix))
}

func StrStartsWith(args ...object.Object) object.Object {
	s, prefix, errObj := strTwoStringArgs("str_starts_with", args)
	if errObj != nil {
		return errObj
	}
	return boolObj(strings.HasPrefix(s, prefix))
}

func StrEndsWith(args ...object.Object) object.Object {
	s, suffix, errObj := strTwoStringArgs("str_ends_with", args)
	if errObj != nil {
		return errObj
	}
	return boolObj(strings.HasSuffix(s, suffix))
}

func StrJoin(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	arr, ok := args[0].(*object.Array)
	if !ok {
		return newError("argument 1 to `str_join` must be ARRAY, got %s", args[0].Type())
	}
	sep, errObj := requireStringArg("str_join", args[1], 2)
	if errObj != nil {
		return errObj
	}
	parts := make([]string, len(arr.Elements))
	for i, el := range arr.Elements {
		s, ok := el.(*object.String)
		if !ok {
			return newError("argument 1 to `str_join` must be an ARRAY of STRING; element %d is %s", i, el.Type())
		}
		parts[i] = s.Value
	}
	return stringObj(strings.Join(parts, sep))
}

func StrRepeat(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	s, errObj := requireStringArg("str_repeat", args[0], 1)
	if errObj != nil {
		return errObj
	}
	n, errObj := requireIntArg("str_repeat", args[1], 2)
	if errObj != nil {
		return errObj
	}
	if n < 0 {
		return newError("argument 2 to `str_repeat` must be non-negative, got %d", n)
	}
	return stringObj(strings.Repeat(s, int(n)))
}

func StrPadLeft(args ...object.Object) object.Object {
	return strPad("str_pad_left", args, true)
}

func StrPadRight(args ...object.Object) object.Object {
	return strPad("str_pad_right", args, false)
}

func StrReverse(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("str_reverse", args)
	if errObj != nil {
		return errObj
	}
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return stringObj(string(runes))
}

func StrSubstr(args ...object.Object) object.Object {
	if len(args) != 3 {
		return newError("wrong number of arguments. got=%d, want=3", len(args))
	}
	s, errObj := requireStringArg("str_substr", args[0], 1)
	if errObj != nil {
		return errObj
	}
	start, errObj := requireIntArg("str_substr", args[1], 2)
	if errObj != nil {
		return errObj
	}
	length, errObj := requireIntArg("str_substr", args[2], 3)
	if errObj != nil {
		return errObj
	}
	if start < 0 || length < 0 {
		return newError("arguments to `str_substr` must be non-negative")
	}
	// rune-aware, with clamping so out-of-range requests return what exists.
	runes := []rune(s)
	if start > int64(len(runes)) {
		start = int64(len(runes))
	}
	end := start + length
	if end > int64(len(runes)) {
		end = int64(len(runes))
	}
	return stringObj(string(runes[start:end]))
}

func StrCharAt(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	s, errObj := requireStringArg("str_char_at", args[0], 1)
	if errObj != nil {
		return errObj
	}
	idx, errObj := requireIntArg("str_char_at", args[1], 2)
	if errObj != nil {
		return errObj
	}
	runes := []rune(s)
	if idx < 0 || idx >= int64(len(runes)) {
		return newError("argument 2 to `str_char_at` index %d out of range (len=%d)", idx, len(runes))
	}
	return stringObj(string(runes[idx]))
}

func StrFormat(args ...object.Object) object.Object {
	if len(args) == 0 {
		return newError("wrong number of arguments. got=0, want=1 or more")
	}
	format, errObj := requireStringArg("str_format", args[0], 1)
	if errObj != nil {
		return errObj
	}
	vals := make([]any, 0, len(args)-1)
	for _, arg := range args[1:] {
		switch v := arg.(type) {
		case *object.Integer:
			vals = append(vals, v.Value)
		case *object.Float:
			vals = append(vals, v.Value)
		case *object.String:
			vals = append(vals, v.Value)
		case *object.Boolean:
			vals = append(vals, v.Value)
		default:
			vals = append(vals, v.Inspect())
		}
	}
	return stringObj(fmt.Sprintf(format, vals...))
}

func StrTitle(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("str_title", args)
	if errObj != nil {
		return errObj
	}
	prevIsSep := true
	titled := strings.Map(func(r rune) rune {
		if prevIsSep && unicode.IsLetter(r) {
			prevIsSep = false
			return unicode.ToTitle(r)
		}
		prevIsSep = !unicode.IsLetter(r) && !unicode.IsNumber(r)
		return r
	}, s)
	return stringObj(titled)
}

// --- shared helpers for this file ---

func strOneStringArg(op string, args []object.Object) (string, *object.Error) {
	if len(args) != 1 {
		return "", newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	return requireStringArg(op, args[0], 1)
}

func strTwoStringArgs(op string, args []object.Object) (string, string, *object.Error) {
	if len(args) != 2 {
		return "", "", newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	a, errObj := requireStringArg(op, args[0], 1)
	if errObj != nil {
		return "", "", errObj
	}
	b, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return "", "", errObj
	}
	return a, b, nil
}

func strPad(op string, args []object.Object, left bool) object.Object {
	if len(args) != 3 {
		return newError("wrong number of arguments. got=%d, want=3", len(args))
	}
	s, errObj := requireStringArg(op, args[0], 1)
	if errObj != nil {
		return errObj
	}
	width, errObj := requireIntArg(op, args[1], 2)
	if errObj != nil {
		return errObj
	}
	pad, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return errObj
	}
	if pad == "" {
		return newError("argument 3 to `%s` (pad) must be non-empty", op)
	}
	runes := []rune(s)
	if int64(len(runes)) >= width {
		return stringObj(s)
	}
	needed := int(width) - len(runes)
	padRunes := []rune(pad)
	fill := make([]rune, 0, needed)
	for len(fill) < needed {
		fill = append(fill, padRunes...)
	}
	fill = fill[:needed]
	if left {
		return stringObj(string(fill) + s)
	}
	return stringObj(s + string(fill))
}
