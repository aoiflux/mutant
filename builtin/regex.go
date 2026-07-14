package builtin

import (
	"regexp"

	"mutant/object"
)

func RegexMatch(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	pattern, input, errObj := regexPatternAndInput("regex_match", args[0], args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return resultAndError(nil, newError("argument 1 to `regex_match` is not a valid regex: %s", err.Error()))
	}

	return resultAndError(boolObj(re.MatchString(input)), nil)
}

func RegexFind(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	pattern, input, errObj := regexPatternAndInput("regex_find", args[0], args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return resultAndError(nil, newError("argument 1 to `regex_find` is not a valid regex: %s", err.Error()))
	}

	match := re.FindString(input)
	if match == "" {
		return resultAndError(globalNullObject(), nil)
	}

	return resultAndError(stringObj(match), nil)
}

func RegexFindAll(args ...object.Object) object.Object {
	if len(args) != 2 && len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}

	pattern, input, errObj := regexPatternAndInput("regex_find_all", args[0], args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	limit := -1
	if len(args) == 3 {
		limitObj, ok := args[2].(*object.Integer)
		if !ok {
			return resultAndError(nil, newError("argument 3 to `regex_find_all` must be INTEGER, got %s", args[2].Type()))
		}
		limit = int(limitObj.Value)
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return resultAndError(nil, newError("argument 1 to `regex_find_all` is not a valid regex: %s", err.Error()))
	}

	matches := re.FindAllString(input, limit)
	elements := make([]object.Object, len(matches))
	for i, match := range matches {
		elements[i] = stringObj(match)
	}

	return resultAndError(&object.Array{Elements: elements}, nil)
}

func RegexReplace(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	pattern, input, errObj := regexPatternAndInput("regex_replace", args[0], args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	replacementObj, ok := args[2].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `regex_replace` must be STRING, got %s", args[2].Type()))
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return resultAndError(nil, newError("argument 1 to `regex_replace` is not a valid regex: %s", err.Error()))
	}

	return resultAndError(stringObj(re.ReplaceAllString(input, replacementObj.Value)), nil)
}

func RegexCaptureGroups(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	pattern, input, errObj := regexPatternAndInput("regex_capture_groups", args[0], args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return resultAndError(nil, newError("argument 1 to `regex_capture_groups` is not a valid regex: %s", err.Error()))
	}

	capture := re.FindStringSubmatch(input)
	if capture == nil {
		return resultAndError(&object.Array{Elements: []object.Object{}}, nil)
	}

	elements := make([]object.Object, len(capture))
	for i, value := range capture {
		elements[i] = stringObj(value)
	}

	return resultAndError(&object.Array{Elements: elements}, nil)
}

func regexPatternAndInput(opName string, patternObj object.Object, inputObj object.Object) (string, string, *object.Error) {
	pattern, ok := patternObj.(*object.String)
	if !ok {
		return "", "", newError("argument 1 to `%s` must be STRING, got %s", opName, patternObj.Type())
	}

	input, ok := inputObj.(*object.String)
	if !ok {
		return "", "", newError("argument 2 to `%s` must be STRING, got %s", opName, inputObj.Type())
	}

	return pattern.Value, input.Value, nil
}

func globalNullObject() object.Object {
	return &object.Null{}
}
