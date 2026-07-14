package builtin

import (
	"strings"

	"mutant/object"
	"mutant/security"
)

func ExecString(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	commandArg, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `exec_string` at position=1 must be STRING, got %s", args[0].Type()))
	}

	shell := "powershell"
	if len(args) == 2 {
		shellArg, isString := args[1].(*object.String)
		if !isString {
			return resultAndError(nil, newError("argument to `exec_string` at position=2 must be STRING, got %s", args[1].Type()))
		}
		shell = shellArg.Value
	}

	result := security.ExecuteCommand(shell, commandArg.Value, "builtin:exec_string")
	return resultAndError(commandResultHash(result), nil)
}

func CmdBuilder(args ...object.Object) object.Object {
	if len(args) > 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0 or 1", len(args)))
	}

	shell := "powershell"
	if len(args) == 1 {
		shellArg, ok := args[0].(*object.String)
		if !ok {
			return resultAndError(nil, newError("argument to `cmd_builder` at position=1 must be STRING, got %s", args[0].Type()))
		}
		shell = shellArg.Value
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"shell": stringObj(shell),
		"lines": &object.Array{Elements: []object.Object{}},
	}), nil)
}

func CmdAdd(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	builder, errObj := decodeBuilder(args[0])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	lineArg, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `cmd_add` at position=2 must be STRING, got %s", args[1].Type()))
	}

	builder.lines = append(builder.lines, lineArg.Value)
	return resultAndError(encodeBuilder(builder), nil)
}

func CmdRun(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	builder, errObj := decodeBuilder(args[0])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if len(builder.lines) == 0 {
		return resultAndError(nil, newError("argument to `cmd_run` has no lines to execute"))
	}

	command := strings.Join(builder.lines, "\n")
	result := security.ExecuteCommand(builder.shell, command, "builtin:cmd_run")
	return resultAndError(commandResultHash(result), nil)
}

type commandBuilder struct {
	shell string
	lines []string
}

func decodeBuilder(input object.Object) (commandBuilder, *object.Error) {
	hash, ok := input.(*object.Hash)
	if !ok {
		return commandBuilder{}, newError("argument to command builder must be HASH, got %s", input.Type())
	}

	shellObj := hashValueByKey(hash, "shell")
	if shellObj == nil {
		return commandBuilder{}, newError("command builder missing key `shell`")
	}
	shellString, ok := shellObj.(*object.String)
	if !ok {
		return commandBuilder{}, newError("command builder key `shell` must be STRING, got %s", shellObj.Type())
	}

	linesObj := hashValueByKey(hash, "lines")
	if linesObj == nil {
		return commandBuilder{}, newError("command builder missing key `lines`")
	}
	linesArray, ok := linesObj.(*object.Array)
	if !ok {
		return commandBuilder{}, newError("command builder key `lines` must be ARRAY, got %s", linesObj.Type())
	}

	lines := make([]string, 0, len(linesArray.Elements))
	for i, element := range linesArray.Elements {
		line, isString := element.(*object.String)
		if !isString {
			return commandBuilder{}, newError("command builder line at index=%d must be STRING, got %s", i, element.Type())
		}
		lines = append(lines, line.Value)
	}

	return commandBuilder{shell: shellString.Value, lines: lines}, nil
}

func encodeBuilder(builder commandBuilder) object.Object {
	lineObjects := make([]object.Object, len(builder.lines))
	for i, line := range builder.lines {
		lineObjects[i] = stringObj(line)
	}

	return makeHashObject(map[string]object.Object{
		"shell": stringObj(builder.shell),
		"lines": &object.Array{Elements: lineObjects},
	})
}

func hashValueByKey(hash *object.Hash, key string) object.Object {
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		return nil
	}
	return pair.Value
}

func commandResultHash(result security.CommandResult) object.Object {
	return makeHashObject(map[string]object.Object{
		"ok":              boolObj(result.Allowed && result.ErrorMessage == "" && !result.TimedOut && result.ExitCode == 0),
		"allowed":         boolObj(result.Allowed),
		"policy_decision": stringObj(result.PolicyDecision),
		"exit_code":       intObj(int64(result.ExitCode)),
		"stdout":          stringObj(result.Stdout),
		"stderr":          stringObj(result.Stderr),
		"timed_out":       boolObj(result.TimedOut),
		"error":           stringObj(result.ErrorMessage),
		"schema_version":  intObj(1),
	})
}
