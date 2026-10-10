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

	shell := security.DefaultShellName()
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

// ExecArgv runs a program with exactly the arguments given and no shell in
// between.
//
// It is the companion to exec_string rather than a replacement for it. Where
// exec_string knows the flags for the shells it names and gives any other name
// the command with -c, this one knows nothing and interprets nothing: the
// caller writes the invocation out, which is what makes a shell whose flag is
// not -c reachable at all.
//
// Every element is required to be a string rather than converted to one. A
// number or a hash in an argv is a mistake in the script, and converting it
// would run a command the author did not write.
func ExecArgv(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	argvArg, ok := args[0].(*object.Array)
	if !ok {
		return resultAndError(nil, newError("argument to `exec_argv` at position=1 must be ARRAY, got %s", args[0].Type()))
	}
	if len(argvArg.Elements) == 0 {
		return resultAndError(nil, newError("argument to `exec_argv` at position=1 must hold at least the program to run"))
	}

	argv := make([]string, 0, len(argvArg.Elements))
	for i, element := range argvArg.Elements {
		value, isString := element.(*object.String)
		if !isString {
			return resultAndError(nil, newError("argument to `exec_argv` at position=1 index=%d must be STRING, got %s", i, element.Type()))
		}
		argv = append(argv, value.Value)
	}
	if strings.TrimSpace(argv[0]) == "" {
		return resultAndError(nil, newError("argument to `exec_argv` at position=1 index=0 must name the program to run"))
	}

	result := security.ExecuteArgv(argv, "builtin:exec_argv")
	return resultAndError(commandResultHash(result), nil)
}

func CmdBuilder(args ...object.Object) object.Object {
	if len(args) > 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0 or 1", len(args)))
	}

	shell := security.DefaultShellName()
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

	// Joined by the package that knows what the shell name means, because the
	// separator is not the same for every shell: cmd.exe reads its command from
	// a command line and a command line ends at the first newline, so a
	// "\n"-joined builder ran line one and dropped the rest while the result
	// said ok (M26-NET-018).
	command := security.JoinShellLines(builder.shell, builder.lines)
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
		"ok":             boolObj(result.ErrorMessage == "" && !result.TimedOut && result.ExitCode == 0),
		"exit_code":      intObj(int64(result.ExitCode)),
		"stdout":         stringObj(result.Stdout),
		"stderr":         stringObj(result.Stderr),
		"timed_out":      boolObj(result.TimedOut),
		"error":          stringObj(result.ErrorMessage),
		"schema_version": intObj(1),
	})
}
