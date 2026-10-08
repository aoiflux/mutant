package builtin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"mutant/object"

	lua "github.com/yuin/gopher-lua"
)

// luaScriptTimeout bounds one lua_run_string / lua_run_file / lua_run_http
// call, from the first instruction of the chunk to its last.
//
// It is measured on the clock by the calling goroutine, which is the only
// place it can be measured. gopher-lua consults the context it is given at a
// VM instruction boundary, and a Lua pattern search runs entirely inside one
// Go function call, where there is no boundary to reach: `string.find` over a
// few hundred bytes with `.-.-.-b` costs about fifteen times more for every
// doubling of the subject and never once asks whether its deadline has
// passed. A sandbox the host documents as the containment for an untrusted
// script has to bound the host's wait whatever the script does.
//
//mutant:limit duration
const luaScriptTimeout = 5 * time.Second

// luaRepeatResultMax bounds how large a string string.rep may build inside
// the sandbox.
//
// It is the one call that turns a short script into a large input, and a large
// input is what makes a backtracking pattern expensive. The deadline above
// bounds how long the host waits; this bounds the work the host is left
// holding after it stops waiting, because an abandoned chunk keeps running
// until its current library call returns.
//
// maxBuiltinResultBytes is the same idea for a Mutant builtin whose result
// size the script picks outright, and is four times this. The sandbox gets the
// tighter number because its scripts are the ones the host documents as
// untrusted -- lua_run_http runs whatever a server chose to return -- and
// because the size of the subject is what decides whether a pattern search
// ends this afternoon.
//
//mutant:limit bytes
const luaRepeatResultMax = 8 * 1024 * 1024

func LuaRunString(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	code, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `lua_run_string` must be STRING, got %s", args[0].Type()))
	}

	return resultAndError(runLuaSource(code.Value, "builtin:lua_run_string"), nil)
}

func LuaRunFile(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	path, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `lua_run_file` must be STRING, got %s", args[0].Type()))
	}

	content, err := os.ReadFile(path.Value)
	if err != nil {
		return resultAndError(nil, newError("lua_run_file: %s", err.Error()))
	}

	return resultAndError(runLuaSource(string(content), "builtin:lua_run_file"), nil)
}

func LuaRunHTTP(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	url, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `lua_run_http` must be STRING, got %s", args[0].Type()))
	}

	client, err := httpClient()
	if err != nil {
		return resultAndError(nil, newError("lua_run_http: %s", err.Error()))
	}
	resp, err := client.Get(url.Value)
	if err != nil {
		return resultAndError(nil, newError("lua_run_http: %s", err.Error()))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resultAndError(nil, newError("lua_run_http: %s", err.Error()))
	}

	return resultAndError(runLuaSource(string(body), "builtin:lua_run_http"), nil)
}

func runLuaSource(source string, stage string) object.Object {
	state := lua.NewState(lua.Options{SkipOpenLibs: true})
	if state == nil {
		return luaResultHash("", fmt.Errorf("failed to initialize lua state"))
	}

	var printBuffer bytes.Buffer

	loadSafeLuaLibraries(state)
	registerCapturedPrint(state, &printBuffer)
	registerMutantLuaAPI(state, stage)

	fn, err := state.Load(bytes.NewReader([]byte(source)), stage)
	if err != nil {
		state.Close()
		return luaResultHash("", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), luaScriptTimeout)
	defer cancel()
	state.SetContext(ctx)

	// The chunk runs on its own goroutine and this one waits on the clock.
	//
	// state.SetContext is kept because it is what makes an abandoned chunk
	// stop: the next instruction boundary it reaches sees the cancelled
	// context and unwinds. What it cannot do is bound the wait, since a
	// backtracking pattern search reaches no boundary at all. Everything that
	// touches the state -- the call, the result off the stack, the captured
	// print output, and Close -- stays on the goroutine that owns it, so
	// returning early here frees nothing the chunk is still reading.
	done := make(chan object.Object, 1)
	go func() {
		defer state.Close()

		state.Push(fn)
		if callErr := state.PCall(0, 1, nil); callErr != nil {
			done <- luaResultHash("", callErr)
			return
		}
		done <- luaChunkResult(state, &printBuffer)
	}()

	select {
	case result := <-done:
		return result
	case <-ctx.Done():
		return luaResultHash("", fmt.Errorf("%s: the script did not finish within %s and was abandoned", stage, luaScriptTimeout))
	}
}

// luaChunkResult reads what the chunk left behind: the value it returned, or
// failing that whatever it printed. It runs on the goroutine that owns the
// state, after a PCall that returned without error.
func luaChunkResult(state *lua.LState, printBuffer *bytes.Buffer) object.Object {
	resultValue := state.Get(-1)
	result, hasResult := luaValueToString(resultValue)
	state.Pop(1)

	if resultValue == lua.LNil {
		captured := strings.TrimRight(printBuffer.String(), "\r\n")
		if captured != "" {
			return luaResultHash(captured, nil)
		}
		return luaResultHash("nil", nil)
	}

	if !hasResult {
		captured := strings.TrimRight(printBuffer.String(), "\r\n")
		if captured != "" {
			return luaResultHash(captured, nil)
		}
		return luaResultHash("", nil)
	}

	return luaResultHash(result, nil)
}

func loadSafeLuaLibraries(state *lua.LState) {
	lua.OpenBase(state)
	lua.OpenMath(state)
	lua.OpenString(state)
	lua.OpenTable(state)
	lua.OpenOs(state)
	// Note: io is deliberately NOT opened — it exposes arbitrary host file
	// read/write. Scripts that need controlled input use mutant.read_file.

	// Remove globals that allow loading/evaluating arbitrary code, and the io
	// library (in case a future base lib pulls it in).
	unsafeNames := []string{"debug", "package", "require", "dofile", "load", "loadfile", "loadstring", "collectgarbage", "io"}
	for _, name := range unsafeNames {
		state.SetGlobal(name, lua.LNil)
	}

	// OpenOs also exposes host-affecting calls: command execution, process exit
	// (which would bypass the PCall context timeout), filesystem mutation, and
	// environment access. Strip them so `os` keeps only safe time/date helpers.
	if osTable, ok := state.GetGlobal("os").(*lua.LTable); ok {
		for _, name := range []string{"execute", "exit", "remove", "rename", "setenv", "getenv", "tmpname"} {
			state.SetField(osTable, name, lua.LNil)
		}
	}

	if stringTable, ok := state.GetGlobal("string").(*lua.LTable); ok {
		state.SetField(stringTable, "rep", state.NewFunction(boundedStringRep))
	}
}

// boundedStringRep stands in for string.rep and refuses to build more than
// luaRepeatResultMax bytes.
//
// It replaces the library function rather than wrapping it, because the check
// has to happen before the allocation: a wrapper that called through would
// have handed gopher-lua the very multiplication it is there to stop. The
// behaviour is otherwise Lua 5.1's -- a count of zero or less is the empty
// string, not an error.
//
// A refusal is a Lua error, so the script sees it and `result["ok"]` is false.
// Returning a shorter string would be worse than the limit it enforces: a
// script that asked for eight million bytes and silently got eight thousand
// goes on to measure, hash or compare the wrong thing.
func boundedStringRep(l *lua.LState) int {
	str := l.CheckString(1)
	count := l.CheckInt(2)

	if count <= 0 || len(str) == 0 {
		l.Push(lua.LString(""))
		return 1
	}
	// Division rather than multiplication: count * len(str) is exactly the
	// overflow this is here to prevent.
	if count > luaRepeatResultMax/len(str) {
		l.RaiseError("string.rep: %d copies of %d bytes is over the sandbox's %d-byte limit", count, len(str), luaRepeatResultMax)
		return 0
	}

	l.Push(lua.LString(strings.Repeat(str, count)))
	return 1
}

func registerMutantLuaAPI(state *lua.LState, stage string) {
	mutantTable := state.NewTable()

	state.SetField(mutantTable, "patch_name", state.NewFunction(func(l *lua.LState) int {
		l.Push(lua.LString(stage))
		return 1
	}))

	state.SetField(mutantTable, "version", state.NewFunction(func(l *lua.LState) int {
		l.Push(lua.LString("2.1.0"))
		return 1
	}))

	state.SetField(mutantTable, "read_file", state.NewFunction(func(l *lua.LState) int {
		path := l.CheckString(1)
		data, err := os.ReadFile(path)
		if err != nil {
			l.Push(lua.LNil)
			l.Push(lua.LString(err.Error()))
			return 2
		}

		l.Push(lua.LString(string(data)))
		l.Push(lua.LNil)
		return 2
	}))

	state.SetGlobal("mutant", mutantTable)
}

func registerCapturedPrint(state *lua.LState, output *bytes.Buffer) {
	state.SetGlobal("print", state.NewFunction(func(l *lua.LState) int {
		top := l.GetTop()
		parts := make([]string, 0, top)
		for i := 1; i <= top; i++ {
			text, _ := luaValueToString(l.Get(i))
			parts = append(parts, text)
		}

		output.WriteString(strings.Join(parts, "\t"))
		output.WriteByte('\n')
		return 0
	}))
}

func luaValueToString(value lua.LValue) (string, bool) {
	switch v := value.(type) {
	case lua.LString:
		return string(v), true
	case lua.LBool:
		if bool(v) {
			return "true", true
		}
		return "false", true
	case lua.LNumber:
		return strconv.FormatFloat(float64(v), 'g', -1, 64), true
	case *lua.LNilType:
		return "nil", true
	case *lua.LTable:
		return "<table>", true
	case *lua.LFunction:
		return "<function>", true
	case *lua.LUserData:
		return "<userdata>", true
	case *lua.LState:
		return "<thread>", true
	default:
		return v.String(), true
	}
}

func luaResultHash(result string, err error) object.Object {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	return makeHashObject(map[string]object.Object{
		"ok":             boolObj(err == nil),
		"result":         stringObj(result),
		"error":          stringObj(errMsg),
		"schema_version": intObj(1),
	})
}
