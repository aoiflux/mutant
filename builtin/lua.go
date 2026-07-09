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

	resp, err := httpClient.Get(url.Value)
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
	defer state.Close()

	var printBuffer bytes.Buffer

	loadSafeLuaLibraries(state)
	registerCapturedPrint(state, &printBuffer)
	registerMutantLuaAPI(state, stage)

	fn, err := state.Load(bytes.NewReader([]byte(source)), stage)
	if err != nil {
		return luaResultHash("", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state.SetContext(ctx)

	state.Push(fn)
	err = state.PCall(0, 1, nil)
	if err != nil {
		return luaResultHash("", err)
	}

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
	lua.OpenIo(state)

	unsafeNames := []string{"debug", "package", "require", "dofile", "load", "loadfile", "loadstring", "collectgarbage"}
	for _, name := range unsafeNames {
		state.SetGlobal(name, lua.LNil)
	}
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
