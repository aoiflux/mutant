package lua

import (
	"fmt"
	"math"

	"mutant/object"

	lua "github.com/yuin/gopher-lua"
)

// APIContext holds Mutant runtime data passed to Lua environment.
// This is the only way Lua patches can interact with Mutant runtime.
type APIContext struct {
	// Globals map holds read-only access to Mutant global variables
	Globals map[string]object.Object

	// PatchName is the name of the executing patch (for logging/debugging)
	PatchName string
}

// RegisterMutantAPI installs the Mutant-specific API into the Lua environment.
// This is the only place where Mutant runtime data is exposed to Lua.
func RegisterMutantAPI(vm *SandboxedVM, ctx *APIContext) error {
	if vm == nil || ctx == nil {
		return fmt.Errorf("vm and context cannot be nil")
	}

	state := vm.GetState()
	if state == nil {
		return fmt.Errorf("sandbox not initialized")
	}

	// Create "mutant" table in Lua
	mutantTable := state.NewTable()

	// Register mutant.get_global(name) - read-only access to Mutant globals
	state.SetField(mutantTable, "get_global", state.NewFunction(func(l *lua.LState) int {
		name := l.CheckString(1)
		if obj, ok := ctx.Globals[name]; ok {
			// Convert object to Lua value
			if objectToLua(l, obj) {
				return 1
			}
		}
		l.Push(lua.LNil)
		return 1
	}))

	// Register mutant.patch_name() - returns current patch name
	state.SetField(mutantTable, "patch_name", state.NewFunction(func(l *lua.LState) int {
		l.Push(lua.LString(ctx.PatchName))
		return 1
	}))

	// Register mutant.can_use_builtin(name) - check if patch has capability
	state.SetField(mutantTable, "can_use_builtin", state.NewFunction(func(l *lua.LState) int {
		l.Push(lua.LBool(true))
		return 1
	}))

	// Register mutant.version() - returns Mutant version for compatibility checks
	state.SetField(mutantTable, "version", state.NewFunction(func(l *lua.LState) int {
		l.Push(lua.LString("2.1.0"))
		return 1
	}))

	// Set mutant table as global
	state.SetGlobal("mutant", mutantTable)

	return nil
}

// objectToLua converts a Mutant object.Object to a Lua value on the stack.
// Returns true if conversion succeeded, false otherwise.
func objectToLua(l *lua.LState, obj object.Object) bool {
	value, ok := objectToLuaValue(obj)
	if !ok {
		return false
	}
	l.Push(value)
	return true
}

func objectToLuaValue(obj object.Object) (lua.LValue, bool) {
	if obj == nil {
		return lua.LNil, true
	}

	switch obj.Type() {
	case object.INTEGER_OBJ:
		intObj := obj.(*object.Integer)
		return lua.LNumber(float64(intObj.Value)), true

	case object.FLOAT_OBJ:
		floatObj := obj.(*object.Float)
		return lua.LNumber(floatObj.Value), true

	case object.BOOLEAN_OBJ:
		boolObj := obj.(*object.Boolean)
		return lua.LBool(boolObj.Value), true

	case object.STRING_OBJ:
		strObj := obj.(*object.String)
		return lua.LString(strObj.Value), true

	// Lua strings are 8-bit clean byte sequences, so a buffer crosses exactly.
	// The conversion back is lossy in the other direction -- a Lua string
	// becomes a Mutant STRING -- but that is the pre-existing shape of this
	// bridge, not something the buffer introduces.
	case object.BYTES_OBJ:
		bytesObj := obj.(*object.Bytes)
		return lua.LString(string(bytesObj.Value)), true

	case object.NULL_OBJ:
		return lua.LNil, true

	case object.ARRAY_OBJ:
		arrObj := obj.(*object.Array)
		table := &lua.LTable{}
		for i, elem := range arrObj.Elements {
			value, ok := objectToLuaValue(elem)
			if !ok {
				value = lua.LNil
			}
			table.RawSetInt(i+1, value)
		}
		return table, true

	case object.HASH_OBJ:
		hashObj := obj.(*object.Hash)
		table := &lua.LTable{}
		for _, pair := range hashObj.Pairs {
			key, ok := objectToLuaValue(pair.Key)
			if !ok {
				key = lua.LNil
			}
			value, ok := objectToLuaValue(pair.Value)
			if !ok {
				value = lua.LNil
			}
			table.RawSet(key, value)
		}
		return table, true

	case object.STRUCT_OBJ:
		structObj := obj.(*object.Struct)
		table := &lua.LTable{}
		for name, value := range structObj.Fields {
			fieldValue, ok := objectToLuaValue(value)
			if !ok {
				fieldValue = lua.LNil
			}
			table.RawSetString(name, fieldValue)
		}
		return table, true

	case object.ENUM_VALUE_OBJ:
		enumObj := obj.(*object.EnumValue)
		table := &lua.LTable{}
		table.RawSetString("_type_name", lua.LString(enumObj.TypeName))
		table.RawSetString("_tag", lua.LString(enumObj.Tag))
		if enumObj.Value != nil {
			value, ok := objectToLuaValue(enumObj.Value)
			if !ok {
				value = lua.LNil
			}
			table.RawSetString("_value", value)
		}
		return table, true

	default:
		// Unsupported types (functions, closures, etc.) cannot be converted
		return nil, false
	}
}

// luaToObject converts a Lua value to a Mutant object.Object.
// Only safe conversions are performed; complex types are rejected.
func luaToObject(l *lua.LState, index int) object.Object {
	return luaToObjectValue(l.Get(index))
}

func luaToObjectValue(value lua.LValue) object.Object {
	switch typed := value.(type) {
	case *lua.LNilType:
		return &object.Null{}

	case lua.LBool:
		return &object.Boolean{Value: bool(typed)}

	case lua.LNumber:
		n := float64(typed)
		if math.Trunc(n) == n {
			return &object.Integer{Value: int64(n)}
		}
		return &object.Float{Value: n}

	case lua.LString:
		return &object.String{Value: string(typed)}

	case *lua.LTable:
		// Convert table to either Array or Hash depending on structure
		// For now, convert to Hash for safety
		hashObj := &object.Hash{Pairs: make(map[object.HashKey]object.HashPair)}
		typed.ForEach(func(k lua.LValue, v lua.LValue) {
			key := luaToObjectValue(k)
			value := luaToObjectValue(v)

			hashKey, ok := key.(object.Hashable)
			if ok {
				pair := object.HashPair{Key: key, Value: value}
				hashObj.Pairs[hashKey.HashKey()] = pair
			}
		})
		return hashObj

	default:
		// Unsupported types return nil
		return &object.Null{}
	}
}
