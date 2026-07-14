package object

type ObjectType string

const (
	FLOAT_OBJ        = "FLOAT"
	INTEGER_OBJ      = "INTEGER"
	BOOLEAN_OBJ      = "BOOLEAN"
	NULL_OBJ         = "NULL"
	RETURN_VALUE_OBJ = "RETURN_VALUE"
	MULTI_VALUE_OBJ  = "MULTI_VALUE"
	ERROR_OBJ        = "ERROR_OBJ"
	FUNCTION_OBJ     = "FUNCTION"
	STRING_OBJ       = "STRING"
	BUILTIN_OBJ      = "BUILTIN"
	ARRAY_OBJ        = "ARRAY"
	HASH_OBJ         = "HASH"
	QUOTE_OBJ        = "QUOTE"
	MACRO_OBJ        = "MACRO"
	COMPILED_FN_OBJ  = "COMPILED_FN_OBJ"
	CLOSURE_OBJ      = "CLOSURE"
	ENCRYPTED_OBJ    = "ENCRYPTED"
	STRUCT_OBJ       = "STRUCT"
	ENUM_VALUE_OBJ   = "ENUM_VALUE"
	BREAK_OBJ        = "BREAK"
	CONTINUE_OBJ     = "CONTINUE"
	LUA_PATCH_OBJ    = "LUA_PATCH"
)

type Object interface {
	Type() ObjectType
	Inspect() string
}
