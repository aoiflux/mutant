package builtin

import (
	"encoding/json"
	"strings"
	"testing"

	"mutant/object"
)

func TestJsonStringifyHash(t *testing.T) {
	input := makeHashObject(map[string]object.Object{
		"name":  stringObj("mutant"),
		"count": intObj(3),
		"flags": &object.Array{Elements: []object.Object{boolObj(true), boolObj(false)}},
	})

	result := JsonStringify(input)

	str, ok := result.(*object.String)
	if !ok {
		t.Fatalf("json_stringify() result is not String. got=%T", result)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(str.Value), &decoded); err != nil {
		t.Fatalf("json_stringify output is not valid JSON: %v", err)
	}

	if decoded["name"] != "mutant" {
		t.Fatalf("unexpected name field: %v", decoded["name"])
	}
}

func TestJsonParseObject(t *testing.T) {
	result := JsonParse(&object.String{Value: `{"name":"mutant","count":3,"enabled":true}`})

	hash, ok := result.(*object.Hash)
	if !ok {
		t.Fatalf("json_parse() result is not Hash. got=%T", result)
	}

	name, ok := hashValueByKey(hash, "name").(*object.String)
	if !ok {
		t.Fatalf("name field is not String. got=%T", hashValueByKey(hash, "name"))
	}
	if name.Value != "mutant" {
		t.Fatalf("unexpected name value: %q", name.Value)
	}

	count, ok := hashValueByKey(hash, "count").(*object.Integer)
	if !ok {
		t.Fatalf("count field is not Integer. got=%T", hashValueByKey(hash, "count"))
	}
	if count.Value != 3 {
		t.Fatalf("unexpected count value: %d", count.Value)
	}

	enabled, ok := hashValueByKey(hash, "enabled").(*object.Boolean)
	if !ok {
		t.Fatalf("enabled field is not Boolean. got=%T", hashValueByKey(hash, "enabled"))
	}
	if !enabled.Value {
		t.Fatalf("unexpected enabled value: %t", enabled.Value)
	}
}

func TestJsonParseInvalidInput(t *testing.T) {
	result := JsonParse(&object.String{Value: `{"name":`})

	errObj, ok := result.(*object.Error)
	if !ok {
		t.Fatalf("json_parse() result is not Error. got=%T", result)
	}

	if !strings.Contains(errObj.Message, "not valid JSON") {
		t.Fatalf("unexpected error message: %q", errObj.Message)
	}
}

func TestJsonStringifyUnsupportedType(t *testing.T) {
	result := JsonStringify(&BuiltIn{Len})

	errObj, ok := result.(*object.Error)
	if !ok {
		t.Fatalf("json_stringify() result is not Error. got=%T", result)
	}

	if !strings.Contains(errObj.Message, "unsupported value type") {
		t.Fatalf("unexpected error message: %q", errObj.Message)
	}
}
