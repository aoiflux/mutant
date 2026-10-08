package builtin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"mutant/object"
)

// maxJSONDepth bounds how deeply arrays and objects may nest in one document.
// It is the bound encoding/json's own decoder applied while these builtins
// used it, kept the same now that they read a document token by token, so
// nothing that parsed before is refused for its depth.
//
//mutant:limit depth
const maxJSONDepth = 10000

func JsonStringify(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	value, err := objectToJSONValue(args[0])
	if err != nil {
		return resultAndError(nil, newError("argument to `json_stringify` could not be converted to JSON: %s", err.Error()))
	}

	bytes, err := json.Marshal(value)
	if err != nil {
		return resultAndError(nil, newError("argument to `json_stringify` could not be converted to JSON: %s", err.Error()))
	}

	return resultAndError(stringObj(string(bytes)), nil)
}

func JsonParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	input, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `json_parse` must be STRING, got %s", args[0].Type()))
	}

	raw, err := decodeJSONDocument(input.Value)
	if err != nil {
		return resultAndError(nil, newError("argument to `json_parse` is not valid JSON: %s", err.Error()))
	}

	parsed, err := jsonValueToObject(raw)
	if err != nil {
		return resultAndError(nil, newError("argument to `json_parse` could not be converted to Mutant object: %s", err.Error()))
	}

	return resultAndError(parsed, nil)
}

// decodeJSONDocument reads exactly one JSON value from text, and refuses three
// things encoding/json lets through without a word:
//
//   - Anything after the value. '{"a":1} {"b":2}' came back as {a: 1}, and a
//     trailing '}' passed ndjson_parse, which says a malformed line fails
//     (M26-DAT-017).
//   - A key written twice in one object, where the library keeps the last
//     copy, so '{"user":"alice","user":"mallory"}' answered mallory and hid
//     alice.
//   - Text the library would change before handing it over: bytes that are
//     not UTF-8, and a \u escape that is half a surrogate pair. Both come
//     back as U+FFFD, a different string from the one in the file.
func decodeJSONDocument(text string) (any, error) {
	if err := jsonTextCheck(text); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	switch token, err := decoder.Token(); {
	// errors.Is rather than ==, matching security/json_tail.go. Go 1.26
	// carries two encoding/json engines and the newer one wraps Token()'s
	// errors, so a bare comparison here would read a genuine end of input
	// as a tail and refuse every well-formed document the day somebody
	// builds with it. The two implementations of this one rule are held to
	// each other by TestTheTwoRepeatedKeyReadersAgree; this is the other
	// half of the same hazard.
	case errors.Is(err, io.EOF):
		return value, nil
	case err != nil:
		return nil, err
	default:
		return nil, fmt.Errorf("%v follows the value; a document holds one value", token)
	}
}

// decodeJSONValue reads one value token by token, so that an object's keys are
// seen as they arrive and a repeated one can be refused.
func decodeJSONValue(decoder *json.Decoder, depth int) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil // a string, a json.Number, a bool or nil
	}
	if depth >= maxJSONDepth {
		return nil, fmt.Errorf("arrays and objects nest deeper than %d levels", maxJSONDepth)
	}
	switch delim {
	case '[':
		items := make([]any, 0)
		for decoder.More() {
			item, err := decodeJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return items, nil
	case '{':
		fields := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("an object key is %v, not a string", keyToken)
			}
			if _, repeated := fields[key]; repeated {
				return nil, fmt.Errorf("the key %q appears twice in one object", key)
			}
			value, err := decodeJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			fields[key] = value
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return fields, nil
	}
	return nil, fmt.Errorf("unexpected %v", delim)
}

// jsonTextCheck refuses JSON text that encoding/json would quietly rewrite: a
// byte that is not UTF-8, or a \u escape naming one half of a UTF-16 surrogate
// pair. Inside a string it tracks escapes exactly as the grammar does, so a
// quote or a backslash that is itself escaped is never taken for structure.
func jsonTextCheck(text string) error {
	if !utf8.ValidString(text) {
		for i := 0; i < len(text); {
			r, width := utf8.DecodeRuneInString(text[i:])
			if r == utf8.RuneError && width == 1 {
				return fmt.Errorf("byte %d is not UTF-8", i)
			}
			i += width
		}
	}
	inString := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if !inString {
			inString = c == '"'
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			unit, ok := jsonEscapeUnit(text, i)
			if !ok {
				i++ // a one-character escape, or a malformed one the decoder names
				continue
			}
			switch {
			case unit >= 0xD800 && unit <= 0xDBFF:
				if low, ok := jsonEscapeUnit(text, i+6); ok && low >= 0xDC00 && low <= 0xDFFF {
					i += 11
					continue
				}
				return fmt.Errorf("the escape %s at byte %d is half of a surrogate pair, which no string can hold", text[i:i+6], i)
			case unit >= 0xDC00 && unit <= 0xDFFF:
				return fmt.Errorf("the escape %s at byte %d is half of a surrogate pair, which no string can hold", text[i:i+6], i)
			}
			i += 5
		}
	}
	return nil
}

// jsonEscapeUnit reads the \uXXXX escape at text[i], if there is one.
func jsonEscapeUnit(text string, i int) (uint64, bool) {
	if i+6 > len(text) || text[i] != '\\' || text[i+1] != 'u' {
		return 0, false
	}
	unit, err := strconv.ParseUint(text[i+2:i+6], 16, 16)
	if err != nil {
		return 0, false
	}
	return unit, true
}

func objectToJSONValue(obj object.Object) (any, error) {
	switch v := obj.(type) {
	case *object.String:
		return v.Value, nil
	// JSON has no binary type, so a buffer is encoded the way it prints: hex.
	// The alternative was to keep erroring on any structure containing one,
	// which would make a bytes unusable in exactly the reports this language
	// exists to produce. Decoding is not symmetric -- json_parse yields the hex
	// string, and string_to_bytes(s, "hex") turns it back.
	case *object.Bytes:
		return v.Inspect(), nil
	case *object.Integer:
		return v.Value, nil
	case *object.Float:
		return v.Value, nil
	case *object.Boolean:
		return v.Value, nil
	case *object.Null:
		return nil, nil
	case *object.Array:
		arr := make([]any, 0, len(v.Elements))
		for _, el := range v.Elements {
			goVal, err := objectToJSONValue(el)
			if err != nil {
				return nil, err
			}
			arr = append(arr, goVal)
		}
		return arr, nil
	case *object.Hash:
		m := make(map[string]any, len(v.Pairs))
		for _, pair := range v.Pairs {
			k, ok := pair.Key.(*object.String)
			if !ok {
				return nil, fmt.Errorf("JSON object keys must be STRING, got %s", pair.Key.Type())
			}
			goVal, err := objectToJSONValue(pair.Value)
			if err != nil {
				return nil, err
			}
			m[k.Value] = goVal
		}
		return m, nil
	case *object.Struct:
		m := make(map[string]any, len(v.Fields))
		for k, field := range v.Fields {
			goVal, err := objectToJSONValue(field)
			if err != nil {
				return nil, err
			}
			m[k] = goVal
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unsupported value type for JSON: %s", obj.Type())
	}
}

func jsonValueToObject(value any) (object.Object, error) {
	switch v := value.(type) {
	case nil:
		return &object.Null{}, nil
	case bool:
		return boolObj(v), nil
	case string:
		return stringObj(v), nil
	case float64:
		return &object.Float{Value: v}, nil
	case json.Number:
		raw := v.String()
		if strings.ContainsAny(raw, ".eE") {
			f, err := v.Float64()
			if err != nil {
				return nil, err
			}
			return &object.Float{Value: f}, nil
		}
		i, err := v.Int64()
		if err != nil {
			// An integer too wide for INTEGER keeps its exact decimal text, as
			// it does from every other decoder here, rather than being rounded
			// into a FLOAT: 18446744073709551615 came back as ...616.0
			// (M26-DAT-018). The decoder has already checked the literal, so
			// the only way Int64 fails is range.
			return stringObj(raw), nil
		}
		return intObj(i), nil
	case []any:
		elements := make([]object.Object, 0, len(v))
		for _, item := range v {
			obj, err := jsonValueToObject(item)
			if err != nil {
				return nil, err
			}
			elements = append(elements, obj)
		}
		return &object.Array{Elements: elements}, nil
	case map[string]any:
		pairs := make(map[string]object.Object, len(v))
		for key, item := range v {
			obj, err := jsonValueToObject(item)
			if err != nil {
				return nil, err
			}
			pairs[key] = obj
		}
		return makeHashObject(pairs), nil
	default:
		return nil, fmt.Errorf("unsupported JSON value type: %T", value)
	}
}
