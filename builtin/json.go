package builtin

import (
	"encoding/json"
	"fmt"
	"strings"

	"mutant/object"
)

func JsonStringify(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}

	value, err := objectToJSONValue(args[0])
	if err != nil {
		return newError("argument to `json_stringify` could not be converted to JSON: %s", err.Error())
	}

	bytes, err := json.Marshal(value)
	if err != nil {
		return newError("argument to `json_stringify` could not be converted to JSON: %s", err.Error())
	}

	return stringObj(string(bytes))
}

func JsonParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}

	input, ok := args[0].(*object.String)
	if !ok {
		return newError("argument to `json_parse` must be STRING, got %s", args[0].Type())
	}

	decoder := json.NewDecoder(strings.NewReader(input.Value))
	decoder.UseNumber()

	var raw any
	if err := decoder.Decode(&raw); err != nil {
		return newError("argument to `json_parse` is not valid JSON: %s", err.Error())
	}

	parsed, err := jsonValueToObject(raw)
	if err != nil {
		return newError("argument to `json_parse` could not be converted to Mutant object: %s", err.Error())
	}

	return parsed
}

func objectToJSONValue(obj object.Object) (any, error) {
	switch v := obj.(type) {
	case *object.String:
		return v.Value, nil
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
			f, fErr := v.Float64()
			if fErr != nil {
				return nil, err
			}
			return &object.Float{Value: f}, nil
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
