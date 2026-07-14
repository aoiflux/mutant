package builtin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"mutant/object"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

func HttpGet(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	url, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `http_get` must be STRING, got %s", args[0].Type()))
	}
	resp, err := httpClient.Get(url.Value)
	return httpResponseOrError2(resp, err, "http_get")
}

func HttpPost(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	url, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `http_post` must be STRING, got %s", args[0].Type()))
	}
	body, errObj := httpBodyString(args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	contentType, ok := args[2].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `http_post` must be STRING, got %s", args[2].Type()))
	}
	resp, err := httpClient.Post(url.Value, contentType.Value, strings.NewReader(body))
	return httpResponseOrError2(resp, err, "http_post")
}

func HttpRequest(args ...object.Object) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	method, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `http_request` must be STRING, got %s", args[0].Type()))
	}
	url, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `http_request` must be STRING, got %s", args[1].Type()))
	}
	body, errObj := httpBodyString(args[2])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	headers, errObj := httpHeaderMap(args[3])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	req, err := http.NewRequest(strings.ToUpper(method.Value), url.Value, strings.NewReader(body))
	if err != nil {
		return resultAndError(nil, newError("http_request: %s", err.Error()))
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	return httpResponseOrError2(resp, err, "http_request")
}

func httpHeaderMap(obj object.Object) (map[string]string, *object.Error) {
	switch v := obj.(type) {
	case *object.Hash:
		result := make(map[string]string, len(v.Pairs))
		for _, pair := range v.Pairs {
			keyObj, ok := pair.Key.(*object.String)
			if !ok {
				return nil, newError("argument 4 to `http_request` must have STRING header keys, got %s", pair.Key.Type())
			}
			result[keyObj.Value] = pair.Value.Inspect()
		}
		return result, nil
	case *object.Struct:
		result := make(map[string]string, len(v.Fields))
		for k, val := range v.Fields {
			result[k] = val.Inspect()
		}
		return result, nil
	default:
		return nil, newError("argument 4 to `http_request` must be HASH or STRUCT, got %s", obj.Type())
	}
}

func httpBodyString(obj object.Object) (string, *object.Error) {
	switch v := obj.(type) {
	case *object.String:
		return v.Value, nil
	case *object.Hash, *object.Struct:
		payload, err := httpJSONBody(obj)
		if err != nil {
			return "", newError("argument body could not be converted to JSON: %s", err.Error())
		}
		return payload, nil
	default:
		return "", newError("argument body must be STRING, HASH, or STRUCT, got %s", obj.Type())
	}
}

func httpJSONBody(obj object.Object) (string, error) {
	value, err := objectToGoValue(obj)
	if err != nil {
		return "", err
	}
	bytes, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func objectToGoValue(obj object.Object) (any, error) {
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
			goVal, err := objectToGoValue(el)
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
			goVal, err := objectToGoValue(pair.Value)
			if err != nil {
				return nil, err
			}
			m[k.Value] = goVal
		}
		return m, nil
	case *object.Struct:
		m := make(map[string]any, len(v.Fields))
		for k, field := range v.Fields {
			goVal, err := objectToGoValue(field)
			if err != nil {
				return nil, err
			}
			m[k] = goVal
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unsupported body field type for JSON: %s", obj.Type())
	}
}

func httpResponseOrError(resp *http.Response, err error) object.Object {
	if err != nil {
		return httpErrorResult(err)
	}
	defer resp.Body.Close()

	rawBody, readErr := io.ReadAll(resp.Body)
	bodyStr := ""
	if readErr == nil {
		bodyStr = string(rawBody)
	}

	// Build headers Hash
	headerPairs := make(map[string]object.Object, len(resp.Header))
	for k, vals := range resp.Header {
		headerPairs[k] = stringObj(strings.Join(vals, ", "))
	}

	return makeHashObject(map[string]object.Object{
		"status":  intObj(int64(resp.StatusCode)),
		"body":    stringObj(bodyStr),
		"headers": makeHashObject(headerPairs),
		"error":   stringObj(""),
	})
}

func httpErrorResult(err error) object.Object {
	return makeHashObject(map[string]object.Object{
		"status":  intObj(0),
		"body":    stringObj(""),
		"headers": makeHashObject(map[string]object.Object{}),
		"error":   stringObj(err.Error()),
	})
}

func httpResponseOrError2(resp *http.Response, err error, opName string) object.Object {
	if err != nil {
		return resultAndError(httpErrorResult(err), newError("%s: %s", opName, err.Error()))
	}

	result := httpResponseOrError(resp, nil)
	hash, ok := result.(*object.Hash)
	if !ok {
		return resultAndError(result, nil)
	}

	errValueObj, ok := hashValueByStringKey(hash, "error")
	if !ok {
		return resultAndError(hash, nil)
	}
	errStr, ok := errValueObj.(*object.String)
	if !ok || errStr.Value == "" {
		return resultAndError(hash, nil)
	}

	return resultAndError(hash, newError("%s: %s", opName, errStr.Value))
}

func hashValueByStringKey(hash *object.Hash, key string) (object.Object, bool) {
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		return nil, false
	}
	return pair.Value, true
}
