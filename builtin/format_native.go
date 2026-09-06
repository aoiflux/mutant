package builtin

import (
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"time"

	"mutant/object"
)

// The bridge between Go's `any` and Mutant values, shared by every format
// family that decodes into an untyped tree: YAML, TOML, CBOR, MessagePack, and
// the CSV/XML/NDJSON helpers that build one on the way past.
//
// One bridge rather than six was the whole point. Each decoder hands back the
// same handful of Go kinds, and writing the conversion once means a []byte
// becomes a BYTES buffer in every format that has a binary type, a timestamp
// renders the same way whether it came out of YAML or TOML, and a value that
// cannot be represented fails with one message instead of six.
//
// json.go keeps its own pair. JSON's decoder is configured to hand back
// json.Number and its encoder has to spell a buffer as hex, so the two have
// almost nothing in common beyond the shape; merging them would mean a bridge
// full of format flags.

const (
	// maxNativeDepth bounds how deep a decoded tree may nest before conversion
	// gives up.
	//
	// Every decoder here is pointed at evidence, and evidence is written by
	// whoever is under investigation. A deeply-nested document is the cheapest
	// possible way to blow a Go stack -- conversion is recursive, and a few
	// hundred bytes of input can describe a hundred thousand levels. The
	// underlying libraries mostly bound this themselves (CBOR defaults to 32
	// levels); this is the backstop for the ones that do not.
	maxNativeDepth = 256
	// maxNativeNodes bounds total values produced from one document, so a
	// small input cannot expand into an unbounded number of Mutant objects.
	maxNativeNodes = 1 << 22
)

// nativeCounter carries the node budget down a conversion.
type nativeCounter struct{ remaining int }

func (c *nativeCounter) take() error {
	c.remaining--
	if c.remaining < 0 {
		return fmt.Errorf("document expands past %d values", maxNativeNodes)
	}
	return nil
}

// nativeToObject converts a decoded Go value into a Mutant value.
func nativeToObject(value any) (object.Object, error) {
	return convertNative(value, 0, &nativeCounter{remaining: maxNativeNodes})
}

func convertNative(value any, depth int, budget *nativeCounter) (object.Object, error) {
	if depth > maxNativeDepth {
		return nil, fmt.Errorf("document nests deeper than %d levels", maxNativeDepth)
	}
	if err := budget.take(); err != nil {
		return nil, err
	}

	switch v := value.(type) {
	case nil:
		return &object.Null{}, nil
	case bool:
		return boolObj(v), nil
	case string:
		return stringObj(v), nil

	// A byte slice is a buffer, not text. This is why L-4 had to land before
	// this item: CBOR, MessagePack and YAML's !!binary all distinguish bytes
	// from strings, and before there was a BYTES type the distinction had
	// nowhere to go.
	case []byte:
		return &object.Bytes{Value: v}, nil

	case int:
		return intObj(int64(v)), nil
	case int8:
		return intObj(int64(v)), nil
	case int16:
		return intObj(int64(v)), nil
	case int32:
		return intObj(int64(v)), nil
	case int64:
		return intObj(v), nil
	case uint:
		return uintToObject(uint64(v)), nil
	case uint8:
		return intObj(int64(v)), nil
	case uint16:
		return intObj(int64(v)), nil
	case uint32:
		return intObj(int64(v)), nil
	case uint64:
		return uintToObject(v), nil
	case float32:
		return floatObj(float64(v)), nil
	case float64:
		return floatObj(v), nil

	// A big integer is out of range for the VM's signed 64-bit integer by
	// definition, so it is rendered as its decimal text rather than truncated.
	// CBOR tags 2 and 3 produce these, and a certificate serial silently
	// reduced to its low 64 bits is exactly the kind of wrong answer this
	// language must not give.
	case big.Int:
		return stringObj(v.String()), nil
	case *big.Int:
		if v == nil {
			return &object.Null{}, nil
		}
		return stringObj(v.String()), nil

	// YAML timestamps and TOML datetimes arrive already parsed. They render in
	// RFC 3339 with nanoseconds, which is what the time_ and timestamp_
	// families read back.
	case time.Time:
		return stringObj(v.UTC().Format(time.RFC3339Nano)), nil

	case []any:
		elements := make([]object.Object, 0, len(v))
		for _, item := range v {
			converted, err := convertNative(item, depth+1, budget)
			if err != nil {
				return nil, err
			}
			elements = append(elements, converted)
		}
		return &object.Array{Elements: elements}, nil

	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		pairs := make([]object.HashPair, 0, len(v))
		for _, key := range keys {
			converted, err := convertNative(v[key], depth+1, budget)
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, object.HashPair{Key: stringObj(key), Value: converted})
		}
		return hashFromPairs(pairs)

	// CBOR and YAML both allow non-string mapping keys, and CBOR's COSE profile
	// uses integer keys throughout -- so a decoder that only accepted string
	// keys would fail on the signed objects it most needs to read.
	case map[any]any:
		pairs := make([]object.HashPair, 0, len(v))
		for key, item := range v {
			keyObj, err := nativeKeyToObject(key)
			if err != nil {
				return nil, err
			}
			converted, err := convertNative(item, depth+1, budget)
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, object.HashPair{Key: keyObj, Value: converted})
		}
		sortHashPairsByInspect(pairs)
		return hashFromPairs(pairs)

	default:
		return nil, fmt.Errorf("unsupported decoded value of Go type %T", value)
	}
}

// uintToObject keeps an unsigned value honest when it will not fit the VM's
// signed integer, rather than wrapping it into a negative number.
func uintToObject(v uint64) object.Object {
	if v > math.MaxInt64 {
		return stringObj(strconv.FormatUint(v, 10))
	}
	return intObj(int64(v))
}

// nativeKeyToObject converts a mapping key. Mutant hashes accept STRING,
// INTEGER and BOOLEAN keys; anything else is named in the error rather than
// stringified, because a key quietly turned into text collides with a real key
// of that spelling.
func nativeKeyToObject(key any) (object.Object, error) {
	switch k := key.(type) {
	case string:
		return stringObj(k), nil
	case bool:
		return boolObj(k), nil
	case int:
		return intObj(int64(k)), nil
	case int8:
		return intObj(int64(k)), nil
	case int16:
		return intObj(int64(k)), nil
	case int32:
		return intObj(int64(k)), nil
	case int64:
		return intObj(k), nil
	case uint:
		return uintKeyToObject(uint64(k))
	case uint8:
		return intObj(int64(k)), nil
	case uint16:
		return intObj(int64(k)), nil
	case uint32:
		return intObj(int64(k)), nil
	case uint64:
		return uintKeyToObject(k)
	default:
		return nil, fmt.Errorf("mapping key of Go type %T cannot be a Mutant hash key (STRING, INTEGER and BOOLEAN can)", key)
	}
}

func uintKeyToObject(v uint64) (object.Object, error) {
	if v > math.MaxInt64 {
		return nil, fmt.Errorf("mapping key %d does not fit a Mutant INTEGER", v)
	}
	return intObj(int64(v)), nil
}

// hashFromPairs builds a Hash, refusing a duplicate key rather than letting the
// last one win silently.
func hashFromPairs(pairs []object.HashPair) (object.Object, error) {
	out := make(map[object.HashKey]object.HashPair, len(pairs))
	for _, pair := range pairs {
		hashable, ok := pair.Key.(object.Hashable)
		if !ok {
			return nil, fmt.Errorf("%s is not usable as a hash key", pair.Key.Type())
		}
		key := hashable.HashKey()
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("duplicate key %s", pair.Key.Inspect())
		}
		out[key] = pair
	}
	return &object.Hash{Pairs: out}, nil
}

func sortHashPairsByInspect(pairs []object.HashPair) {
	sort.SliceStable(pairs, func(i, j int) bool {
		return pairs[i].Key.Inspect() < pairs[j].Key.Inspect()
	})
}

// objectToNative converts a Mutant value into the Go value an encoder wants.
//
// rawBytes says what happens to a BYTES buffer: formats with a binary type
// (CBOR, MessagePack) take the slice; formats without one (YAML, TOML) take its
// hex, matching Inspect and json_stringify so a buffer renders the same way
// wherever it is written.
func objectToNative(obj object.Object, rawBytes bool) (any, error) {
	return convertToNative(obj, rawBytes, 0)
}

func convertToNative(obj object.Object, rawBytes bool, depth int) (any, error) {
	if depth > maxNativeDepth {
		return nil, fmt.Errorf("value nests deeper than %d levels", maxNativeDepth)
	}

	switch v := obj.(type) {
	case nil:
		return nil, nil
	case *object.Null:
		return nil, nil
	case *object.String:
		return v.Value, nil
	case *object.Bytes:
		if rawBytes {
			return v.Value, nil
		}
		return v.Inspect(), nil
	case *object.Integer:
		return v.Value, nil
	case *object.Float:
		return v.Value, nil
	case *object.Boolean:
		return v.Value, nil
	case *object.Array:
		out := make([]any, 0, len(v.Elements))
		for _, el := range v.Elements {
			converted, err := convertToNative(el, rawBytes, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, converted)
		}
		return out, nil
	case *object.Hash:
		out := make(map[string]any, len(v.Pairs))
		for _, pair := range v.Pairs {
			key, err := nativeKeyText(pair.Key)
			if err != nil {
				return nil, err
			}
			if _, exists := out[key]; exists {
				return nil, fmt.Errorf("two keys render as %q", key)
			}
			converted, err := convertToNative(pair.Value, rawBytes, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	case *object.Struct:
		out := make(map[string]any, len(v.Fields))
		for name, field := range v.Fields {
			converted, err := convertToNative(field, rawBytes, depth+1)
			if err != nil {
				return nil, err
			}
			out[name] = converted
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported value type: %s", obj.Type())
	}
}

// nativeKeyText renders a hash key as the string key these formats require at
// the top of a mapping. An INTEGER or BOOLEAN key is spelled the way the
// language prints it; anything else is refused by name.
func nativeKeyText(key object.Object) (string, error) {
	switch k := key.(type) {
	case *object.String:
		return k.Value, nil
	case *object.Integer:
		return strconv.FormatInt(k.Value, 10), nil
	case *object.Boolean:
		return strconv.FormatBool(k.Value), nil
	default:
		return "", fmt.Errorf("hash key must be STRING, INTEGER or BOOLEAN, got %s", key.Type())
	}
}
