package mutil

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"mutant/compiler"
	"mutant/global"
	"mutant/object"
	"mutant/security"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

func EncryptByteCode(byteCode *compiler.ByteCode, password string) *compiler.ByteCode {
	insLen := len(byteCode.Instructions)

	// If no password provided, derive one from instruction hash for deterministic encryption
	if password == "" {
		derivingPassword := security.DerivePasswordFromInstructions(byteCode.Instructions)
		password = string(rune(derivingPassword)) // Convert to string for consistent handling
	}

	xored, err := security.SecureXOR(byteCode.Instructions, int64(insLen), password)
	if err == nil {
		byteCode.Instructions = xored
	}

	for i := range byteCode.Constants {
		if byteCode.Constants[i].Type() == object.COMPILED_FN_OBJ {
			ins := byteCode.Constants[i].(*object.CompiledFunction).Instructions
			xored, err := security.SecureXOR(ins, int64(insLen), password)
			if err == nil {
				byteCode.Constants[i].(*object.CompiledFunction).Instructions = xored
			}
			continue
		}

		if encConst, err := EncryptObject(byteCode.Constants[i], insLen, password); err == nil {
			byteCode.Constants[i] = encConst
		}
	}

	return byteCode
}

func EncryptObject(obj object.Object, length int, password string) (object.Object, error) {
	if obj == nil {
		return nil, errors.New("nil obj")
	}

	var encObj object.Object
	var err error

	switch obj.Type() {
	case object.ENCRYPTED_OBJ:
		encObj = obj

	case object.INTEGER_OBJ:
		val := obj.(*object.Integer).Value
		bite := make([]byte, 8)
		binary.LittleEndian.PutUint64(bite, uint64(val))
		xored, err := security.SecureXOR(bite, int64(length), password)
		if err != nil {
			return nil, err
		}

		encObj = &object.Encrypted{
			EncType: object.INTEGER_OBJ,
			Value:   xored,
			Seed:    int64(length),
		}

	case object.STRING_OBJ:
		val := obj.(*object.String).Value
		xored, err := security.SecureXOR([]byte(val), int64(length), password)
		if err != nil {
			return nil, err
		}

		encObj = &object.Encrypted{
			EncType: object.STRING_OBJ,
			Value:   xored,
			Seed:    int64(length),
		}

	// A byte buffer is the value type most likely to hold something worth
	// encrypting -- a key, a decoded section, a captured page. Without this arm
	// it would fall to the default below, and because both callers of this
	// function discard the error and keep the plaintext object, it would travel
	// unencrypted with nothing said.
	case object.BYTES_OBJ:
		val := obj.(*object.Bytes).Value
		xored, err := security.SecureXOR(val, int64(length), password)
		if err != nil {
			return nil, err
		}

		encObj = &object.Encrypted{
			EncType: object.BYTES_OBJ,
			Value:   xored,
			Seed:    int64(length),
		}

	case object.BOOLEAN_OBJ:
		val := obj.(*object.Boolean).Value
		str := strconv.FormatBool(val)
		xored, err := security.SecureXOR([]byte(str), int64(length), password)
		if err != nil {
			return nil, err
		}

		encObj = &object.Encrypted{
			EncType: object.BOOLEAN_OBJ,
			Value:   xored,
			Seed:    int64(length),
		}

	case object.FLOAT_OBJ:
		val := obj.(*object.Float).Value
		bite := make([]byte, 8)
		binary.LittleEndian.PutUint64(bite, math.Float64bits(val))
		xored, err := security.SecureXOR(bite, int64(length), password)
		if err != nil {
			return nil, err
		}

		encObj = &object.Encrypted{
			EncType: object.FLOAT_OBJ,
			Value:   xored,
			Seed:    int64(length),
		}

	case object.NULL_OBJ:
		encObj = &object.Encrypted{
			EncType: object.NULL_OBJ,
			Value:   []byte{},
			Seed:    int64(length),
		}

	case object.ARRAY_OBJ:
		arrayObj := obj.(*object.Array)
		elements := make([]object.Object, len(arrayObj.Elements))
		for i, element := range arrayObj.Elements {
			encElement, encErr := EncryptObject(element, length, password)
			if encErr != nil {
				return nil, encErr
			}
			elements[i] = encElement
		}
		encObj = &object.Array{Elements: elements}

	case object.HASH_OBJ:
		hashObj := obj.(*object.Hash)
		pairs := make(map[object.HashKey]object.HashPair, len(hashObj.Pairs))
		for hashKey, pair := range hashObj.Pairs {
			encKey, encErr := EncryptObject(pair.Key, length, password)
			if encErr != nil {
				return nil, encErr
			}
			encValue, encErr := EncryptObject(pair.Value, length, password)
			if encErr != nil {
				return nil, encErr
			}
			pairs[hashKey] = object.HashPair{Key: encKey, Value: encValue}
		}
		encObj = &object.Hash{Pairs: pairs}

	case object.STRUCT_OBJ:
		structObj := obj.(*object.Struct)
		fields := make(map[string]object.Object, len(structObj.Fields))
		for name, value := range structObj.Fields {
			encValue, encErr := EncryptObject(value, length, password)
			if encErr != nil {
				return nil, encErr
			}
			fields[name] = encValue
		}
		encObj = &object.Struct{TypeName: structObj.TypeName, Fields: fields}

	case object.ENUM_VALUE_OBJ:
		enumObj := obj.(*object.EnumValue)
		var encValue object.Object
		if enumObj.Value != nil {
			encInner, encErr := EncryptObject(enumObj.Value, length, password)
			if encErr != nil {
				return nil, encErr
			}
			encValue = encInner
		}
		encObj = &object.EnumValue{TypeName: enumObj.TypeName, Tag: enumObj.Tag, Value: encValue}

	case object.CLOSURE_OBJ:
		closureObj := obj.(*object.Closure)
		free := make([]object.Object, len(closureObj.Free))
		for i, freeObj := range closureObj.Free {
			encFree, encErr := EncryptObject(freeObj, length, password)
			if encErr != nil {
				return nil, encErr
			}
			free[i] = encFree
		}
		encObj = &object.Closure{Fn: closureObj.Fn, Free: free}

	case object.LUA_PATCH_OBJ:
		patchObj := obj.(*object.LuaPatch)
		xored, err := security.SecureXOR(patchObj.EncryptedPayload, int64(length), password)
		if err != nil {
			return nil, err
		}
		encObj = &object.LuaPatch{
			Name:             patchObj.Name,
			EncryptedPayload: xored,
			ChecksumExpected: patchObj.ChecksumExpected,
		}

	case object.COMPILED_FN_OBJ, object.BUILTIN_OBJ:
		encObj = obj

	default:
		err = errors.New("wrong obj type")
	}

	return encObj, err
}

func DecryptObject(obj object.Object, length int, password string) (object.Object, error) {
	if obj == nil {
		return nil, errors.New("nil obj")
	}

	decObj := obj
	var err error

	if decObj.Type() == object.ENCRYPTED_OBJ {
		encrypted := decObj.(*object.Encrypted)
		if encrypted.EncType == object.NULL_OBJ {
			return global.Null, nil
		}

		seed := int64(length)
		if encrypted.Seed != 0 {
			seed = encrypted.Seed
		}

		biteVal := encrypted.Value
		bite := make([]byte, len(biteVal))
		copy(bite, biteVal)
		xored, err := security.SecureXOR(bite, seed, password)
		if err != nil {
			return nil, err
		}

		switch encrypted.EncType {
		case object.INTEGER_OBJ:
			val := binary.LittleEndian.Uint64(xored)
			decObj = &object.Integer{Value: int64(val)}

		case object.STRING_OBJ:
			decObj = &object.String{Value: string(xored)}

		case object.BYTES_OBJ:
			decObj = &object.Bytes{Value: xored}

		case object.BOOLEAN_OBJ:
			str := strings.ToLower(string(xored))
			if str == "true" {
				decObj = global.True
			} else {
				decObj = global.False
			}

		case object.FLOAT_OBJ:
			val := binary.LittleEndian.Uint64(xored)
			decObj = &object.Float{Value: math.Float64frombits(val)}

		case object.NULL_OBJ:
			decObj = global.Null
		}

		return decObj, nil
	}

	switch decObj.Type() {
	case object.ARRAY_OBJ:
		arrayObj := decObj.(*object.Array)
		elements := make([]object.Object, len(arrayObj.Elements))
		for i, element := range arrayObj.Elements {
			decElement, decErr := DecryptObject(element, length, password)
			if decErr != nil {
				return nil, decErr
			}
			elements[i] = decElement
		}
		return &object.Array{Elements: elements}, nil

	case object.HASH_OBJ:
		hashObj := decObj.(*object.Hash)
		pairs := make(map[object.HashKey]object.HashPair, len(hashObj.Pairs))
		for hashKey, pair := range hashObj.Pairs {
			decKey, decErr := DecryptObject(pair.Key, length, password)
			if decErr != nil {
				return nil, decErr
			}
			decValue, decErr := DecryptObject(pair.Value, length, password)
			if decErr != nil {
				return nil, decErr
			}
			pairs[hashKey] = object.HashPair{Key: decKey, Value: decValue}
		}
		return &object.Hash{Pairs: pairs}, nil

	case object.STRUCT_OBJ:
		structObj := decObj.(*object.Struct)
		fields := make(map[string]object.Object, len(structObj.Fields))
		for name, value := range structObj.Fields {
			decValue, decErr := DecryptObject(value, length, password)
			if decErr != nil {
				return nil, decErr
			}
			fields[name] = decValue
		}
		return &object.Struct{TypeName: structObj.TypeName, Fields: fields}, nil

	case object.ENUM_VALUE_OBJ:
		enumObj := decObj.(*object.EnumValue)
		var decValue object.Object
		if enumObj.Value != nil {
			inner, decErr := DecryptObject(enumObj.Value, length, password)
			if decErr != nil {
				return nil, decErr
			}
			decValue = inner
		}
		return &object.EnumValue{TypeName: enumObj.TypeName, Tag: enumObj.Tag, Value: decValue}, nil

	case object.LUA_PATCH_OBJ:
		patchObj := decObj.(*object.LuaPatch)
		xored, err := security.SecureXOR(patchObj.EncryptedPayload, int64(length), password)
		if err != nil {
			return nil, err
		}
		return &object.LuaPatch{
			Name:             patchObj.Name,
			EncryptedPayload: xored,
			ChecksumExpected: patchObj.ChecksumExpected,
		}, nil

	case object.CLOSURE_OBJ:
		closureObj := decObj.(*object.Closure)
		free := make([]object.Object, len(closureObj.Free))
		for i, freeObj := range closureObj.Free {
			decFree, decErr := DecryptObject(freeObj, length, password)
			if decErr != nil {
				return nil, decErr
			}
			free[i] = decFree
		}
		return &object.Closure{Fn: closureObj.Fn, Free: free}, nil

	case object.COMPILED_FN_OBJ, object.BUILTIN_OBJ:
		return decObj, nil
	}

	err = errors.New("wrong obj type")
	return obj, err
}

func GetPwd() string {
	// Use HKDF (HMAC-based Key Derivation Function) - RFC 5869
	// This generates a deterministic password from fixed context

	masterSecret := []byte("mutant-lang-security-kdf-v1-deterministic-key")
	contextInfo := []byte("mutant-instruction-encryption-key")
	salt := []byte("mutant-hkdf-salt-v1")

	hkdfReader := hkdf.New(sha512.New, masterSecret, salt, contextInfo)

	derivedKey := make([]byte, 64)
	_, err := hkdfReader.Read(derivedKey)
	if err != nil {
		return "mutant-default-security-key-v1"
	}
	return hex.EncodeToString(derivedKey)
}

// DecryptLuaPatch decrypts a Lua patch's encrypted payload using the same pipeline as runtime objects.
func DecryptLuaPatch(patch *object.LuaPatch, length int, password string) ([]byte, error) {
	if patch == nil {
		return nil, errors.New("patch is nil")
	}

	xored, err := security.SecureXOR(patch.EncryptedPayload, int64(length), password)
	if err != nil {
		return nil, err
	}

	return xored, nil
}

// AssertObjectTypes checks if the given input type is one of the expected object types.
// It returns true if the input type matches any of the expected types, false otherwise.
func AssertObjectTypes(inType string, objTypes ...string) bool {
	return slices.Contains(objTypes, inType)
}
