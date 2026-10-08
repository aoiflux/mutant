package mutil

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"math"
	"mutant/compiler"
	"mutant/global"
	"mutant/object"
	"mutant/security"
	"mutant/serialize"
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

// xorPayload encrypts a value's bytes, treating an empty payload as its own
// ciphertext rather than as an error.
//
// sealKey is what a stored value's payload is sealed with: the (seed, password)
// pair every value in a run shares, and -- when the caller has already derived
// it -- the key itself.
//
// The key and the nonce depend on nothing but the seed and the password, and a
// run has one of each: the VM seals and opens with its own inslen and its own
// password from the first instruction to the last. Deriving them per call was
// the cost of a container load rather than the cipher, two SHA-256 hashes per
// eight bytes of payload -- building an array of 800 elements in a loop made
// 2,890,011 derivations for 22 MiB of payload (M26-VM-001). The VM already
// holds the stream it derived for its instructions, under exactly that pair, so
// it hands that one in and the derivation happens once per run instead.
//
// The stream is optional, and it is skipped rather than trusted when the value
// disagrees with it: a stored value records the seed it was sealed under, and
// one sealed under a different seed has to be opened with a key derived for
// that seed. The REPL is where this is not hypothetical -- it compiles a new
// program per line, so inslen changes while the globals carried across lines
// keep the seed of the line that stored them.
type sealKey struct {
	length   int
	password string
	stream   *security.XORStream
}

// seed identifies the keystream, and is not an offset into it: every object
// payload is sealed from the start of its own stream.
func (k sealKey) seed() int64 {
	return int64(k.length)
}

// xor seals or opens a payload under this key's own seed.
func (k sealKey) xor(data []byte) ([]byte, error) {
	return k.xorAtSeed(data, k.seed())
}

// xorAtSeed is xor for a value that records a seed of its own. A derived stream
// answers for its own seed and for nothing else; anything else derives, as it
// always did.
func (k sealKey) xorAtSeed(data []byte, seed int64) ([]byte, error) {
	if k.stream != nil && seed == k.seed() {
		return k.stream.XORAt(data, 0)
	}
	return security.SecureXOR(data, seed, k.password)
}

// security.SecureXOR rejects empty input. That is a reasonable guard where a
// caller passing nothing is a mistake, and the wrong answer here: XOR over zero
// bytes is zero bytes, so there is nothing to protect and nothing to get wrong.
// The error it returned instead was load-bearing in the worst direction. Both
// callers of EncryptObject keep the plaintext object when it fails, and the
// container arms below propagate a child's failure to the whole container -- so
// a single empty string in an array left every sibling in the clear:
//
//	let g = ["", "secret"];   // the whole array stored unencrypted
//
// The NULL arm has always short-circuited for the same reason; strings, byte
// buffers and Lua payloads simply never got the same treatment.
//
// The opening side keeps the error rather than sharing this arm: there a
// payload's length is the only thing that says how much was stored, so an empty
// one for a type that is always eight bytes is a corrupt value, not an empty
// one.
func (k sealKey) xorPayload(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	return k.xor(data)
}

// EncryptObject seals a value for storage, deriving the key it needs.
func EncryptObject(obj object.Object, length int, password string) (object.Object, error) {
	return encryptObject(obj, sealKey{length: length, password: password})
}

// EncryptObjectWithStream is EncryptObject for a caller that already holds the
// derived stream for this (length, password) -- the VM, which derives one per
// run for its instructions and seals its values under the same pair. The
// password is still required, because a value may record a seed of its own;
// see sealKey.
func EncryptObjectWithStream(obj object.Object, length int, password string, stream *security.XORStream) (object.Object, error) {
	return encryptObject(obj, sealKey{length: length, password: password, stream: stream})
}

func encryptObject(obj object.Object, key sealKey) (object.Object, error) {
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
		xored, err := key.xor(bite)
		if err != nil {
			return nil, err
		}

		encObj = &object.Encrypted{
			EncType: object.INTEGER_OBJ,
			Value:   xored,
			Seed:    key.seed(),
		}

	case object.STRING_OBJ:
		val := obj.(*object.String).Value
		xored, err := key.xorPayload([]byte(val))
		if err != nil {
			return nil, err
		}

		encObj = &object.Encrypted{
			EncType: object.STRING_OBJ,
			Value:   xored,
			Seed:    key.seed(),
		}

	// A byte buffer is the value type most likely to hold something worth
	// encrypting -- a key, a decoded section, a captured page. Without this arm
	// it would fall to the default below, and because both callers of this
	// function discard the error and keep the plaintext object, it would travel
	// unencrypted with nothing said.
	case object.BYTES_OBJ:
		val := obj.(*object.Bytes).Value
		xored, err := key.xorPayload(val)
		if err != nil {
			return nil, err
		}

		encObj = &object.Encrypted{
			EncType:    object.BYTES_OBJ,
			Value:      xored,
			Seed:       key.seed(),
			Classified: obj.(*object.Bytes).Classified,
		}

	case object.BOOLEAN_OBJ:
		val := obj.(*object.Boolean).Value
		str := strconv.FormatBool(val)
		xored, err := key.xor([]byte(str))
		if err != nil {
			return nil, err
		}

		encObj = &object.Encrypted{
			EncType: object.BOOLEAN_OBJ,
			Value:   xored,
			Seed:    key.seed(),
		}

	case object.FLOAT_OBJ:
		val := obj.(*object.Float).Value
		bite := make([]byte, 8)
		binary.LittleEndian.PutUint64(bite, math.Float64bits(val))
		xored, err := key.xor(bite)
		if err != nil {
			return nil, err
		}

		encObj = &object.Encrypted{
			EncType: object.FLOAT_OBJ,
			Value:   xored,
			Seed:    key.seed(),
		}

	case object.NULL_OBJ:
		encObj = &object.Encrypted{
			EncType: object.NULL_OBJ,
			Value:   []byte{},
			Seed:    key.seed(),
		}

	case object.ARRAY_OBJ:
		arrayObj := obj.(*object.Array)
		elements := make([]object.Object, len(arrayObj.Elements))
		for i, element := range arrayObj.Elements {
			encElement, encErr := encryptObject(element, key)
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
			encKey, encErr := encryptObject(pair.Key, key)
			if encErr != nil {
				return nil, encErr
			}
			encValue, encErr := encryptObject(pair.Value, key)
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
			encValue, encErr := encryptObject(value, key)
			if encErr != nil {
				return nil, encErr
			}
			fields[name] = encValue
		}
		// FieldOrder is copied rather than shared. Every value the VM stores
		// round-trips through here, and a stored value must not alias the one
		// handed in; dropping the field entirely would lose the struct's
		// declaration order on the first assignment.
		encObj = &object.Struct{
			TypeName:   structObj.TypeName,
			FieldOrder: append([]string(nil), structObj.FieldOrder...),
			Fields:     fields,
		}

	case object.ENUM_VALUE_OBJ:
		enumObj := obj.(*object.EnumValue)
		var encValue object.Object
		if enumObj.Value != nil {
			encInner, encErr := encryptObject(enumObj.Value, key)
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
			encFree, encErr := encryptObject(freeObj, key)
			if encErr != nil {
				return nil, encErr
			}
			free[i] = encFree
		}
		encObj = &object.Closure{Fn: closureObj.Fn, Free: free}

	case object.LUA_PATCH_OBJ:
		patchObj := obj.(*object.LuaPatch)
		xored, err := key.xorPayload(patchObj.EncryptedPayload)
		if err != nil {
			return nil, err
		}
		encObj = &object.LuaPatch{
			Name:             patchObj.Name,
			EncryptedPayload: xored,
			ChecksumExpected: patchObj.ChecksumExpected,
		}

	// A multi-value is a list of values wearing a different name, and it reaches
	// storage the same way an array does: Mutant's whole (value, err) idiom
	// produces one, and `let r = f();` binds it to a global. Without this arm it
	// fell to the default below and was stored in the clear -- along with, via the
	// container arms above, any array or struct that happened to hold one.
	case object.MULTI_VALUE_OBJ:
		multiObj := obj.(*object.MultiValue)
		values := make([]object.Object, len(multiObj.Values))
		for i, value := range multiObj.Values {
			encValue, encErr := encryptObject(value, key)
			if encErr != nil {
				return nil, encErr
			}
			values[i] = encValue
		}
		encObj = &object.MultiValue{Values: values}

	// An error is an ordinary value in this language, so `let v, e = fs_read(p);`
	// binds one to a global and it sits there for the life of the program. It is
	// also the value most worth covering: its Message carries the path that
	// failed, and SourceLine carries a line of the program itself.
	//
	// It is encoded whole rather than field by field. Error has ten fields and
	// gains more over time; encrypting a chosen few would leave the rest in the
	// clear and would go stale the next time one is added.
	case object.ERROR_OBJ:
		encoded, encErr := encodeError(obj.(*object.Error))
		if encErr != nil {
			return nil, encErr
		}
		xored, xorErr := key.xorPayload(encoded)
		if xorErr != nil {
			return nil, xorErr
		}

		encObj = &object.Encrypted{
			EncType: object.ERROR_OBJ,
			Value:   xored,
			Seed:    key.seed(),
		}

	// A cell is a handle, not a value, and encrypting it would be actively
	// wrong rather than merely pointless: every encryption here returns a *new*
	// object, and a new cell is a second storage location -- exactly the
	// by-value copy that boxed captures exist to eliminate. The cell's contents
	// are still covered, because whatever the VM writes into cell.Value went
	// through this function on the way in.
	//
	// It has its own arm rather than joining the list below because the reason
	// is different, and because the default arm silently leaves a value in
	// plaintext (both callers discard the error) -- an accidental right answer
	// is one refactor away from a wrong one.
	case object.CELL_OBJ:
		encObj = obj

	// A loop cursor passes through by pointer for the same reason a cell does,
	// and the consequence is sharper: OpIterNext peeks the cursor on the stack
	// and advances it in place. Handing back a copy would reset the loop to its
	// first element on every iteration -- an endless loop, not an error. It
	// holds no data of its own worth sealing; its keys and values were sealed
	// when they went into the collection it walks.
	case object.ITERATOR_OBJ:
		encObj = obj

	// Code and control flow, not data at rest: there is nothing in a compiled
	// function, a builtin, an evaluator function, a macro, a quoted node or a
	// loop-control singleton that encrypting would protect. The last five are
	// evaluator-only and unreachable from here today, since the evaluator never
	// calls this function -- they are named anyway, because `default` is the arm
	// that silently leaves a value in plaintext (both callers discard the error),
	// and an unreachable default is the only kind that cannot do that.
	case object.COMPILED_FN_OBJ, object.BUILTIN_OBJ, object.FUNCTION_OBJ,
		object.MACRO_OBJ, object.QUOTE_OBJ, object.RETURN_VALUE_OBJ,
		object.BREAK_OBJ, object.CONTINUE_OBJ:
		encObj = obj

	default:
		err = errors.New("wrong obj type")
	}

	return encObj, err
}

// encodeError and decodeError serialise an *object.Error so it can be covered
// by the same XOR every other stored value gets. gob is used rather than a
// hand-rolled layout because Error gains fields over time and the encoding
// stays correct as it does -- which is the failure mode a hand-rolled one
// would have.
//
// The registration is not optional, and it is not defensive. Related is
// map[string]object.Object, so an error carrying any context at all is encoded
// through an interface, and gob refuses a concrete type it was not told about.
// It refuses by returning an error -- and both callers of EncryptObject keep
// the plaintext object when this fails, so an unregistered type would not fail
// loudly. It would quietly store the error, its message and its copied source
// line in the clear, which is the one outcome this function exists to prevent.
//
// This used to read "no gob.Register is needed: Error is a plain struct of
// concrete types". That stopped being true when Related was widened from
// map[string]string, so the registration moved in rather than the list being
// copied here -- serialize owns the one list precisely so it cannot be
// duplicated into a second one that drifts. RegisterGobTypes is a sync.Once,
// so calling it on every error costs a mutex read.
func encodeError(errObj *object.Error) ([]byte, error) {
	serialize.RegisterGobTypes()

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(errObj); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeError(encoded []byte) (*object.Error, error) {
	serialize.RegisterGobTypes()

	var errObj object.Error
	if err := gob.NewDecoder(bytes.NewReader(encoded)).Decode(&errObj); err != nil {
		return nil, err
	}
	return &errObj, nil
}

// DecryptObject opens a stored value, deriving the key it needs.
func DecryptObject(obj object.Object, length int, password string) (object.Object, error) {
	return decryptObject(obj, sealKey{length: length, password: password})
}

// DecryptObjectWithStream is DecryptObject for a caller that already holds the
// derived stream; see EncryptObjectWithStream and sealKey.
func DecryptObjectWithStream(obj object.Object, length int, password string, stream *security.XORStream) (object.Object, error) {
	return decryptObject(obj, sealKey{length: length, password: password, stream: stream})
}

func decryptObject(obj object.Object, key sealKey) (object.Object, error) {
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

		// The mirror of xorPayload. An empty payload is legitimate for exactly the
		// two variable-length types and impossible for the rest -- an integer is
		// always eight bytes, a boolean always "true" or "false" -- so the
		// short-circuit is deliberately narrow. Widening it would turn a corrupt
		// integer into a silent zero instead of an error.
		if len(encrypted.Value) == 0 {
			switch encrypted.EncType {
			case object.STRING_OBJ:
				return &object.String{Value: ""}, nil
			case object.BYTES_OBJ:
				return &object.Bytes{Value: []byte{}, Classified: encrypted.Classified}, nil
			}
		}

		seed := key.seed()
		if encrypted.Seed != 0 {
			seed = encrypted.Seed
		}

		biteVal := encrypted.Value
		bite := make([]byte, len(biteVal))
		copy(bite, biteVal)
		xored, err := key.xorAtSeed(bite, seed)
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
			decObj = &object.Bytes{Value: xored, Classified: encrypted.Classified}

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

		case object.ERROR_OBJ:
			errObj, decErr := decodeError(xored)
			if decErr != nil {
				return nil, decErr
			}
			decObj = errObj
		}

		return decObj, nil
	}

	switch decObj.Type() {
	case object.ARRAY_OBJ:
		arrayObj := decObj.(*object.Array)
		elements := make([]object.Object, len(arrayObj.Elements))
		for i, element := range arrayObj.Elements {
			decElement, decErr := decryptObject(element, key)
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
			decKey, decErr := decryptObject(pair.Key, key)
			if decErr != nil {
				return nil, decErr
			}
			decValue, decErr := decryptObject(pair.Value, key)
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
			decValue, decErr := decryptObject(value, key)
			if decErr != nil {
				return nil, decErr
			}
			fields[name] = decValue
		}
		return &object.Struct{
			TypeName:   structObj.TypeName,
			FieldOrder: append([]string(nil), structObj.FieldOrder...),
			Fields:     fields,
		}, nil

	case object.ENUM_VALUE_OBJ:
		enumObj := decObj.(*object.EnumValue)
		var decValue object.Object
		if enumObj.Value != nil {
			inner, decErr := decryptObject(enumObj.Value, key)
			if decErr != nil {
				return nil, decErr
			}
			decValue = inner
		}
		return &object.EnumValue{TypeName: enumObj.TypeName, Tag: enumObj.Tag, Value: decValue}, nil

	case object.LUA_PATCH_OBJ:
		patchObj := decObj.(*object.LuaPatch)
		xored, err := key.xorPayload(patchObj.EncryptedPayload)
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
			decFree, decErr := decryptObject(freeObj, key)
			if decErr != nil {
				return nil, decErr
			}
			free[i] = decFree
		}
		return &object.Closure{Fn: closureObj.Fn, Free: free}, nil

	case object.MULTI_VALUE_OBJ:
		multiObj := decObj.(*object.MultiValue)
		values := make([]object.Object, len(multiObj.Values))
		for i, value := range multiObj.Values {
			decValue, decErr := decryptObject(value, key)
			if decErr != nil {
				return nil, decErr
			}
			values[i] = decValue
		}
		return &object.MultiValue{Values: values}, nil

	// The mirror of the pass-through group in EncryptObject; see the comment
	// there for why the evaluator-only types are named rather than defaulted.
	// The mirror of the encrypt side: the cell passes through by pointer so the
	// frame slot and every closure over it stay one location. cell.Value is
	// decrypted where it is read, by OpGetLocalCell and OpGetFree.
	case object.CELL_OBJ:
		return decObj, nil

	// A loop cursor passes through by pointer for the same reason a cell does,
	// and the consequence is sharper: OpIterNext peeks the cursor on the stack
	// and advances it in place. Handing back a copy would reset the loop to its
	// first element on every iteration -- an endless loop, not an error. It
	// holds no data of its own worth sealing; its keys and values were sealed
	// when they went into the collection it walks.
	case object.ITERATOR_OBJ:
		return decObj, nil

	case object.COMPILED_FN_OBJ, object.BUILTIN_OBJ, object.FUNCTION_OBJ,
		object.MACRO_OBJ, object.QUOTE_OBJ, object.RETURN_VALUE_OBJ,
		object.BREAK_OBJ, object.CONTINUE_OBJ:
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
