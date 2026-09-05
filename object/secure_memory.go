package object

import (
	"encoding/binary"
	"errors"
	"mutant/security"
	"strconv"
	"time"
)

// SecureGlobal wraps global objects with encryption
type SecureGlobal struct {
	encryptedValue []byte
	objectType     ObjectType
	lastAccess     time.Time
	seed           int64
}

// NewSecureGlobal creates an encrypted global object
func NewSecureGlobal(obj Object, seed int64) (*SecureGlobal, error) {
	encrypted, err := encryptObjectSecure(obj, seed, "")
	if err != nil {
		return nil, err
	}

	return &SecureGlobal{
		encryptedValue: encrypted,
		objectType:     obj.Type(),
		lastAccess:     time.Now(),
		seed:           seed,
	}, nil
}

// Get decrypts and returns the object
func (sg *SecureGlobal) Get() (Object, error) {
	sg.lastAccess = time.Now()
	return decryptObjectSecure(sg.encryptedValue, sg.objectType, sg.seed, "")
}

// Set encrypts and updates the object
func (sg *SecureGlobal) Set(obj Object) error {
	if obj.Type() != sg.objectType {
		return errors.New("type mismatch")
	}

	encrypted, err := encryptObjectSecure(obj, sg.seed, "")
	if err != nil {
		return err
	}

	// Zero out old encrypted value before replacing
	security.SecureZero(sg.encryptedValue)

	sg.encryptedValue = encrypted
	sg.lastAccess = time.Now()
	return nil
}

// Clear securely wipes the encrypted value
func (sg *SecureGlobal) Clear() {
	security.SecureZero(sg.encryptedValue)
	sg.encryptedValue = nil
}

// encryptObjectSecure encrypts an object using secure methods
func encryptObjectSecure(obj Object, seed int64, password string) ([]byte, error) {
	var data []byte
	offset := objectStreamOffset(obj.Type())

	switch obj.Type() {
	case INTEGER_OBJ:
		val := obj.(*Integer).Value
		data = make([]byte, 8)
		binary.LittleEndian.PutUint64(data, uint64(val))

	case STRING_OBJ:
		data = []byte(obj.(*String).Value)

	case BYTES_OBJ:
		data = obj.(*Bytes).Value

	case BOOLEAN_OBJ:
		val := obj.(*Boolean).Value
		data = []byte(strconv.FormatBool(val))

	default:
		return nil, errors.New("unsupported object type for encryption")
	}

	// Use offset-aware stream encryption with deterministic object-type offsets.
	encrypted, err := security.SecureXORAt(data, seed, password, offset)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// decryptObjectSecure decrypts an object using secure methods
func decryptObjectSecure(encrypted []byte, objType ObjectType, seed int64, password string) (Object, error) {
	// Decrypt with the same deterministic object-type stream offset.
	data, err := security.SecureXORAt(encrypted, seed, password, objectStreamOffset(objType))
	if err != nil {
		return nil, err
	}

	switch objType {
	case INTEGER_OBJ:
		val := binary.LittleEndian.Uint64(data)
		return &Integer{Value: int64(val)}, nil

	case STRING_OBJ:
		return &String{Value: string(data)}, nil

	case BYTES_OBJ:
		return &Bytes{Value: data}, nil

	case BOOLEAN_OBJ:
		val, err := strconv.ParseBool(string(data))
		if err != nil {
			return nil, err
		}
		return &Boolean{Value: val}, nil

	default:
		return nil, errors.New("unsupported object type for decryption")
	}
}

func objectStreamOffset(objType ObjectType) int64 {
	switch objType {
	case INTEGER_OBJ:
		return 64
	case STRING_OBJ:
		return 128
	case BOOLEAN_OBJ:
		return 192
	case BYTES_OBJ:
		return 320
	default:
		return 256
	}
}

// SecureStack implements auto-encrypting stack
type SecureStack struct {
	data         []Object
	lastAccess   []time.Time
	autoEncrypt  bool
	encryptAfter time.Duration
	seed         int64
}

// NewSecureStack creates a new secure stack
func NewSecureStack(size int, seed int64) *SecureStack {
	return &SecureStack{
		data:         make([]Object, size),
		lastAccess:   make([]time.Time, size),
		autoEncrypt:  true,
		encryptAfter: 100 * time.Millisecond, // Encrypt after 100ms of no access
		seed:         seed,
	}
}

// Get retrieves an item from the stack
func (ss *SecureStack) Get(index int) (Object, error) {
	if index < 0 || index >= len(ss.data) {
		return nil, errors.New("index out of bounds")
	}

	ss.lastAccess[index] = time.Now()

	obj := ss.data[index]
	if obj == nil {
		return nil, nil
	}

	// If it's encrypted, decrypt it
	if enc, ok := obj.(*Encrypted); ok {
		return decryptObjectSecure(enc.Value, enc.EncType, ss.seed, "")
	}

	return obj, nil
}

// Set stores an item on the stack
func (ss *SecureStack) Set(index int, obj Object) error {
	if index < 0 || index >= len(ss.data) {
		return errors.New("index out of bounds")
	}

	// Clear old value securely if it exists
	if ss.data[index] != nil {
		ss.clearObject(ss.data[index])
	}

	ss.data[index] = obj
	ss.lastAccess[index] = time.Now()

	return nil
}

// AutoProtect encrypts items not accessed recently
func (ss *SecureStack) AutoProtect() {
	if !ss.autoEncrypt {
		return
	}

	now := time.Now()
	for i := range ss.data {
		if ss.data[i] == nil {
			continue
		}

		// Skip if already encrypted
		if _, ok := ss.data[i].(*Encrypted); ok {
			continue
		}

		// Encrypt if not accessed recently
		if now.Sub(ss.lastAccess[i]) > ss.encryptAfter {
			encrypted, err := encryptObjectSecure(ss.data[i], ss.seed, "")
			if err == nil {
				// Clear the original object
				ss.clearObject(ss.data[i])

				// Store encrypted version
				ss.data[i] = &Encrypted{
					EncType: ss.data[i].Type(),
					Value:   encrypted,
				}
			}
		}
	}
}

// clearObject securely clears an object's sensitive data
func (ss *SecureStack) clearObject(obj Object) {
	switch v := obj.(type) {
	case *String:
		// []byte(v.Value) is a copy Go makes at the conversion, so this zeroes
		// the copy and the string itself lives on until it is collected. Go
		// strings are immutable; there is no way to wipe one in place. Dropping
		// the reference is all this can honestly do -- which is precisely why a
		// buffer that holds key material belongs in a Bytes.
		security.SecureZero([]byte(v.Value))
		v.Value = ""

	case *Bytes:
		// A Bytes, unlike a String, really can be wiped.
		v.Zero()

	case *Integer:
		v.Value = 0

	case *Encrypted:
		security.SecureZero(v.Value)
		v.Value = nil
	}
}

// Clear securely wipes the entire stack
func (ss *SecureStack) Clear() {
	for i := range ss.data {
		if ss.data[i] != nil {
			ss.clearObject(ss.data[i])
			ss.data[i] = nil
		}
	}
}

// SecureConstantPool implements lazy-decryption constant pool
type SecureConstantPool struct {
	encrypted [][]byte
	types     []ObjectType
	cache     map[int]Object
	cacheSize int
	lruOrder  []int
	seed      int64
}

// NewSecureConstantPool creates a new secure constant pool
func NewSecureConstantPool(constants []Object, cacheSize int, seed int64) (*SecureConstantPool, error) {
	encrypted := make([][]byte, len(constants))
	types := make([]ObjectType, len(constants))

	for i, obj := range constants {
		enc, err := encryptObjectSecure(obj, seed, "")
		if err != nil {
			// For objects that can't be encrypted, store nil
			encrypted[i] = nil
			types[i] = obj.Type()
			continue
		}

		encrypted[i] = enc
		types[i] = obj.Type()
	}

	return &SecureConstantPool{
		encrypted: encrypted,
		types:     types,
		cache:     make(map[int]Object),
		cacheSize: cacheSize,
		lruOrder:  make([]int, 0, cacheSize),
		seed:      seed,
	}, nil
}

// Get retrieves a constant, decrypting if necessary
func (scp *SecureConstantPool) Get(index int) (Object, error) {
	if index < 0 || index >= len(scp.encrypted) {
		return nil, errors.New("index out of bounds")
	}

	// Check cache first
	if obj, ok := scp.cache[index]; ok {
		scp.updateLRU(index)
		return obj, nil
	}

	// If not encrypted (complex object), return error
	if scp.encrypted[index] == nil {
		return nil, errors.New("constant cannot be securely cached")
	}

	// Decrypt
	obj, err := decryptObjectSecure(scp.encrypted[index], scp.types[index], scp.seed, "")
	if err != nil {
		return nil, err
	}

	// Add to cache
	if len(scp.cache) >= scp.cacheSize {
		scp.evictOldest()
	}

	scp.cache[index] = obj
	scp.lruOrder = append(scp.lruOrder, index)

	return obj, nil
}

// updateLRU moves an index to the end of LRU order
func (scp *SecureConstantPool) updateLRU(index int) {
	// Remove from current position
	for i, idx := range scp.lruOrder {
		if idx == index {
			scp.lruOrder = append(scp.lruOrder[:i], scp.lruOrder[i+1:]...)
			break
		}
	}

	// Add to end
	scp.lruOrder = append(scp.lruOrder, index)
}

// evictOldest removes the least recently used item
func (scp *SecureConstantPool) evictOldest() {
	if len(scp.lruOrder) == 0 {
		return
	}

	// Remove oldest
	oldest := scp.lruOrder[0]
	scp.lruOrder = scp.lruOrder[1:]

	// Clear from cache
	if obj, ok := scp.cache[oldest]; ok {
		// Securely clear the object
		switch v := obj.(type) {
		case *String:
			bytes := []byte(v.Value)
			security.SecureZero(bytes)
		case *Integer:
			v.Value = 0
		}

		delete(scp.cache, oldest)
	}
}

// Clear securely wipes the cache
func (scp *SecureConstantPool) Clear() {
	for _, obj := range scp.cache {
		switch v := obj.(type) {
		case *String:
			bytes := []byte(v.Value)
			security.SecureZero(bytes)
		case *Integer:
			v.Value = 0
		}
	}

	scp.cache = make(map[int]Object)
	scp.lruOrder = make([]int, 0, scp.cacheSize)
}
