package object

import "fmt"

type Encrypted struct {
	Value   []byte
	EncType ObjectType
	Seed    int64
	// Classified is the mark a BYTES value carried when it was encrypted for
	// storage; see Bytes.Classified. It holds no plaintext -- a record uid,
	// class tags and labels -- so it travels beside the ciphertext rather than
	// inside it, and decryption puts it back. Every variable the VM holds is
	// stored encrypted, so without this a buffer lost its mark the moment it
	// was bound to a name, and every sink check downstream passed it.
	Classified *Classification
}

func (e *Encrypted) Type() ObjectType { return ENCRYPTED_OBJ }
func (e *Encrypted) Inspect() string  { return fmt.Sprintf("%v", e.Value) }
