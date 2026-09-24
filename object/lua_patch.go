package object

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// LuaPatch is an encrypted Lua payload carried in an artifact. The checksum of
// the decrypted bytecode is compared with ChecksumExpected where the patch is
// executed (runtime/lua); nothing is recorded back onto the object, because a
// field set after decryption would be dropped the first time the VM stored the
// value (mutil rebuilds it from its encrypted fields).
type LuaPatch struct {
	Name             string // e.g., "mitigation_buffer_overflow"
	EncryptedPayload []byte // Lua bytecode, encrypted
	ChecksumExpected string // SHA-256 of decrypted bytecode (for integrity check)
}

func (lp *LuaPatch) Type() ObjectType {
	return LUA_PATCH_OBJ
}

func (lp *LuaPatch) Inspect() string {
	var out bytes.Buffer
	out.WriteString("LuaPatch{")
	out.WriteString("name: ")
	out.WriteString(lp.Name)
	out.WriteString(", encrypted_size: ")
	out.WriteString(fmt.Sprintf("%d", len(lp.EncryptedPayload)))
	out.WriteString("}")
	return out.String()
}

// ComputeChecksum computes SHA-256 of plaintext bytecode
func ComputeChecksum(plaintext []byte) string {
	h := sha256.Sum256(plaintext)
	return fmt.Sprintf("%x", h[:])
}
