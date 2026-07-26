package builtin

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"hash/crc32"

	"github.com/google/uuid"
	"golang.org/x/crypto/blake2b"

	"mutant/object"
)

func hashHexOf(newHash func() hash.Hash, data []byte) string {
	h := newHash()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func hashOneString(op string, args []object.Object) (string, *object.Error) {
	if len(args) != 1 {
		return "", newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	return requireStringArg(op, args[0], 1)
}

func HashMD5(args ...object.Object) object.Object {
	s, errObj := hashOneString("hash_md5", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(hashHexOf(func() hash.Hash { return md5.New() }, []byte(s)))
}

func HashSHA1(args ...object.Object) object.Object {
	s, errObj := hashOneString("hash_sha1", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(hashHexOf(func() hash.Hash { return sha1.New() }, []byte(s)))
}

func HashSHA256(args ...object.Object) object.Object {
	s, errObj := hashOneString("hash_sha256", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(hashHexOf(func() hash.Hash { return sha256.New() }, []byte(s)))
}

func HashSHA512(args ...object.Object) object.Object {
	s, errObj := hashOneString("hash_sha512", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(hashHexOf(func() hash.Hash { return sha512.New() }, []byte(s)))
}

func HashCRC32(args ...object.Object) object.Object {
	s, errObj := hashOneString("hash_crc32", args)
	if errObj != nil {
		return errObj
	}
	sum := crc32.ChecksumIEEE([]byte(s))
	b := []byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)}
	return stringObj(hex.EncodeToString(b))
}

func HashBlake2(args ...object.Object) object.Object {
	s, errObj := hashOneString("hash_blake2", args)
	if errObj != nil {
		return errObj
	}
	sum := blake2b.Sum256([]byte(s))
	return stringObj(hex.EncodeToString(sum[:]))
}

func HMAC(args ...object.Object) object.Object {
	if len(args) != 3 {
		return newError("wrong number of arguments. got=%d, want=3", len(args))
	}
	key, errObj := requireStringArg("hmac", args[0], 1)
	if errObj != nil {
		return errObj
	}
	msg, errObj := requireStringArg("hmac", args[1], 2)
	if errObj != nil {
		return errObj
	}
	algo, errObj := requireStringArg("hmac", args[2], 3)
	if errObj != nil {
		return errObj
	}
	var newHash func() hash.Hash
	switch algo {
	case "md5":
		newHash = func() hash.Hash { return md5.New() }
	case "sha1":
		newHash = func() hash.Hash { return sha1.New() }
	case "sha256":
		newHash = func() hash.Hash { return sha256.New() }
	case "sha512":
		newHash = func() hash.Hash { return sha512.New() }
	default:
		return newError("argument 3 to `hmac` has unsupported algorithm %q (use md5/sha1/sha256/sha512)", algo)
	}
	mac := hmac.New(newHash, []byte(key))
	mac.Write([]byte(msg))
	return stringObj(hex.EncodeToString(mac.Sum(nil)))
}

func UUIDv4(args ...object.Object) object.Object {
	if len(args) != 0 {
		return newError("wrong number of arguments. got=%d, want=0", len(args))
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return newError("uuid_v4: %s", err.Error())
	}
	return stringObj(id.String())
}

func UUIDv7(args ...object.Object) object.Object {
	if len(args) != 0 {
		return newError("wrong number of arguments. got=%d, want=0", len(args))
	}
	id, err := uuid.NewV7()
	if err != nil {
		return newError("uuid_v7: %s", err.Error())
	}
	return stringObj(id.String())
}

func RandomHex(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	n, errObj := requireIntArg("random_hex", args[0], 1)
	if errObj != nil {
		return errObj
	}
	if n < 0 {
		return newError("argument 1 to `random_hex` must be non-negative, got %d", n)
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return newError("random_hex: %s", err.Error())
	}
	return stringObj(hex.EncodeToString(buf))
}

const nanoidAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-"

func NanoID(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	n, errObj := requireIntArg("nanoid", args[0], 1)
	if errObj != nil {
		return errObj
	}
	if n < 1 {
		return newError("argument 1 to `nanoid` must be positive, got %d", n)
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return newError("nanoid: %s", err.Error())
	}
	out := make([]byte, n)
	for i := range buf {
		out[i] = nanoidAlphabet[int(buf[i])%len(nanoidAlphabet)]
	}
	return stringObj(string(out))
}
