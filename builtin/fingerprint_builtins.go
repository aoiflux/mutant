package builtin

import (
	"crypto/des"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf16"

	saferpe "github.com/saferwall/pe"
	"golang.org/x/crypto/md4"

	"mutant/object"
)

// --- imphash (PE import hash, pefile/Mandiant algorithm) ---

type imphashFunc struct {
	name      string
	ordinal   uint32
	byOrdinal bool
}

type imphashLib struct {
	dll   string
	funcs []imphashFunc
}

// computeImphash builds the pefile-style import string ("dll.func,dll.func,...",
// lowercased, with dll/ocx/sys extensions stripped and ordinal imports rendered
// as "ord<N>") and returns its MD5 hex digest.
func computeImphash(libs []imphashLib) string {
	parts := make([]string, 0)
	for _, lib := range libs {
		libname := strings.ToLower(lib.dll)
		if i := strings.LastIndex(libname, "."); i >= 0 {
			switch libname[i+1:] {
			case "dll", "ocx", "sys":
				libname = libname[:i]
			}
		}
		for _, fn := range lib.funcs {
			funcname := strings.ToLower(fn.name)
			if fn.byOrdinal || funcname == "" {
				funcname = "ord" + strconv.FormatUint(uint64(fn.ordinal), 10)
			}
			parts = append(parts, libname+"."+funcname)
		}
	}
	sum := md5.Sum([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(sum[:])
}

func Imphash(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("imphash: panic during PE parse: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("imphash", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	peFile, err := saferpe.New(path, &saferpe.Options{Fast: false})
	if err != nil {
		return resultAndError(nil, newError("imphash: %s", err.Error()))
	}
	defer peFile.Close()
	if err := peFile.Parse(); err != nil {
		return resultAndError(nil, newError("imphash: not a parseable PE: %s", err.Error()))
	}

	libs := make([]imphashLib, 0, len(peFile.Imports))
	importCount := 0
	for _, imp := range peFile.Imports {
		funcs := make([]imphashFunc, 0, len(imp.Functions))
		for _, fn := range imp.Functions {
			funcs = append(funcs, imphashFunc{name: fn.Name, ordinal: fn.Ordinal, byOrdinal: fn.ByOrdinal})
			importCount++
		}
		libs = append(libs, imphashLib{dll: imp.Name, funcs: funcs})
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"imphash":      stringObj(computeImphash(libs)),
		"import_count": intObj(int64(importCount)),
		"dll_count":    intObj(int64(len(libs))),
	}), nil)
}

// --- NTLM credential hashes ---

// NTHash returns the NT hash (MD4 of the UTF-16LE password), as used in NTLM.
func NTHash(args ...object.Object) object.Object {
	password, errObj := strOneStringArg("nt_hash", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(ntHashHex(password))
}

func ntHashHex(password string) string {
	u16 := utf16.Encode([]rune(password))
	buf := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	h := md4.New()
	h.Write(buf)
	return hex.EncodeToString(h.Sum(nil))
}

var lmMagic = []byte("KGS!@#$%")

// LMHash returns the legacy LM hash of a password (DES-based; case-insensitive,
// max 14 chars). Empty password -> aad3b435b51404eeaad3b435b51404ee.
func LMHash(args ...object.Object) object.Object {
	password, errObj := strOneStringArg("lm_hash", args)
	if errObj != nil {
		return errObj
	}
	digest, err := lmHashHex(password)
	if err != nil {
		return newError("lm_hash: %s", err.Error())
	}
	return stringObj(digest)
}

func lmHashHex(password string) (string, error) {
	padded := make([]byte, 14)
	copy(padded, []byte(strings.ToUpper(password))) // truncates to 14, zero-pads

	left, err := lmHalf(padded[:7])
	if err != nil {
		return "", err
	}
	right, err := lmHalf(padded[7:14])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(append(left, right...)), nil
}

func lmHalf(key7 []byte) ([]byte, error) {
	block, err := des.NewCipher(lmExpandKey(key7))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	block.Encrypt(out, lmMagic)
	return out, nil
}

// lmExpandKey turns a 7-byte key into an 8-byte DES key (7 bits per byte, low
// parity bit zeroed).
func lmExpandKey(k []byte) []byte {
	out := make([]byte, 8)
	out[0] = k[0] >> 1
	out[1] = ((k[0] & 0x01) << 6) | (k[1] >> 2)
	out[2] = ((k[1] & 0x03) << 5) | (k[2] >> 3)
	out[3] = ((k[2] & 0x07) << 4) | (k[3] >> 4)
	out[4] = ((k[3] & 0x0F) << 3) | (k[4] >> 5)
	out[5] = ((k[4] & 0x1F) << 2) | (k[5] >> 6)
	out[6] = ((k[5] & 0x3F) << 1) | (k[6] >> 7)
	out[7] = k[6] & 0x7F
	for i := range out {
		out[i] = (out[i] << 1) & 0xFE
	}
	return out
}
