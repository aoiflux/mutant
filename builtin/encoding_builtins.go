package builtin

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strconv"

	"mutant/object"
)

func encOneString(op string, args []object.Object) (string, *object.Error) {
	if len(args) != 1 {
		return "", newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	return requireStringArg(op, args[0], 1)
}

// encOneBinary is encOneString for the encoders that consume arbitrary data
// rather than text -- base64, base32, hex, gzip, zlib. They accept a buffer as
// readily as a string, because encoding bytes is the entire job.
//
// url_encode deliberately keeps the text-only helper: percent-encoding is
// defined over a URL component, and accepting a buffer there would widen the
// argument-type diagnostic for no gain.
func encOneBinary(op string, args []object.Object) (string, *object.Error) {
	if len(args) != 1 {
		return "", newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	data, errObj := requireBinaryArg(op, args[0], 1)
	if errObj != nil {
		return "", errObj
	}
	return string(data), nil
}

func Base64Encode(args ...object.Object) object.Object {
	s, errObj := encOneBinary(BuiltinNameBase64Encode, args)
	if errObj != nil {
		return errObj
	}
	return stringObj(base64.StdEncoding.EncodeToString([]byte(s)))
}

func Base64Decode(args ...object.Object) object.Object {
	return base64Decode(args, BuiltinNameBase64Decode, false)
}

// Base64DecodeBytes decodes standard base64 into a buffer.
func Base64DecodeBytes(args ...object.Object) object.Object {
	return base64Decode(args, BuiltinNameBase64DecodeBytes, true)
}

func base64Decode(args []object.Object, opName string, binary bool) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg(opName, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", opName, err.Error()))
	}
	return resultAndError(binaryResult(binary, decoded), nil)
}

func Base64URLEncode(args ...object.Object) object.Object {
	s, errObj := encOneBinary(BuiltinNameBase64URLEncode, args)
	if errObj != nil {
		return errObj
	}
	return stringObj(base64.URLEncoding.EncodeToString([]byte(s)))
}

func Base64URLDecode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg(BuiltinNameBase64URLDecode, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	decoded, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return resultAndError(nil, newError("base64url_decode: %s", err.Error()))
	}
	return resultAndError(stringObj(string(decoded)), nil)
}

func Base32Encode(args ...object.Object) object.Object {
	s, errObj := encOneBinary(BuiltinNameBase32Encode, args)
	if errObj != nil {
		return errObj
	}
	return stringObj(base32.StdEncoding.EncodeToString([]byte(s)))
}

func Base32Decode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg(BuiltinNameBase32Decode, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	decoded, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return resultAndError(nil, newError("base32_decode: %s", err.Error()))
	}
	return resultAndError(stringObj(string(decoded)), nil)
}

func HexEncode(args ...object.Object) object.Object {
	s, errObj := encOneBinary(BuiltinNameHexEncode, args)
	if errObj != nil {
		return errObj
	}
	return stringObj(hex.EncodeToString([]byte(s)))
}

func HexDecode(args ...object.Object) object.Object { return hexDecode(args, BuiltinNameHexDecode, false) }

// HexDecodeBytes decodes hex into a buffer. Decoded hex is binary by
// definition -- that is what hex is for -- so this is the variant most callers
// want once they have somewhere binary to put it.
func HexDecodeBytes(args ...object.Object) object.Object {
	return hexDecode(args, BuiltinNameHexDecodeBytes, true)
}

func hexDecode(args []object.Object, opName string, binary bool) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg(opName, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", opName, err.Error()))
	}
	return resultAndError(binaryResult(binary, decoded), nil)
}

func URLEncode(args ...object.Object) object.Object {
	s, errObj := encOneString(BuiltinNameURLEncode, args)
	if errObj != nil {
		return errObj
	}
	return stringObj(url.QueryEscape(s))
}

func URLDecode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg(BuiltinNameURLDecode, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return resultAndError(nil, newError("url_decode: %s", err.Error()))
	}
	return resultAndError(stringObj(decoded), nil)
}

func Gzip(args ...object.Object) object.Object {
	s, errObj := encOneBinary(BuiltinNameGzip, args)
	if errObj != nil {
		return errObj
	}
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		return newError("gzip: %s", err.Error())
	}
	if err := w.Close(); err != nil {
		return newError("gzip: %s", err.Error())
	}
	return stringObj(buf.String())
}

func Gunzip(args ...object.Object) object.Object { return gunzip(args, BuiltinNameGunzip, false) }

// GunzipBytes decompresses gzip data into a buffer.
func GunzipBytes(args ...object.Object) object.Object { return gunzip(args, BuiltinNameGunzipBytes, true) }

// gunzip and zlibDecompress both bound what they will materialise.
//
// They did not, and the omission was not theoretical: io.ReadAll on a
// decompressing reader holds whatever the stream produces, so a kilobyte of
// hostile input was enough to take the process out. A forensics language is
// handed hostile input by definition -- that is what evidence is -- and these
// two are how a program reaches the compressed member of an artifact it has
// just parsed out of a container.
//
// The limit is the shared one: 1000x the input, capped at 1 GiB, or whatever
// the caller names in max_bytes. See decompressionLimit.
func gunzip(args []object.Object, opName string, binary bool) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	s, errObj := requireBinaryArg(opName, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	limit, errObj := resolveDecompressionLimit(opName, args, 2, int64(len(s)))
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	r, err := gzip.NewReader(bytes.NewReader(s))
	if err != nil {
		return resultAndError(nil, newError("%s: %s", opName, err.Error()))
	}
	defer r.Close()
	out, err := readLimited(r, limit)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", opName, err.Error()))
	}
	return resultAndError(binaryResult(binary, out), nil)
}

func ZlibCompress(args ...object.Object) object.Object {
	s, errObj := encOneBinary(BuiltinNameZlibCompress, args)
	if errObj != nil {
		return errObj
	}
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		return newError("zlib_compress: %s", err.Error())
	}
	if err := w.Close(); err != nil {
		return newError("zlib_compress: %s", err.Error())
	}
	return stringObj(buf.String())
}

func ZlibDecompress(args ...object.Object) object.Object {
	return zlibDecompress(args, BuiltinNameZlibDecompress, false)
}

// ZlibDecompressBytes decompresses zlib data into a buffer.
func ZlibDecompressBytes(args ...object.Object) object.Object {
	return zlibDecompress(args, BuiltinNameZlibDecompressBytes, true)
}

func zlibDecompress(args []object.Object, opName string, binary bool) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	s, errObj := requireBinaryArg(opName, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	limit, errObj := resolveDecompressionLimit(opName, args, 2, int64(len(s)))
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	r, err := zlib.NewReader(bytes.NewReader(s))
	if err != nil {
		return resultAndError(nil, newError("%s: %s", opName, err.Error()))
	}
	defer r.Close()
	out, err := readLimited(r, limit)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", opName, err.Error()))
	}
	return resultAndError(binaryResult(binary, out), nil)
}

func ToBase(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	n, errObj := requireIntArg(BuiltinNameToBase, args[0], 1)
	if errObj != nil {
		return errObj
	}
	base, errObj := requireIntArg(BuiltinNameToBase, args[1], 2)
	if errObj != nil {
		return errObj
	}
	if base < 2 || base > 36 {
		return newError("to_base: base must be between 2 and 36, got %d", base)
	}
	return stringObj(strconv.FormatInt(n, int(base)))
}

func FromBase(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	s, errObj := requireStringArg(BuiltinNameFromBase, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	base, errObj := requireIntArg(BuiltinNameFromBase, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if base < 2 || base > 36 {
		return resultAndError(nil, newError("from_base: base must be between 2 and 36, got %d", base))
	}
	n, err := strconv.ParseInt(s, int(base), 64)
	if err != nil {
		return resultAndError(nil, newError("from_base: %s", err.Error()))
	}
	return resultAndError(intObj(n), nil)
}
