package builtin

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"io"
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

func Base64Encode(args ...object.Object) object.Object {
	s, errObj := encOneString("base64_encode", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(base64.StdEncoding.EncodeToString([]byte(s)))
}

func Base64Decode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg("base64_decode", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return resultAndError(nil, newError("base64_decode: %s", err.Error()))
	}
	return resultAndError(stringObj(string(decoded)), nil)
}

func Base64URLEncode(args ...object.Object) object.Object {
	s, errObj := encOneString("base64url_encode", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(base64.URLEncoding.EncodeToString([]byte(s)))
}

func Base64URLDecode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg("base64url_decode", args[0], 1)
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
	s, errObj := encOneString("base32_encode", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(base32.StdEncoding.EncodeToString([]byte(s)))
}

func Base32Decode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg("base32_decode", args[0], 1)
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
	s, errObj := encOneString("hex_encode", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(hex.EncodeToString([]byte(s)))
}

func HexDecode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg("hex_decode", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return resultAndError(nil, newError("hex_decode: %s", err.Error()))
	}
	return resultAndError(stringObj(string(decoded)), nil)
}

func URLEncode(args ...object.Object) object.Object {
	s, errObj := encOneString("url_encode", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(url.QueryEscape(s))
}

func URLDecode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg("url_decode", args[0], 1)
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
	s, errObj := encOneString("gzip", args)
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

func Gunzip(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg("gunzip", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	r, err := gzip.NewReader(bytes.NewReader([]byte(s)))
	if err != nil {
		return resultAndError(nil, newError("gunzip: %s", err.Error()))
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return resultAndError(nil, newError("gunzip: %s", err.Error()))
	}
	return resultAndError(stringObj(string(out)), nil)
}

func ZlibCompress(args ...object.Object) object.Object {
	s, errObj := encOneString("zlib_compress", args)
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
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg("zlib_decompress", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	r, err := zlib.NewReader(bytes.NewReader([]byte(s)))
	if err != nil {
		return resultAndError(nil, newError("zlib_decompress: %s", err.Error()))
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return resultAndError(nil, newError("zlib_decompress: %s", err.Error()))
	}
	return resultAndError(stringObj(string(out)), nil)
}

func ToBase(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	n, errObj := requireIntArg("to_base", args[0], 1)
	if errObj != nil {
		return errObj
	}
	base, errObj := requireIntArg("to_base", args[1], 2)
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
	s, errObj := requireStringArg("from_base", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	base, errObj := requireIntArg("from_base", args[1], 2)
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
