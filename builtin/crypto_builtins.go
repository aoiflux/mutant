package builtin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"

	"mutant/object"
)

// decodeJSONToObject parses JSON bytes into a Mutant object, matching json_parse's
// number handling (integers stay INTEGER, decimals become FLOAT).
func decodeJSONToObject(data []byte) (object.Object, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return jsonValueToObject(v)
}

func X509Parse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	input, errObj := requireStringArg("x509_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	der := []byte(input)
	if block, _ := pem.Decode([]byte(input)); block != nil {
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return resultAndError(nil, newError("x509_parse: %s", err.Error()))
	}

	sha1fp := sha1.Sum(cert.Raw)
	sha256fp := sha256.Sum256(cert.Raw)

	ipStrings := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ipStrings[i] = ip.String()
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"subject":             stringObj(cert.Subject.String()),
		"issuer":              stringObj(cert.Issuer.String()),
		"serial":              stringObj(cert.SerialNumber.String()),
		"not_before":          intObj(cert.NotBefore.Unix()),
		"not_after":           intObj(cert.NotAfter.Unix()),
		"is_ca":               boolObj(cert.IsCA),
		"version":             intObj(int64(cert.Version)),
		"dns_names":           stringArrayObj(cert.DNSNames),
		"ip_addresses":        stringArrayObj(ipStrings),
		"email_addresses":     stringArrayObj(cert.EmailAddresses),
		"key_algorithm":       stringObj(cert.PublicKeyAlgorithm.String()),
		"signature_algorithm": stringObj(cert.SignatureAlgorithm.String()),
		"sha1":                stringObj(hex.EncodeToString(sha1fp[:])),
		"sha256":              stringObj(hex.EncodeToString(sha256fp[:])),
	}), nil)
}

func JWTDecode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	token, errObj := requireStringArg("jwt_decode", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 {
		return resultAndError(nil, newError("jwt_decode: not a JWT (expected at least header.payload)"))
	}

	headerBytes, err := decodeJWTSegment(parts[0])
	if err != nil {
		return resultAndError(nil, newError("jwt_decode: bad header: %s", err.Error()))
	}
	header, err := decodeJSONToObject(headerBytes)
	if err != nil {
		return resultAndError(nil, newError("jwt_decode: header is not JSON: %s", err.Error()))
	}
	payloadBytes, err := decodeJWTSegment(parts[1])
	if err != nil {
		return resultAndError(nil, newError("jwt_decode: bad payload: %s", err.Error()))
	}
	claims, err := decodeJSONToObject(payloadBytes)
	if err != nil {
		return resultAndError(nil, newError("jwt_decode: payload is not JSON: %s", err.Error()))
	}

	algo := ""
	if h, ok := header.(*object.Hash); ok {
		if v := hashValueByKey(h, "alg"); v != nil {
			if s, ok := v.(*object.String); ok {
				algo = s.Value
			}
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"header":            header,
		"claims":            claims,
		"algorithm":         stringObj(algo),
		"signature_present": boolObj(len(parts) == 3 && parts[2] != ""),
		"verified":          boolObj(false),
	}), nil)
}

// decodeJWTSegment decodes a base64url JWT segment, tolerating missing padding.
func decodeJWTSegment(seg string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(seg)
}

func AESEncrypt(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 (key, plaintext)", len(args)))
	}
	key, errObj := requireStringArg("aes_encrypt", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	plaintext, errObj := requireStringArg("aes_encrypt", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	gcm, errObj := newAESGCM("aes_encrypt", key)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return resultAndError(nil, newError("aes_encrypt: %s", err.Error()))
	}
	// Prepend the nonce so aes_decrypt is self-contained.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return resultAndError(stringObj(string(ciphertext)), nil)
}

func AESDecrypt(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 (key, ciphertext)", len(args)))
	}
	key, errObj := requireStringArg("aes_decrypt", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	data, errObj := requireStringArg("aes_decrypt", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	gcm, errObj := newAESGCM("aes_decrypt", key)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	raw := []byte(data)
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return resultAndError(nil, newError("aes_decrypt: ciphertext too short (missing nonce)"))
	}
	nonce, ciphertext := raw[:ns], raw[ns:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return resultAndError(nil, newError("aes_decrypt: %s (wrong key or corrupted data)", err.Error()))
	}
	return resultAndError(stringObj(string(plaintext)), nil)
}

func newAESGCM(op, key string) (cipher.AEAD, *object.Error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, newError("%s: key must be 16, 24, or 32 bytes (AES-128/192/256), got %d", op, len(key))
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, newError("%s: %s", op, err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, newError("%s: %s", op, err.Error())
	}
	return gcm, nil
}

func PEMDecode(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg("pem_decode", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	block, rest := pem.Decode([]byte(s))
	if block == nil {
		return resultAndError(nil, newError("pem_decode: no PEM block found"))
	}
	headers := make(map[string]object.Object, len(block.Headers))
	for k, v := range block.Headers {
		headers[k] = stringObj(v)
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"type":            stringObj(block.Type),
		"headers":         makeHashObject(headers),
		"der_hex":         stringObj(hex.EncodeToString(block.Bytes)),
		"size":            intObj(int64(len(block.Bytes))),
		"remaining_bytes": intObj(int64(len(rest))),
	}), nil)
}
