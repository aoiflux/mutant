package builtin

// WebSocket (RFC 6455) frame primitives (dev-sec-platform-upgrades).
//
// These sit directly on the existing managedConn buffered reader (secure_net.go),
// so a Mutant proxy can intercept a WebSocket after the HTTP Upgrade: read one
// frame, inspect/rewrite it, write it to the other side. Deliberately low-level
// (handshake helper + read/write frame) rather than wrapping a WS library, which
// would want to own the net.Conn and fight the shared bufio.Reader used by the
// http_conn_* builtins.
//
//   ws_accept_key(client_key)              -> (accept STRING, err)   handshake helper
//   ws_read_frame(handle, timeout_ms)      -> (HASH, err)            {fin,opcode,payload,masked,length,is_control}
//   ws_write_frame(handle, opcode, payload, mask) -> (bytes INT, err)
//
// Opcodes: 0x0 continuation, 0x1 text, 0x2 binary, 0x8 close, 0x9 ping, 0xA pong.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"

	"mutant/object"
)

// wsMagicGUID is the RFC 6455 handshake constant.
const wsMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WSAcceptKey computes the Sec-WebSocket-Accept value for a client's
// Sec-WebSocket-Key, so a proxy acting as the server can complete the 101
// handshake: base64(sha1(key + magic)).
func WSAcceptKey(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	key, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `ws_accept_key` must be STRING, got %s", args[0].Type()))
	}
	sum := sha1.Sum([]byte(key.Value + wsMagicGUID))
	return resultAndError(stringObj(base64.StdEncoding.EncodeToString(sum[:])), nil)
}

// WSReadFrame reads exactly one WebSocket frame from a connection handle and
// returns it fully unmasked. Honours the read timeout like http_conn_read_*.
func WSReadFrame(args ...object.Object) object.Object {
	mc, timeoutMs, errObj := connAndTimeout("ws_read_frame", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	applyReadDeadline(mc, timeoutMs)
	r := mc.buffered()

	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return resultAndError(nil, newError("ws_read_frame: reading header: %s", err.Error()))
	}
	fin := header[0]&0x80 != 0
	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	length := int64(header[1] & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return resultAndError(nil, newError("ws_read_frame: reading 16-bit length: %s", err.Error()))
		}
		length = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return resultAndError(nil, newError("ws_read_frame: reading 64-bit length: %s", err.Error()))
		}
		length = int64(binary.BigEndian.Uint64(ext[:]))
	}
	if length < 0 || length > maxHTTPBodyBytes {
		return resultAndError(nil, newError("ws_read_frame: frame payload too large: %d (max %d)", length, maxHTTPBodyBytes))
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return resultAndError(nil, newError("ws_read_frame: reading mask key: %s", err.Error()))
		}
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return resultAndError(nil, newError("ws_read_frame: reading payload: %s", err.Error()))
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"fin":        boolObj(fin),
		"opcode":     intObj(int64(opcode)),
		"masked":     boolObj(masked),
		"length":     intObj(length),
		"is_control": boolObj(opcode >= 0x8),
		"payload":    stringObj(string(payload)),
	}), nil)
}

// WSWriteFrame builds and writes a single WebSocket frame. Per RFC 6455, frames
// a client sends to a server MUST be masked (mask=true); server->client frames
// MUST NOT be (mask=false). FIN is always set (no fragmentation).
func WSWriteFrame(args ...object.Object) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `ws_write_frame` must be INTEGER, got %s", args[0].Type()))
	}
	opcodeObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `ws_write_frame` must be INTEGER, got %s", args[1].Type()))
	}
	payloadObj, ok := args[2].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `ws_write_frame` must be STRING, got %s", args[2].Type()))
	}
	maskObj, ok := args[3].(*object.Boolean)
	if !ok {
		return resultAndError(nil, newError("argument 4 to `ws_write_frame` must be BOOLEAN, got %s", args[3].Type()))
	}

	mc, ok := lookupConn(handle.Value)
	if !ok {
		return resultAndError(nil, newError("ws_write_frame: unknown connection handle %d", handle.Value))
	}

	payload := []byte(payloadObj.Value)
	opcode := byte(opcodeObj.Value & 0x0f)

	var b bytes.Buffer
	b.WriteByte(0x80 | opcode) // FIN + opcode

	maskBit := byte(0)
	if maskObj.Value {
		maskBit = 0x80
	}
	length := len(payload)
	switch {
	case length < 126:
		b.WriteByte(maskBit | byte(length))
	case length < 65536:
		b.WriteByte(maskBit | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(length))
		b.Write(ext[:])
	default:
		b.WriteByte(maskBit | 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(length))
		b.Write(ext[:])
	}

	if maskObj.Value {
		var maskKey [4]byte
		if _, err := rand.Read(maskKey[:]); err != nil {
			return resultAndError(nil, newError("ws_write_frame: generating mask: %s", err.Error()))
		}
		b.Write(maskKey[:])
		masked := make([]byte, length)
		for i := range payload {
			masked[i] = payload[i] ^ maskKey[i%4]
		}
		b.Write(masked)
	} else {
		b.Write(payload)
	}

	n, err := mc.conn.Write(b.Bytes())
	if err != nil {
		return resultAndError(nil, newError("ws_write_frame: %s", err.Error()))
	}
	return resultAndError(intObj(int64(n)), nil)
}
