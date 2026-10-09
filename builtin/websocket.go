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
//   ws_read_frame(handle, timeout_ms)      -> (HASH, err)            {fin,rsv1,rsv2,rsv3,opcode,payload,masked,length,is_control}
//   ws_write_frame(handle, opcode, payload, mask, timeout_ms_or_flags?) -> (bytes INT, err)
//
// Opcodes: 0x0 continuation, 0x1 text, 0x2 binary, 0x8 close, 0x9 ping, 0xA pong.
//
// A frame is relayed by handing the hash ws_read_frame returned back to
// ws_write_frame as its fifth argument, which carries the first byte's FIN and
// RSV bits across. Without them the relay was not a relay: an RSV1 frame went
// out uncompressed-but-flagged-compressed and a FIN=0 fragment went out whole
// (M26-NET-017).

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

// wsFirstControlOpcode is the opcode at which a frame is a control frame: 0x8
// close, 0x9 ping, 0xA pong, and 0xB to 0xF reserved for control use (RFC 6455
// section 11.8). A control frame is the one kind the standard constrains by
// size and by fragmentation, so the boundary is named rather than written 0x8
// in three places.
const wsFirstControlOpcode = 0x8

// wsMaxOpcode is the largest opcode a frame can carry, because the field is
// four bits wide. It is a fact about the wire format and not a budget of ours,
// but it has to be checked: the opcode used to be masked with 0x0f, so
// ws_write_frame(h, 16, ...) wrote opcode 0 -- a continuation frame, which is a
// different kind of frame than the caller named.
//
//mutant:format RFC 6455 section 5.2, base framing protocol: the opcode field is four bits
const wsMaxOpcode = 0x0f

// wsMaxControlPayload is how many bytes of payload a control frame may carry.
// The standard fixes it at 125 and requires a peer to fail the connection on a
// longer one, so writing a longer one is not a strictness choice of ours: a
// close frame with a 200-byte reason was a connection the far side dropped
// rather than a close it read.
//
//mutant:format RFC 6455 section 5.5, control frames: "All control frames MUST have a payload length of 125 bytes or less"
const wsMaxControlPayload = 125

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
	mc, timeoutMs, errObj := connAndTimeout(BuiltinNameWsReadFrame, args)
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
	// The three RSV bits are what an extension negotiated in the handshake
	// uses; RSV1 is permessage-deflate (RFC 7692), which Chrome and Firefox
	// ask for by default. They are reported rather than interpreted: this
	// package does not inflate a frame, and a relay that drops the bit
	// hands the far side a payload its own extension state says is
	// compressed and is not.
	rsv1 := header[0]&0x40 != 0
	rsv2 := header[0]&0x20 != 0
	rsv3 := header[0]&0x10 != 0
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
		"rsv1":       boolObj(rsv1),
		"rsv2":       boolObj(rsv2),
		"rsv3":       boolObj(rsv3),
		"opcode":     intObj(int64(opcode)),
		"masked":     boolObj(masked),
		"length":     intObj(length),
		"is_control": boolObj(opcode >= wsFirstControlOpcode),
		"payload":    stringObj(string(payload)),
	}), nil)
}

// wsFrameHeaderFlags are the first byte's bits a caller may choose -- FIN and
// the three RSV bits -- together with the write deadline, which travels with
// them so that naming a bit does not cost the default timeout.
//
// They arrive as the optional fifth argument of ws_write_frame, which is either
// the write deadline on its own, as it has always been, or a hash. The hash is
// read for five keys and ignores every other one, so the hash ws_read_frame
// returned can be handed straight back: that is the relay this package exists
// for, and until now the relay could not say what it had read.
//
// "masked" is deliberately not one of the keys. Masking is a property of the
// direction a frame travels -- a client masks, a server must not (RFC 6455
// section 5.3) -- so it belongs to the connection being written to and not to
// the frame that was read. It stays the fourth argument, where the caller has
// to state it.
type wsFrameHeaderFlags struct {
	fin       bool
	rsv1      bool
	rsv2      bool
	rsv3      bool
	timeoutMs int64
}

// headerByte builds a frame's first byte: FIN, the three RSV bits, the opcode.
func (f wsFrameHeaderFlags) headerByte(opcode byte) byte {
	var first byte
	if f.fin {
		first |= 0x80
	}
	if f.rsv1 {
		first |= 0x40
	}
	if f.rsv2 {
		first |= 0x20
	}
	if f.rsv3 {
		first |= 0x10
	}
	return first | opcode
}

// wsWriteFrameFlags reads ws_write_frame's optional fifth argument.
//
// A missing key keeps the default -- FIN set, no RSV bit, the default deadline
// -- which is what every call written before the flags existed gets. A key that
// is present and of the wrong type is refused rather than ignored: a frame
// written with "fin": 0 silently meaning fin true is the same class of defect as
// the dropped bits this argument exists to fix.
func wsWriteFrameFlags(args []object.Object) (wsFrameHeaderFlags, *object.Error) {
	flags := wsFrameHeaderFlags{fin: true, timeoutMs: int64(defaultWriteTimeoutMs)}
	if len(args) != 5 {
		return flags, nil
	}
	switch arg := args[4].(type) {
	case *object.Integer:
		flags.timeoutMs = arg.Value
	case *object.Hash, *object.Struct:
		bits := []struct {
			key   string
			field *bool
		}{
			{"fin", &flags.fin},
			{"rsv1", &flags.rsv1},
			{"rsv2", &flags.rsv2},
			{"rsv3", &flags.rsv3},
		}
		for _, bit := range bits {
			value, ok := objField(arg, bit.key)
			if !ok {
				continue
			}
			b, ok := value.(*object.Boolean)
			if !ok {
				return flags, newError("ws_write_frame: %s in the frame flags must be BOOLEAN, got %s", bit.key, value.Type())
			}
			*bit.field = b.Value
		}
		if value, ok := objField(arg, "timeout_ms"); ok {
			ms, ok := value.(*object.Integer)
			if !ok {
				return flags, newError("ws_write_frame: timeout_ms in the frame flags must be INTEGER, got %s", value.Type())
			}
			flags.timeoutMs = ms.Value
		}
	default:
		return flags, newError(
			"argument 5 to `ws_write_frame` must be INTEGER (the write deadline) or HASH (the frame's fin, rsv1, rsv2, rsv3 and timeout_ms), got %s",
			args[4].Type())
	}
	return flags, nil
}

// WSWriteFrame builds and writes a single WebSocket frame. Per RFC 6455, frames
// a client sends to a server MUST be masked (mask=true); server->client frames
// MUST NOT be (mask=false). FIN is set and no RSV bit is, unless the optional
// fifth argument says otherwise -- see wsFrameHeaderFlags, which is also how a
// frame read off one connection is relayed faithfully onto another. A write
// deadline (default 30s, or the timeout; <=0 blocks forever) keeps a stalled
// peer from hanging the write.
func WSWriteFrame(args ...object.Object) object.Object {
	if len(args) != 4 && len(args) != 5 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4 or 5", len(args)))
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
	flags, flagErr := wsWriteFrameFlags(args)
	if flagErr != nil {
		return resultAndError(nil, flagErr)
	}

	mc, ok := lookupConn(handle.Value)
	if !ok {
		return resultAndError(nil, newError("ws_write_frame: unknown connection handle %d", handle.Value))
	}

	payload := []byte(payloadObj.Value)
	if opcodeObj.Value < 0 || opcodeObj.Value > wsMaxOpcode {
		return resultAndError(nil, newError(
			"ws_write_frame: %d is not an opcode: a frame has four bits for it, so 0 to %d, and the low four bits of %d name opcode %d -- a different kind of frame than the one asked for",
			opcodeObj.Value, wsMaxOpcode, opcodeObj.Value, opcodeObj.Value&0x0f))
	}
	opcode := byte(opcodeObj.Value)
	if opcode >= wsFirstControlOpcode {
		if len(payload) > wsMaxControlPayload {
			return resultAndError(nil, newError(
				"ws_write_frame: a control frame carries at most %d bytes of payload and this one holds %d (RFC 6455 section 5.5); a peer fails the connection on a longer one, so it would not be read",
				wsMaxControlPayload, len(payload)))
		}
		if !flags.fin {
			return resultAndError(nil, newError(
				"ws_write_frame: a control frame cannot be fragmented (RFC 6455 section 5.5), so fin cannot be false on opcode %d",
				opcode))
		}
	}

	var b bytes.Buffer
	b.WriteByte(flags.headerByte(opcode))

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

	setWriteDeadline(mc.conn, flags.timeoutMs)
	n, err := mc.conn.Write(b.Bytes())
	if err != nil {
		return resultAndError(nil, newError("ws_write_frame: %s", err.Error()))
	}
	return resultAndError(intObj(int64(n)), nil)
}
