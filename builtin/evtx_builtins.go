package builtin

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Velocidex/ordereddict"
	evtx "www.velocidex.com/golang/evtx"

	"mutant/object"
)

// EvtxParse decodes a Windows Event Log (.evtx) file. It walks every ElfChnk
// chunk, parses each event record's BinXML (templates + substitutions) via the
// Velocidex evtx library, and returns the fully-expanded event tree per record
// plus convenience summary fields (event_id, provider, channel, computer, level,
// record_id, timestamp).
//
// Returns {source, chunk_count, count, records:[...]} paired with an error.
func EvtxParse(args ...object.Object) object.Object {
	return evtxParseBuiltin(BuiltinNameEvtxParse, false, args...)
}

// EvtxParseBytes is evtx_parse with binary event values returned as BYTES
// buffers rather than hex strings.
//
// It is a second builtin rather than a second field because an event tree's
// shape comes from the record: the keys are element names lifted out of the
// BinXML being parsed, nested arbitrarily deep, so there is no key we own to
// hang an alternative rendering on and no fixed place a caller could look.
//
// What changes is one arm of evtxValue. Binary is what EVTX calls BinaryType --
// the Data element of a Windows Defender or driver event, say -- and evtx_parse
// renders it with %x, which is faithful but leaves the caller to hex_decode it
// before anything can read it.
func EvtxParseBytes(args ...object.Object) object.Object {
	return evtxParseBuiltin(BuiltinNameEvtxParseBytes, true, args...)
}

func evtxParseBuiltin(name string, rawBinary bool, args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("%s: panic during parse: %v", name, r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg(name, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	f, err := os.Open(path)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", name, err.Error()))
	}
	defer f.Close()

	chunks, err := evtx.GetChunks(f)
	if err != nil {
		return resultAndError(nil, newError("%s: not a valid EVTX file: %s", name, err.Error()))
	}

	records := make([]object.Object, 0, len(chunks)*100)
	for _, chunk := range chunks {
		for _, rec := range parseEvtxChunk(chunk) {
			records = append(records, evtxRecordToHash(rec, rawBinary))
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"source":      stringObj("evtx"),
		"chunk_count": intObj(int64(len(chunks))),
		"count":       intObj(int64(len(records))),
		"records":     &object.Array{Elements: records},
	}), nil)
}

// parseEvtxChunk parses one chunk, isolating panics/errors so a single corrupt
// chunk cannot abort the whole file.
func parseEvtxChunk(chunk *evtx.Chunk) (recs []*evtx.EventRecord) {
	defer func() {
		if r := recover(); r != nil {
			recs = nil
		}
	}()
	parsed, err := chunk.Parse(0)
	if err != nil {
		return nil
	}
	return parsed
}

func evtxRecordToHash(rec *evtx.EventRecord, rawBinary bool) object.Object {
	event := evtxValue(rec.Event, rawBinary)
	unix := filetimeToUnix(rec.Header.FileTime)

	m := map[string]object.Object{
		"record_id":     intObj(int64(rec.Header.RecordID)),
		"timestamp":     intObj(unix),
		"timestamp_iso": stringObj(unixToISO(unix)),
		"event":         event,
	}

	// Best-effort summary fields from Event/System; shapes vary across providers.
	system := evtxDescend(event, "Event", "System")
	eventID, _ := evtxAsInt(evtxDescend(system, "EventID"))
	m["event_id"] = intObj(eventID)
	m["event_record_id"] = intObj(evtxIntOr(evtxDescend(system, "EventRecordID")))
	m["level"] = intObj(evtxIntOr(evtxDescend(system, "Level")))
	m["channel"] = stringObj(evtxAsStr(evtxDescend(system, "Channel")))
	m["computer"] = stringObj(evtxAsStr(evtxDescend(system, "Computer")))

	provider := evtxDescend(system, "Provider")
	providerName := evtxAsStr(provider)
	if providerName == "" {
		providerName = evtxAsStr(evtxDescend(provider, "Name"))
	}
	m["provider"] = stringObj(providerName)

	return makeHashObject(m)
}

// evtxDescend walks an object.Hash tree by successive keys, returning nil if any
// step is missing or not a hash.
func evtxDescend(o object.Object, keys ...string) object.Object {
	cur := o
	for _, k := range keys {
		h, ok := cur.(*object.Hash)
		if !ok {
			return nil
		}
		cur = hashValueByKey(h, k)
		if cur == nil {
			return nil
		}
	}
	return cur
}

func evtxAsInt(o object.Object) (int64, bool) {
	switch v := o.(type) {
	case *object.Integer:
		return v.Value, true
	case *object.String:
		if n, err := strconv.ParseInt(v.Value, 10, 64); err == nil {
			return n, true
		}
	case *object.Hash:
		// e.g. EventID rendered as {Value: 4624, Qualifiers: ...}
		if inner := hashValueByKey(v, "Value"); inner != nil {
			return evtxAsInt(inner)
		}
	}
	return 0, false
}

func evtxIntOr(o object.Object) int64 {
	n, _ := evtxAsInt(o)
	return n
}

func evtxAsStr(o object.Object) string {
	switch v := o.(type) {
	case *object.String:
		return v.Value
	case *object.Integer:
		return strconv.FormatInt(v.Value, 10)
	}
	return ""
}

// evtxValueToObject recursively converts a Velocidex ordereddict event tree into
// mutant objects, rendering binary as hex the way evtx_parse does.
func evtxValueToObject(v interface{}) object.Object {
	return evtxValue(v, false)
}

// evtxValue is the same walk with a say in how binary is rendered: as a BYTES
// buffer when rawBinary is set, as hex otherwise. Every other arm is shared, so
// the two builtins cannot drift apart on anything but the one value type they
// were written to disagree about.
func evtxValue(v interface{}, rawBinary bool) object.Object {
	switch val := v.(type) {
	case nil:
		return &object.Null{}
	case *ordereddict.Dict:
		m := make(map[string]object.Object, val.Len())
		for _, k := range val.Keys() {
			vv, _ := val.Get(k)
			m[k] = evtxValue(vv, rawBinary)
		}
		return makeHashObject(m)
	case []interface{}:
		elems := make([]object.Object, len(val))
		for i, e := range val {
			elems[i] = evtxValue(e, rawBinary)
		}
		return &object.Array{Elements: elems}
	case string:
		return stringObj(val)
	case bool:
		return boolObj(val)
	case time.Time:
		return stringObj(val.UTC().Format(time.RFC3339))
	case []byte:
		if rawBinary {
			// Cloned, because val is not ours. The library's ConsumeBytes returns
			// buff[offset:offset+size] -- a window onto the whole parsed chunk, which
			// every other value in that chunk is also a window onto. An *object.Bytes
			// is mutable from a script, so handing the window back would put a
			// parser's buffer under a script's pen, and would pin the entire chunk in
			// memory for the sake of a few bytes.
			return &object.Bytes{Value: append([]byte(nil), val...)}
		}
		return stringObj(fmt.Sprintf("%x", val))
	case int:
		return intObj(int64(val))
	case int8:
		return intObj(int64(val))
	case int16:
		return intObj(int64(val))
	case int32:
		return intObj(int64(val))
	case int64:
		return intObj(val)
	case uint:
		return intObj(int64(val))
	case uint8:
		return intObj(int64(val))
	case uint16:
		return intObj(int64(val))
	case uint32:
		return intObj(int64(val))
	case uint64:
		return intObj(int64(val))
	case float32:
		return floatObj(float64(val))
	case float64:
		return floatObj(val)
	default:
		return stringObj(fmt.Sprintf("%v", val))
	}
}
