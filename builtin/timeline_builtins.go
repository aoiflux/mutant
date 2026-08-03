package builtin

import (
	"sort"
	"strings"
	"time"

	"mutant/object"
)

// Seconds between the 1601-01-01 (Windows) epoch and the 1970 Unix epoch.
const filetimeEpochDeltaSec = 11644473600

// TimestampNormalize converts a timestamp in a variety of forensic formats to a
// canonical {unix, unix_ms, iso, format} hash. Supported formats: unix (s/ms/us/
// ns), filetime (Windows 100-ns since 1601), webkit/chrome (us since 1601), dos
// (packed 32-bit), iso (RFC3339 string). Default format "auto" detects unix
// second/ms/us/ns by magnitude (or parses an ISO string); filetime/webkit/dos
// must be named explicitly.
func TimestampNormalize(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	format := "auto"
	if len(args) == 2 {
		f, errObj := requireStringArg("timestamp_normalize", args[1], 2)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		format = strings.ToLower(strings.TrimSpace(f))
	}

	unixSec, unixMs, used, errObj := normalizeTimestamp(args[0], format)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	iso := time.Unix(unixSec, (unixMs%1000)*int64(time.Millisecond)).UTC().Format(time.RFC3339Nano)
	return resultAndError(makeHashObject(map[string]object.Object{
		"unix":    intObj(unixSec),
		"unix_ms": intObj(unixMs),
		"iso":     stringObj(iso),
		"format":  stringObj(used),
	}), nil)
}

func normalizeTimestamp(value object.Object, format string) (int64, int64, string, *object.Error) {
	// String input is only meaningful as an ISO/RFC3339 timestamp.
	if s, ok := value.(*object.String); ok {
		if format == "auto" || format == "iso" || format == "rfc3339" {
			t, err := parseISOTime(s.Value)
			if err != nil {
				return 0, 0, "", newError("timestamp_normalize: cannot parse %q as ISO time", s.Value)
			}
			return t.Unix(), t.UnixMilli(), "iso", nil
		}
		return 0, 0, "", newError("timestamp_normalize: format %q requires an INTEGER value", format)
	}

	v, ok := value.(*object.Integer)
	if !ok {
		return 0, 0, "", newError("timestamp_normalize: value must be INTEGER or STRING, got %s", value.Type())
	}
	n := v.Value

	switch format {
	case "auto":
		return autoNumericTimestamp(n)
	case "unix", "epoch", "s", "sec", "seconds":
		return n, n * 1000, "unix", nil
	case "unix_ms", "ms", "millis", "milliseconds":
		return n / 1000, n, "unix_ms", nil
	case "unix_us", "us", "micro", "microseconds":
		return n / 1_000_000, n / 1000, "unix_us", nil
	case "unix_ns", "ns", "nano", "nanoseconds":
		return n / 1_000_000_000, n / 1_000_000, "unix_ns", nil
	case "filetime", "win_filetime":
		sec := n/10_000_000 - filetimeEpochDeltaSec
		return sec, n/10_000 - filetimeEpochDeltaSec*1000, "filetime", nil
	case "webkit", "chrome":
		sec := n/1_000_000 - filetimeEpochDeltaSec
		return sec, n/1000 - filetimeEpochDeltaSec*1000, "webkit", nil
	case "dos":
		return dosTimestamp(uint32(n))
	default:
		return 0, 0, "", newError("timestamp_normalize: unknown format %q", format)
	}
}

func autoNumericTimestamp(n int64) (int64, int64, string, *object.Error) {
	abs := n
	if abs < 0 {
		abs = -abs
	}
	switch {
	case abs < 100_000_000_000: // < ~year 5138 in seconds
		return n, n * 1000, "unix", nil
	case abs < 100_000_000_000_000:
		return n / 1000, n, "unix_ms", nil
	case abs < 100_000_000_000_000_000:
		return n / 1_000_000, n / 1000, "unix_us", nil
	default:
		return n / 1_000_000_000, n / 1_000_000, "unix_ns", nil
	}
}

func dosTimestamp(v uint32) (int64, int64, string, *object.Error) {
	dosDate := (v >> 16) & 0xFFFF
	dosTime := v & 0xFFFF
	day := int(dosDate & 0x1F)
	month := int((dosDate >> 5) & 0x0F)
	year := 1980 + int((dosDate>>9)&0x7F)
	sec := int((dosTime & 0x1F) * 2)
	min := int((dosTime >> 5) & 0x3F)
	hour := int((dosTime >> 11) & 0x1F)
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return 0, 0, "", newError("timestamp_normalize: invalid DOS timestamp 0x%08x", v)
	}
	t := time.Date(year, time.Month(month), day, hour, min, sec, 0, time.UTC)
	return t.Unix(), t.UnixMilli(), "dos", nil
}

func parseISOTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	layouts := []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", "2006-01-02T15:04:05",
		"2006-01-02", "2006/01/02 15:04:05", "01/02/2006 15:04:05",
	}
	var lastErr error
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		} else {
			lastErr = err
		}
	}
	return time.Time{}, lastErr
}

// --- timeline sort / merge ---

func TimelineSort(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=1 or 2", len(args))
	}
	events, errObj := requireArrayArg("timeline_sort", args[0], 1)
	if errObj != nil {
		return errObj
	}
	field := "ts"
	if len(args) == 2 {
		f, errObj := requireStringArg("timeline_sort", args[1], 2)
		if errObj != nil {
			return errObj
		}
		field = f
	}
	sorted, errObj := sortEventsByField("timeline_sort", events.Elements, field)
	if errObj != nil {
		return errObj
	}
	return &object.Array{Elements: sorted}
}

func TimelineMerge(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=1 or 2", len(args))
	}
	sources, errObj := requireArrayArg("timeline_merge", args[0], 1)
	if errObj != nil {
		return errObj
	}
	field := "ts"
	if len(args) == 2 {
		f, errObj := requireStringArg("timeline_merge", args[1], 2)
		if errObj != nil {
			return errObj
		}
		field = f
	}

	merged := make([]object.Object, 0)
	for i, src := range sources.Elements {
		arr, ok := src.(*object.Array)
		if !ok {
			return newError("timeline_merge: source %d must be an ARRAY of events, got %s", i, src.Type())
		}
		merged = append(merged, arr.Elements...)
	}
	sorted, errObj := sortEventsByField("timeline_merge", merged, field)
	if errObj != nil {
		return errObj
	}
	return &object.Array{Elements: sorted}
}

// sortEventsByField stable-sorts event hashes by a numeric timestamp field
// (ascending); events missing the field sort to the end.
func sortEventsByField(op string, events []object.Object, field string) ([]object.Object, *object.Error) {
	out := make([]object.Object, len(events))
	copy(out, events)
	for i, ev := range out {
		if _, ok := ev.(*object.Hash); !ok {
			return nil, newError("%s: event %d must be a HASH, got %s", op, i, ev.Type())
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, oki := eventTimestamp(out[i].(*object.Hash), field)
		tj, okj := eventTimestamp(out[j].(*object.Hash), field)
		if oki != okj {
			return oki // present sorts before missing
		}
		return ti < tj
	})
	return out, nil
}

func eventTimestamp(ev *object.Hash, field string) (float64, bool) {
	v := hashValueByKey(ev, field)
	switch n := v.(type) {
	case *object.Integer:
		return float64(n.Value), true
	case *object.Float:
		return n.Value, true
	default:
		return 0, false
	}
}
