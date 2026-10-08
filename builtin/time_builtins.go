package builtin

import (
	"time"

	"mutant/object"
)

func TimeNow(args ...object.Object) object.Object {
	if len(args) != 0 {
		return newError("wrong number of arguments. got=%d, want=0", len(args))
	}
	now := time.Now().UTC()
	return makeHashObject(map[string]object.Object{
		"unix":   intObj(now.Unix()),
		"iso":    stringObj(now.Format(time.RFC3339)),
		"year":   intObj(int64(now.Year())),
		"month":  intObj(int64(now.Month())),
		"day":    intObj(int64(now.Day())),
		"hour":   intObj(int64(now.Hour())),
		"minute": intObj(int64(now.Minute())),
		"second": intObj(int64(now.Second())),
	})
}

func TimeUnix(args ...object.Object) object.Object {
	if len(args) != 0 {
		return newError("wrong number of arguments. got=%d, want=0", len(args))
	}
	return intObj(time.Now().Unix())
}

func TimeFormat(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	unix, errObj := requireIntArg(BuiltinNameTimeFormat, args[0], 1)
	if errObj != nil {
		return errObj
	}
	layout, errObj := requireStringArg(BuiltinNameTimeFormat, args[1], 2)
	if errObj != nil {
		return errObj
	}
	return stringObj(time.Unix(unix, 0).UTC().Format(layout))
}

func TimeParse(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	value, errObj := requireStringArg(BuiltinNameTimeParse, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	layout, errObj := requireStringArg(BuiltinNameTimeParse, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	// Against UTC rather than against the host. time.Parse resolves a zone
	// abbreviation -- the MST layout verb -- only when it belongs to
	// time.Local, so the same text gave two different instants on two
	// examiners' machines (M26-BLT-003). A layout with no zone element is
	// unaffected, because time.Parse already defaults such a layout to UTC,
	// and so is a numeric offset, which carries its own.
	t, err := time.ParseInLocation(layout, value, time.UTC)
	if err != nil {
		return resultAndError(nil, newError("time_parse: %s", err.Error()))
	}
	if name, fabricated := timeParseFabricatedZone(t); fabricated {
		return resultAndError(nil, newError(
			"time_parse: %q is a zone abbreviation this cannot resolve, and Go reads an "+
				"unresolvable one as +0000 without an error -- so the instant would come back "+
				"shifted by that zone's real offset and look valid. An abbreviation is ambiguous "+
				"in any case: IST is +0530, +0100 and +0200 to three different places, so there is "+
				"no table to resolve it by. State the offset instead -- a layout like "+
				"\"2006-01-02 15:04 -0700\", or RFC3339 -- or keep the abbreviation beside its "+
				"offset, as in \"2006-01-02 15:04 MST-0700\"", name))
	}
	return resultAndError(intObj(t.Unix()), nil)
}

// timeParseFabricatedZone names the zone of a parsed time when Go invented that
// zone rather than resolving it, which is the case time_parse refuses.
//
// time.ParseInLocation resolves a zone abbreviation only when the abbreviation
// belongs to the location it is given. For any other abbreviation it keeps the
// name, uses offset 0 and returns no error, so the result is a timestamp that
// is wrong by that zone's real offset and says nothing about it.
//
// A zone that genuinely means +0000 is told apart by its name: UTC and GMT are
// the only such abbreviations Go accepts. It rejects "UT" and a bare "Z"
// outright against this layout verb, so neither reaches here. The three shapes
// that must keep working all arrive named or offset: a non-zero numeric offset
// has no zone name and a real offset, a "+0000" numeric offset is named "UTC"
// by Go, and a layout with no zone element takes the location's own name, which
// is UTC here. So all three are resolved rather than fabricated, and pass.
func timeParseFabricatedZone(t time.Time) (string, bool) {
	name, offset := t.Zone()
	if offset != 0 || name == "" || name == "UTC" || name == "GMT" {
		return name, false
	}
	return name, true
}

func TimeDiff(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	a, errObj := requireIntArg(BuiltinNameTimeDiff, args[0], 1)
	if errObj != nil {
		return errObj
	}
	b, errObj := requireIntArg(BuiltinNameTimeDiff, args[1], 2)
	if errObj != nil {
		return errObj
	}
	return intObj(a - b)
}

func TimeAdd(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	t, errObj := requireIntArg(BuiltinNameTimeAdd, args[0], 1)
	if errObj != nil {
		return errObj
	}
	seconds, errObj := requireIntArg(BuiltinNameTimeAdd, args[1], 2)
	if errObj != nil {
		return errObj
	}
	return intObj(t + seconds)
}
