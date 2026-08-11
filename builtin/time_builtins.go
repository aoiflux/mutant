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
	unix, errObj := requireIntArg("time_format", args[0], 1)
	if errObj != nil {
		return errObj
	}
	layout, errObj := requireStringArg("time_format", args[1], 2)
	if errObj != nil {
		return errObj
	}
	return stringObj(time.Unix(unix, 0).UTC().Format(layout))
}

func TimeParse(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	value, errObj := requireStringArg("time_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	layout, errObj := requireStringArg("time_parse", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	t, err := time.Parse(layout, value)
	if err != nil {
		return resultAndError(nil, newError("time_parse: %s", err.Error()))
	}
	return resultAndError(intObj(t.Unix()), nil)
}

func TimeDiff(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	a, errObj := requireIntArg("time_diff", args[0], 1)
	if errObj != nil {
		return errObj
	}
	b, errObj := requireIntArg("time_diff", args[1], 2)
	if errObj != nil {
		return errObj
	}
	return intObj(a - b)
}

func TimeAdd(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	t, errObj := requireIntArg("time_add", args[0], 1)
	if errObj != nil {
		return errObj
	}
	seconds, errObj := requireIntArg("time_add", args[1], 2)
	if errObj != nil {
		return errObj
	}
	return intObj(t + seconds)
}
