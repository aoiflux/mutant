package builtin

// Time utilities (dev-sec-platform-upgrades). Small helpers a networked/proxy
// program needs: sleeping for backoff/rate-limiting and a monotonic-ish clock.

import (
	"time"

	"mutant/object"
)

// SleepMs blocks the calling goroutine for the given number of milliseconds.
// sleep_ms(ms INTEGER) -> (true, err)
func SleepMs(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	ms, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `sleep_ms` must be INTEGER, got %s", args[0].Type()))
	}
	if ms.Value > 0 {
		time.Sleep(time.Duration(ms.Value) * time.Millisecond)
	}
	return resultAndError(boolObj(true), nil)
}

// TimeMs returns the current Unix time in milliseconds.
// time_ms() -> (INTEGER, err)
func TimeMs(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}
	return resultAndError(intObj(time.Now().UnixMilli()), nil)
}
