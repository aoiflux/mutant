package builtin

import (
	"net"
	"time"

	"mutant/object"
)

func NetResolve(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	host, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `net_resolve` must be STRING, got %s", args[0].Type()))
	}
	addrs, err := net.LookupHost(host.Value)
	if err != nil {
		return resultAndError(nil, newError("net_resolve: %s", err.Error()))
	}
	elements := make([]object.Object, 0, len(addrs))
	for _, addr := range addrs {
		elements = append(elements, stringObj(addr))
	}
	return resultAndError(&object.Array{Elements: elements}, nil)
}

func NetDial(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	addr, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_dial` must be STRING, got %s", args[0].Type()))
	}
	timeoutMs, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_dial` must be INTEGER, got %s", args[1].Type()))
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr.Value, time.Duration(timeoutMs.Value)*time.Millisecond)
	elapsed := time.Since(start).Milliseconds()

	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	} else {
		conn.Close()
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"ok":         boolObj(err == nil),
		"latency_ms": intObj(elapsed),
		"error":      stringObj(errMsg),
	}), nil)
}
