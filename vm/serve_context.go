package vm

// serve_conn() and serve_arg() report the context the running program was
// dispatched with: for a net_serve handler, the connection it is serving and the
// shared arg net_serve was given.
//
// They are executor-native for the same structural reason the higher-order
// builtins are -- the answer lives in the VM, and the registered Fn has no way to
// reach it. The registered Fn is still the honest answer outside a running
// program, which is that there is no context, so the same handler file compiles
// and runs standalone.

import (
	"mutant/global"
	"mutant/object"
)

// SetServeContext records the connection handle and shared arg this VM is
// running for. net_serve calls it before Run; worker VMs inherit it, so work a
// handler hands to spawn or pmap keeps the connection it belongs to.
func (vm *VM) SetServeContext(conn int64, arg object.Object) {
	vm.serveContextSet = true
	vm.serveConn = conn
	vm.serveArg = arg
}

func (vm *VM) serveConnValue(args []object.Object) (object.Object, error) {
	if len(args) != 0 {
		return vmPair(nil, vmErrorf("wrong number of arguments. got=%d, want=0", len(args))), nil
	}
	if !vm.serveContextSet {
		return vmPair(global.Null, nil), nil
	}
	return vmPair(&object.Integer{Value: vm.serveConn}, nil), nil
}

func (vm *VM) serveArgValue(args []object.Object) (object.Object, error) {
	if len(args) != 0 {
		return vmPair(nil, vmErrorf("wrong number of arguments. got=%d, want=0", len(args))), nil
	}
	return vmPair(vm.serveArg, nil), nil
}
