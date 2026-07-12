package vm

import (
	"mutant/code"
	"mutant/compiler"
	"mutant/object"
	"testing"
)

var benchGlobalObjectSink object.Object

func benchmarkSetGetGlobal(b *testing.B, mode string, valueFactory func(int) object.Object) {
	b.Helper()
	b.Setenv(vMGlobalMemoryModeEnv, mode)
	vm := New(&compiler.ByteCode{Instructions: code.Instructions{}, Constants: nil})
	vm.ensureGlobalCapacity(0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm.setGlobal(0, valueFactory(i))
		benchGlobalObjectSink = vm.getGlobal(0)
	}
}

func BenchmarkVMGlobalMemoryModeRuntime_IntegerSetGet(b *testing.B) {
	benchmarkSetGetGlobal(b, vMMemoryModeRuntime, func(i int) object.Object {
		return &object.Integer{Value: int64(i)}
	})
}

func BenchmarkVMGlobalMemoryModeWrapper_IntegerSetGet(b *testing.B) {
	benchmarkSetGetGlobal(b, vMMemoryModeWrapper, func(i int) object.Object {
		return &object.Integer{Value: int64(i)}
	})
}

func BenchmarkVMGlobalMemoryModeRuntime_ArraySetGet(b *testing.B) {
	benchmarkSetGetGlobal(b, vMMemoryModeRuntime, func(i int) object.Object {
		return &object.Array{Elements: []object.Object{&object.Integer{Value: int64(i)}}}
	})
}

func BenchmarkVMGlobalMemoryModeWrapper_ArraySetGet(b *testing.B) {
	benchmarkSetGetGlobal(b, vMMemoryModeWrapper, func(i int) object.Object {
		return &object.Array{Elements: []object.Object{&object.Integer{Value: int64(i)}}}
	})
}
