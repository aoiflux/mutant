package builtin

import "mutant/object"

// The test framework's builtins. Every one of them is executor-native, for the
// two reasons this package's higher_order.go already lists.
//
// `test` needs to CALL the function it is handed, which the registered Fn has
// no way to do. The assertions need the other thing an executor has: a failed
// assertion is not something the caller is obliged to look at -- a statement
// `assert_eq(a, b);` pops its result and moves on -- so the failure has to be
// recorded somewhere the run can be asked about afterwards, and the only thing
// that outlives the call is the executor. It is also the only thing that knows
// WHERE the call was: the position comes from the executing frame's line table.
//
// The engine is vm/testing.go. The registered Fn here is never reached from a
// running program; it exists so the names resolve and compile like any builtin.
var (
	testBuiltin       = &BuiltIn{Fn: testingStub(BuiltinNameTest)}
	beforeEachBuiltin = &BuiltIn{Fn: testingStub(BuiltinNameBeforeEach)}
	afterEachBuiltin  = &BuiltIn{Fn: testingStub(BuiltinNameAfterEach)}

	assertBuiltin         = &BuiltIn{Fn: testingStub(BuiltinNameAssert)}
	assertEqBuiltin       = &BuiltIn{Fn: testingStub(BuiltinNameAssertEq)}
	assertNeBuiltin       = &BuiltIn{Fn: testingStub(BuiltinNameAssertNe)}
	assertContainsBuiltin = &BuiltIn{Fn: testingStub(BuiltinNameAssertContains)}
	assertErrBuiltin      = &BuiltIn{Fn: testingStub(BuiltinNameAssertErr)}
	assertOkBuiltin       = &BuiltIn{Fn: testingStub(BuiltinNameAssertOk)}
	failBuiltin           = &BuiltIn{Fn: testingStub(BuiltinNameFail)}
)

// testingStub is the answer outside a running program. It is a different
// sentence from higherOrderStub's because the reason is different: `map` cannot
// work outside an executor, while an assertion could compare two values
// perfectly well and would simply have nowhere to file the result -- which is
// the whole of its job.
func testingStub(name string) BuiltinFunction {
	return func(args ...object.Object) object.Object {
		return newError("%s records its result in the run that is executing, so it only works inside a running program", name)
	}
}
