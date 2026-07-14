package vm

import (
	"fmt"
	"mutant/ast"
	"mutant/code"
	"mutant/compiler"
	"mutant/global"
	"mutant/lexer"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
	"mutant/security"
	"strings"
	"testing"
)

type vmTestCase struct {
	input    string
	expected interface{}
}

func runVMTests(t *testing.T, tests []vmTestCase) {
	t.Helper()
	for _, tt := range tests {
		program := parse(tt.input)
		comp := compiler.New()

		if err := comp.Compile(program); err != nil {
			t.Fatalf("compiler error: %s", err)
		}

		byteCode := comp.ByteCode()

		for i, constant := range byteCode.Constants {
			fmt.Printf("CONSTANT %d %p (%T):\n", i, constant, constant)
			switch constant := constant.(type) {
			case *object.CompiledFunction:
				fmt.Printf(" Instructions:\n%s", constant.Instructions)
			case *object.Integer:
				fmt.Printf(" Valie: %d\n", constant.Value)
			}

			fmt.Println()
		}

		password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
		byteCode = mutil.EncryptByteCode(byteCode, password)

		vm := NewWithGlobalStoreAndPassword(byteCode, make([]object.Object, global.GlobalSize), password)
		if err := vm.Run(); err != nil {
			t.Fatalf("vm error: %s", err)
		}

		stackElem := vm.LastPoppedStackElement()
		testExpectedObject(t, tt.expected, stackElem)
	}
}

func runEncryptedVM(input string) (*VM, error) {
	program := parse(input)
	comp := compiler.New()

	if err := comp.Compile(program); err != nil {
		return nil, err
	}

	byteCode := comp.ByteCode()
	password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
	byteCode = mutil.EncryptByteCode(byteCode, password)

	vm := NewWithGlobalStoreAndPassword(byteCode, make([]object.Object, global.GlobalSize), password)
	if err := vm.Run(); err != nil {
		return nil, err
	}

	return vm, nil
}

func parse(input string) *ast.Program {
	l := lexer.New(input)
	p := parser.New(l)

	return p.ParseProgram()
}

func testFoatObject(expected float64, actual object.Object) error {
	result, ok := actual.(*object.Float)

	if !ok {
		return fmt.Errorf("object is not Float. got=%T (%+v)", actual, actual)
	}

	if result.Value != expected {
		return fmt.Errorf("object has wrong value. got=%g, want=%g", result.Value, expected)
	}

	return nil
}

func testIntegerObject(expected int64, actual object.Object) error {
	result, ok := actual.(*object.Integer)

	if !ok {
		return fmt.Errorf("object is not Integer. got=%T (%+v)", actual, actual)
	}

	if result.Value != expected {
		return fmt.Errorf("object has wrong value. got=%d, want=%d", result.Value, expected)
	}

	return nil
}

func testBooleanObject(expected bool, actual object.Object) error {
	result, ok := actual.(*object.Boolean)
	if !ok {
		return fmt.Errorf("object is not Boolean. got=%T (%+v)", actual, actual)
	}

	if result.Value != expected {
		return fmt.Errorf("object has wrong value. got=%t, want=%t", result.Value, expected)
	}

	return nil
}

func testStringObject(expected string, actual object.Object) error {
	result, ok := actual.(*object.String)
	if !ok {
		return fmt.Errorf("object is not String. got=%T (%+v)", actual, actual)
	}

	if result.Value != expected {
		return fmt.Errorf("object has wrong value. got=%q, want=%q", result.Value, expected)
	}

	return nil
}

func testExpectedObject(t *testing.T, expected interface{}, actual object.Object) {
	t.Helper()
	switch expected := expected.(type) {
	case int:
		if err := testIntegerObject(int64(expected), actual); err != nil {
			t.Errorf("testIntegerObject failed: %s", err)
		}
	case bool:
		if err := testBooleanObject(bool(expected), actual); err != nil {
			t.Errorf("testBooleanObject failed: %s", err)
		}
	case string:
		if err := testStringObject(string(expected), actual); err != nil {
			t.Errorf("testStringObject failed: %s", err)
		}
	case []int:
		array, ok := actual.(*object.Array)
		if !ok {
			t.Errorf("object not array: %T (%+v)", actual, actual)
			return
		}
		if len(array.Elements) != len(expected) {
			t.Errorf("wrong number of elements. want=%d, got=%d", len(expected), len(array.Elements))
			return
		}
		for i, expectedElement := range expected {
			if err := testIntegerObject(int64(expectedElement), array.Elements[i]); err != nil {
				t.Errorf("testIntegerObject failed: %s", err)
			}
		}
	case map[object.HashKey]int64:
		hash, ok := actual.(*object.Hash)
		if !ok {
			t.Errorf("object is not Hash. got=%T (%+v)", actual, actual)
			return
		}
		if len(hash.Pairs) != len(expected) {
			t.Errorf("hash has wrong number of pairs, want=%d, got=%d", len(expected), len(hash.Pairs))
			return
		}
		for expectedKey, expectedValue := range expected {
			pair, ok := hash.Pairs[expectedKey]
			if !ok {
				t.Errorf("no pair for given key in the Pairs")
			}
			if err := testIntegerObject(expectedValue, pair.Value); err != nil {
				t.Errorf("testIntegerObject failed: %s", err)
			}
		}
	case *object.Null:
		if actual != global.Null {
			t.Errorf("object is not Null: %T (%+v)", actual, actual)
		}
	case *object.Error:
		errObj, ok := actual.(*object.Error)
		if !ok {
			t.Errorf("object is not Error: %T (%v)", actual, actual)
			return
		}
		if errObj.Message != expected.Message {
			t.Errorf("wrong error message. expected:%q, got:%q", expected.Message, errObj.Message)
		}
	}
}

func TestIntegerArithmatic(t *testing.T) {
	tests := []vmTestCase{
		{"1", 1},
		{"2", 2},
		{"1 + 2", 3},
		{"1 - 2", -1},
		{"1 * 2", 2},
		{"4 / 2", 2},
		{"50 / 2 * 2 + 10 - 5", 55},
		{"5 + 5 + 5 + 5 - 10", 10},
		{"2 * 2 * 2 * 2 * 2", 32},
		{"5 * 2 + 10", 20},
		{"5 + 2 * 10", 25},
		{"5 * (2 + 10)", 60},
		{"-5", -5},
		{"-10", -10},
		{"-50 + 100 + -50", 0},
		{"(5 + 10 * 2 + 15 / 3) * 2 + -10", 50},
	}
	runVMTests(t, tests)
}

func TestResolveVMGlobalMemoryModeDefaultsRuntime(t *testing.T) {
	if got := resolveVMGlobalMemoryMode(); got != vMMemoryModeRuntime {
		t.Fatalf("expected default memory mode runtime, got %q", got)
	}
}

func TestResolveVMGlobalMemoryModeWrapper(t *testing.T) {
	if got := resolveVMGlobalMemoryMode(); got != vMMemoryModeRuntime {
		t.Fatalf("expected deterministic memory mode runtime, got %q", got)
	}
}

func TestWrapperGlobalModeStoresSupportedTypeInSecureWrapper(t *testing.T) {
	vm := New(&compiler.ByteCode{Instructions: code.Instructions{}, Constants: nil})
	vm.memoryMode = vMMemoryModeWrapper

	vm.ensureGlobalCapacity(3)
	vm.setGlobal(3, &object.Integer{Value: 42})

	if _, ok := vm.secureGlobals[3]; !ok {
		t.Fatalf("expected secure wrapper entry for supported global type")
	}
	got := vm.getGlobal(3)
	if err := testIntegerObject(42, got); err != nil {
		t.Fatalf("expected wrapped global roundtrip value, got error: %v", err)
	}
}

func TestWrapperGlobalModeFallsBackForUnsupportedType(t *testing.T) {
	vm := New(&compiler.ByteCode{Instructions: code.Instructions{}, Constants: nil})
	vm.memoryMode = vMMemoryModeWrapper

	vm.ensureGlobalCapacity(1)
	vm.setGlobal(1, &object.Array{Elements: []object.Object{&object.Integer{Value: 1}}})

	if _, ok := vm.secureGlobals[1]; ok {
		t.Fatalf("expected unsupported wrapper type to fall back to runtime storage")
	}
	if vm.globals[1] == nil {
		t.Fatalf("expected fallback global storage value")
	}
}

func TestBooleanExpressions(t *testing.T) {
	tests := []vmTestCase{
		{"true", true},
		{"false", false},
		{"1 < 2", true},
		{"1 > 2", false},
		{"1 < 1", false},
		{"1 > 1", false},
		{"1 == 1", true},
		{"1 != 1", false},
		{"1 == 2", false},
		{"1 != 2", true},
		{"true == true", true},
		{"false == false", true},
		{"true == false", false},
		{"true != false", true},
		{"false != true", true},
		{"(1 < 2) == true", true},
		{"(1 < 2) == false", false},
		{"(1 > 2) == true", false},
		{"(1 > 2) == false", true},
		{"!false", true},
		{"!true", false},
		{"!5", false},
		{"!!true", true},
		{"!!false", false},
		{"!!5", true},
		{"!(if (false) { 5; })", true},
	}
	runVMTests(t, tests)
}

func TestConditionals(t *testing.T) {
	tests := []vmTestCase{
		{"if (true) { 10 }", 10},
		{"if (true) { 10 } else { 20 }", 10},
		{"if (false) { 10 } else { 20 } ", 20},
		{"if (1) { 10 }", 10},
		{"if (1 < 2) { 10 }", 10},
		{"if (1 < 2) { 10 } else { 20 }", 10},
		{"if (1 > 2) { 10 } else { 20 }", 20},
		{"if (1 > 2) { 10 }", global.Null},
		{"if (false) { 10 }", global.Null},
		{"if ((if (false) { 10 })) { 10 } else { 20 }", 20},
	}
	runVMTests(t, tests)
}

func TestGlobalLetStatements(t *testing.T) {
	tests := []vmTestCase{
		{"let one = 1; one", 1},
		{"let one = 1; let two = 2; one + two", 3},
		{"let one = 1; let two = one + one; one + two", 3},
	}
	runVMTests(t, tests)
}

func TestMultiValueReturnStatements(t *testing.T) {
	vm, err := runEncryptedVM("let pair = fn() { return 10, 20; }; pair();")
	if err != nil {
		t.Fatalf("vm run failed: %s", err)
	}

	actual := vm.LastPoppedStackElement()
	multi, ok := actual.(*object.MultiValue)
	if !ok {
		t.Fatalf("object is not MultiValue. got=%T (%+v)", actual, actual)
	}

	if len(multi.Values) != 2 {
		t.Fatalf("wrong number of values. got=%d", len(multi.Values))
	}

	if err := testIntegerObject(10, multi.Values[0]); err != nil {
		t.Fatalf("first value mismatch: %s", err)
	}
	if err := testIntegerObject(20, multi.Values[1]); err != nil {
		t.Fatalf("second value mismatch: %s", err)
	}
}

func TestMultiValueIndexExpressions(t *testing.T) {
	tests := []vmTestCase{
		{"let pair = fn() { return 10, 20; }; pair()[0]", 10},
		{"let pair = fn() { return 10, 20; }; pair()[1]", 20},
		{"let pair = fn() { return 10, 20; }; pair()[2]", global.Null},
	}

	runVMTests(t, tests)
}

func TestLetDestructuringStatements(t *testing.T) {
	tests := []vmTestCase{
		{"let pair = fn() { return 10, 20; }; let a, b = pair(); a", 10},
		{"let pair = fn() { return 10, 20; }; let a, b = pair(); b", 20},
		{"let a, b = 10; b", global.Null},
	}

	runVMTests(t, tests)
}

func TestStringExpressions(t *testing.T) {
	tests := []vmTestCase{
		{`"monkey"`, "monkey"},
		{`"mon" + "key"`, "monkey"},
		{`"mon" + "key" + "banana"`, "monkeybanana"},
	}
	runVMTests(t, tests)
}

func TestArrayLiterals(t *testing.T) {
	tests := []vmTestCase{
		{"[]", []int{}},
		{"[1, 2, 3]", []int{1, 2, 3}},
		{"[1 + 2, 3 * 4, 5 + 6]", []int{3, 12, 11}},
	}
	runVMTests(t, tests)
}

func TestHashLiterals(t *testing.T) {
	tests := []vmTestCase{
		{"{}", map[object.HashKey]int64{}},
		{
			"{1: 2, 2: 3}",
			map[object.HashKey]int64{
				(&object.Integer{Value: 1}).HashKey(): 2,
				(&object.Integer{Value: 2}).HashKey(): 3,
			},
		},
		{
			"{1+1: 2*2, 3+3: 4*4}",
			map[object.HashKey]int64{
				(&object.Integer{Value: 1 + 1}).HashKey(): 2 * 2,
				(&object.Integer{Value: 3 + 3}).HashKey(): 4 * 4,
			},
		},
	}
	runVMTests(t, tests)
}

func TestIndexExpressions(t *testing.T) {
	tests := []vmTestCase{
		{"[1, 2, 3][1]", 2},
		{"[1, 2, 3][0 + 2]", 3},
		{"[[1, 1, 1]][0][0]", 1},
		{"[][0]", global.Null},
		{"[1, 2, 3][99]", global.Null},
		{"[1][-1]", 1},
		{"{1: 1, 2: 2}[1]", 1},
		{"{1: 1, 2: 2}[2]", 2},
		{"{1: 1}[0]", global.Null},
		{"{}[0]", global.Null},
		{`"apple"[0]`, "a"},
		{`"apple"[-1]`, "e"},
	}
	runVMTests(t, tests)
}

func TestCallingFunctionsWithoutArgument(t *testing.T) {
	tests := []vmTestCase{
		{
			input:    "let x = fn(){ 5 + 10; }; x();",
			expected: 15,
		},
		{
			input:    "let o = fn(){1;}; let t = fn(){2;}; o() + t();",
			expected: 3,
		},
		{
			input:    "let a = fn() { 1 }; let b = fn() { a() + 1 }; let c = fn() { b() + 1 }; c();",
			expected: 3,
		},
	}
	runVMTests(t, tests)
}

func TestCallingFunctionsWithReturn(t *testing.T) {
	tests := []vmTestCase{
		{
			input:    "let x = fn(){ return 5 + 10; }; x();",
			expected: 15,
		},
		{
			input:    "let o = fn(){ return 1;}; let t = fn(){ return 2;}; o() + t();",
			expected: 3,
		},
		{
			input:    "let a = fn() { return 1; }; let b = fn() { return a() + 1; }; let c = fn() { return b() + 1; }; c();",
			expected: 3,
		},
	}
	runVMTests(t, tests)
}

func TestFunctionsWithoutReturnValue(t *testing.T) {
	tests := []vmTestCase{
		{input: ` let noReturn = fn() { }; noReturn(); `, expected: global.Null},
		{input: ` let noReturn = fn() { }; let noReturnTwo = fn() { noReturn(); }; noReturn(); noReturnTwo(); `, expected: global.Null},
	}
	runVMTests(t, tests)
}

func TestFirstClassFunctions(t *testing.T) {
	tests := []vmTestCase{
		{
			input:    "let returnsOne = fn() { 1; }; let returnsOneReturner = fn() { returnsOne; }; returnsOneReturner()(); ",
			expected: 1,
		},
	}
	runVMTests(t, tests)
}

func TestCallingFunctionsWithBindings(t *testing.T) {
	tests := []vmTestCase{
		{
			input:    "let one = fn() { let one = 1; one }; one();",
			expected: 1,
		},
		{
			input:    "let oneAndTwo = fn() { let one = 1; let two = 2; one + two; }; oneAndTwo();",
			expected: 3,
		},
		{
			input: `
					let oneAndTwo = fn() { let one = 1; let two = 2; one + two; };
					let threeAndFour = fn() { let three = 3; let four = 4; three + four; };
					oneAndTwo() + threeAndFour();
					`,
			expected: 10,
		},
		{
			input: `
						let firstFoobar = fn() { let foobar = 50; foobar; };
						let secondFoobar = fn() { let foobar = 100; foobar; };
						firstFoobar() + secondFoobar();
					`,
			expected: 150,
		},
		{
			input: `
						let globalSeed = 50;
						let minusOne = fn() { let num = 1; return globalSeed - num; };
						let minusTwo = fn() { let num = 2; return globalSeed - num; };
						minusOne() + minusTwo();
					`,
			expected: 97,
		},
		{
			input:    "let returnsOneReturner = fn() { let returnsOne = fn() { 1; }; returnsOne; }; returnsOneReturner()();",
			expected: 1,
		},
		{
			input: `
						let globalSeed = 50;
						let minusOne = fn() { let num = 50; return globalSeed == num; };
						let minusTwo = fn() { let num = 50; return globalSeed == num; };
						minusOne() == minusTwo();
					`,
			expected: true,
		},
	}
	runVMTests(t, tests)
}

func TestCallingFunctionsWithArgumentsAndBindings(t *testing.T) {
	tests := []vmTestCase{
		{input: "let identity = fn(a) { a; }; identity(4);", expected: 4},
		{input: "let sum = fn(a, b) { a + b; }; sum(1, 2); ", expected: 3},
		{input: "let sum = fn(a, b) { let c = a + b; c; }; sum(1, 2);", expected: 3},
		{input: "let sum = fn(a, b) { let c = a + b; c; }; sum(1, 2) + sum(3, 4);", expected: 10},
		{input: "let sum = fn(a, b) { let c = a + b; c; }; let outer = fn() { sum(1, 2) + sum(3, 4); }; outer();", expected: 10},
		{
			input: `
					let globalNum = 10;
					let sum = fn(a, b) {
						let c = a + b;
						c + globalNum;
					};

					let outer = fn() {
						sum(1, 2) + sum(3, 4) + globalNum;
					};

					outer() + globalNum;
				   `,
			expected: 50,
		},
		{
			input: `
					let pass = "test";
					let testpass = fn(a) {
						return a == pass;
					};

					let ans = "test";
					testpass(ans);
				   `,
			expected: true,
		},
	}
	runVMTests(t, tests)
}

func TestCallingFunctionsWithWrongArguments(t *testing.T) {
	tests := []vmTestCase{
		{input: "fn() { 1; }(1);", expected: "wrong number of arguments. want=0, got=1"},
		{input: "fn(a) { a; }();", expected: "wrong number of arguments. want=1, got=0"},
		{input: "fn(a, b) { a + b; }(1);", expected: "wrong number of arguments. want=2, got=1"},
	}

	for _, tt := range tests {
		program := parse(tt.input)
		comp := compiler.New()

		if err := comp.Compile(program); err != nil {
			t.Fatalf("compiler error: %s", err)
		}

		byteCode := comp.ByteCode()
		password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
		byteCode = mutil.EncryptByteCode(byteCode, password)

		vm := NewWithGlobalStoreAndPassword(byteCode, make([]object.Object, global.GlobalSize), password)

		if err := vm.Run(); err == nil {
			t.Fatalf("expected VM error but resulted in none.")
		} else {
			expected, ok := tt.expected.(string)
			if !ok {
				t.Fatalf("expected string assertion in test case, got=%T", tt.expected)
			}
			if !strings.Contains(err.Error(), expected) {
				t.Fatalf("wrong VM error: want substring=%q, got=%q", expected, err)
			}
		}
	}
}

func TestRuntimeErrorsIncludeInstructionMetadata(t *testing.T) {
	program := parse("fn(a) { a; }();")
	comp := compiler.New()

	if err := comp.Compile(program); err != nil {
		t.Fatalf("compiler error: %s", err)
	}

	byteCode := comp.ByteCode()
	password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
	byteCode = mutil.EncryptByteCode(byteCode, password)

	vm := NewWithGlobalStoreAndPassword(byteCode, make([]object.Object, global.GlobalSize), password)
	err := vm.Run()
	if err == nil {
		t.Fatalf("expected runtime error")
	}
	message := err.Error()
	if !strings.Contains(message, "vm_runtime_error ip=") {
		t.Fatalf("expected runtime metadata in error, got=%q", message)
	}
	if !strings.Contains(message, "op=Opcall") {
		t.Fatalf("expected opcode metadata in error, got=%q", message)
	}
}

func TestBuiltinFunctions(t *testing.T) {
	tests := []vmTestCase{
		{`len([1, 2, 3]);`, 3},
		{`let a = [1, 2, 3]; len(a)`, 3},
		{`len("")`, 0},
		{`len("four")`, 4},
		{`len("hello world")`, 11},
		{`len(1)`, &object.Error{Message: "argument to `len` not supported, got INTEGER"}},
		{`len("one", "two")`, &object.Error{Message: "wrong number of arguments. got=2, want=1"}},
		{`len([])`, 0},
		{`putf("hello", "world!")`, global.Null},
		{`first([1, 2, 3])`, 1},
		{`first([])`, global.Null},
		{`first(1)`, &object.Error{Message: "argument to `first` must be ARRAY, got INTEGER"}},
		{`last([1, 2, 3])`, 3},
		{`last([])`, global.Null},
		{`last(1)`, &object.Error{Message: "argument to `last` must be ARRAY, got INTEGER"}},
		{`rest([1, 2, 3])`, []int{2, 3}},
		{`rest([])`, global.Null},
		{`push([], 1)`, []int{1}},
		{`push(1, 1)`, &object.Error{Message: "argument to `push` must be ARRAY, got=INTEGER"}},
		{`putf("four")`, global.Null},
		{`putln("four")`, global.Null},
	}
	runVMTests(t, tests)
}

func TestEncryptedVMWithDerivedPassword(t *testing.T) {
	vm, err := runEncryptedVM("1")
	if err != nil {
		t.Fatalf("vm error: %s", err)
	}

	if err := testIntegerObject(1, vm.LastPoppedStackElement()); err != nil {
		t.Fatalf("wrong result: %s", err)
	}
}

func TestStackGrowsBeyondInitialCapacity(t *testing.T) {
	vm := &VM{
		stack:        make([]object.Object, 1),
		stackPointer: 0,
		inslen:       1,
	}

	for i := 0; i < 3; i++ {
		if err := vm.push(&object.Integer{Value: int64(i)}); err != nil {
			t.Fatalf("push %d failed: %s", i, err)
		}
	}

	if got := len(vm.stack); got < 3 {
		t.Fatalf("stack did not grow enough: got capacity %d", got)
	}

	if got := vm.stackPointer; got != 3 {
		t.Fatalf("wrong stack pointer: got=%d, want=3", got)
	}

	if err := testIntegerObject(2, vm.pop()); err != nil {
		t.Fatalf("wrong top element after growth: %s", err)
	}
}

func TestGlobalsGrowBeyondInitialCapacity(t *testing.T) {
	vm := &VM{globals: make([]object.Object, 1)}
	vm.ensureGlobalCapacity(3)
	vm.globals[3] = &object.Integer{Value: 99}

	if got := len(vm.globals); got < 4 {
		t.Fatalf("globals did not grow enough: got capacity %d", got)
	}

	if err := testIntegerObject(99, vm.globals[3]); err != nil {
		t.Fatalf("wrong global element after growth: %s", err)
	}
}

func TestEncryptObjectSupportsCompositeRuntimeObjects(t *testing.T) {
	array := &object.Array{Elements: []object.Object{&object.Integer{Value: 7}, &object.Float{Value: 2.5}, global.Null}}
	hashKey := (&object.String{Value: "k"}).HashKey()
	hash := &object.Hash{Pairs: map[object.HashKey]object.HashPair{
		hashKey: {Key: &object.String{Value: "k"}, Value: &object.Integer{Value: 9}},
	}}
	strct := &object.Struct{TypeName: "Point", Fields: map[string]object.Object{"x": &object.Integer{Value: 4}, "y": &object.Integer{Value: 5}}}
	enumVal := &object.EnumValue{TypeName: "Color", Tag: "Green", Value: &object.Integer{Value: 7}}
	closure := &object.Closure{Fn: &object.CompiledFunction{Instructions: []byte{1, 2, 3}}, Free: []object.Object{&object.Integer{Value: 11}, hash}}

	for name, value := range map[string]object.Object{
		"float":   &object.Float{Value: 3.25},
		"null":    global.Null,
		"array":   array,
		"hash":    hash,
		"struct":  strct,
		"enum":    enumVal,
		"closure": closure,
	} {
		enc, err := mutil.EncryptObject(value, 3, "pwd")
		if err != nil {
			t.Fatalf("encrypt %s failed: %s", name, err)
		}
		dec, err := mutil.DecryptObject(enc, 3, "pwd")
		if err != nil {
			t.Fatalf("decrypt %s failed: %s", name, err)
		}
		if dec.Type() != value.Type() {
			t.Fatalf("wrong decrypted %s type: got=%s want=%s", name, dec.Type(), value.Type())
		}
		if name == "closure" {
			decryptedClosure := dec.(*object.Closure)
			if len(decryptedClosure.Free) != 2 {
				t.Fatalf("wrong decrypted closure free count: got=%d want=2", len(decryptedClosure.Free))
			}
			if err := testIntegerObject(11, decryptedClosure.Free[0]); err != nil {
				t.Fatalf("wrong decrypted closure free value: %s", err)
			}
			continue
		}
		if name == "struct" {
			decryptedStruct := dec.(*object.Struct)
			if decryptedStruct.TypeName != "Point" {
				t.Fatalf("wrong decrypted struct type name: got=%s", decryptedStruct.TypeName)
			}
			if err := testIntegerObject(4, decryptedStruct.Fields["x"]); err != nil {
				t.Fatalf("wrong decrypted struct field x: %s", err)
			}
			if err := testIntegerObject(5, decryptedStruct.Fields["y"]); err != nil {
				t.Fatalf("wrong decrypted struct field y: %s", err)
			}
			continue
		}
		if got, want := dec.Inspect(), value.Inspect(); got != want {
			t.Fatalf("wrong decrypted %s: got=%q want=%q", name, got, want)
		}
	}
}

func TestEnumValuesRemainEncryptedAtRest(t *testing.T) {
	vm, err := runEncryptedVM("enum Color { Red, Blue, Green }; let c = Color.Green; c;")
	if err != nil {
		t.Fatalf("vm error: %s", err)
	}

	stored, ok := vm.globals[0].(*object.EnumValue)
	if !ok {
		t.Fatalf("expected stored enum in globals, got=%T", vm.globals[0])
	}

	if stored.TypeName != "Color" || stored.Tag != "Green" {
		t.Fatalf("wrong stored enum identity: got=%s.%s", stored.TypeName, stored.Tag)
	}

	if stored.Value == nil {
		t.Fatalf("expected stored enum payload to be encrypted, got nil")
	}
	if stored.Value.Type() != object.ENCRYPTED_OBJ {
		t.Fatalf("expected stored enum payload to remain encrypted, got=%s", stored.Value.Type())
	}

	last := vm.LastPoppedStackElement()
	dec, ok := last.(*object.EnumValue)
	if !ok {
		t.Fatalf("expected enum result, got=%T", last)
	}

	if dec.TypeName != "Color" || dec.Tag != "Green" {
		t.Fatalf("wrong decrypted enum identity: got=%s.%s", dec.TypeName, dec.Tag)
	}
	decOrdinal, ok := dec.Value.(*object.Integer)
	if !ok {
		t.Fatalf("expected decrypted enum payload integer ordinal, got=%T", dec.Value)
	}
	if decOrdinal.Value != 2 {
		t.Fatalf("wrong decrypted enum ordinal payload: got=%d want=2", decOrdinal.Value)
	}
}

func TestStructFieldsRemainEncryptedAtRest(t *testing.T) {
	vm, err := runEncryptedVM("struct Point { x; y; }; let p = Point { x: 10, y: 20 }; p;")
	if err != nil {
		t.Fatalf("vm error: %s", err)
	}

	storedStruct, ok := vm.stack[vm.stackPointer].(*object.Struct)
	if !ok {
		t.Fatalf("expected stored struct result, got=%T", vm.stack[vm.stackPointer])
	}

	x := storedStruct.Fields["x"]
	y := storedStruct.Fields["y"]
	if x == nil || y == nil {
		t.Fatalf("expected struct fields x and y to exist")
	}

	if x.Type() != object.ENCRYPTED_OBJ {
		t.Fatalf("struct field x stored decrypted: got=%s", x.Type())
	}
	if y.Type() != object.ENCRYPTED_OBJ {
		t.Fatalf("struct field y stored decrypted: got=%s", y.Type())
	}

	decrypted := vm.LastPoppedStackElement()
	point, ok := decrypted.(*object.Struct)
	if !ok {
		t.Fatalf("expected decrypted result to be STRUCT, got=%T", decrypted)
	}

	if err := testIntegerObject(10, point.Fields["x"]); err != nil {
		t.Fatalf("wrong decrypted struct field x: %s", err)
	}
	if err := testIntegerObject(20, point.Fields["y"]); err != nil {
		t.Fatalf("wrong decrypted struct field y: %s", err)
	}
}

func TestStoredGlobalsRemainEncryptedAtRest(t *testing.T) {
	vm, err := runEncryptedVM("let secret = 42; secret;")
	if err != nil {
		t.Fatalf("vm error: %s", err)
	}

	stored := vm.globals[0]
	if stored.Type() != object.ENCRYPTED_OBJ {
		t.Fatalf("global stored decrypted: got=%s", stored.Type())
	}

	if err := testIntegerObject(42, vm.LastPoppedStackElement()); err != nil {
		t.Fatalf("wrong result: %s", err)
	}
}

func TestClosureFreeVarsRemainEncryptedAtRest(t *testing.T) {
	vm, err := runEncryptedVM("let newClosure = fn(a) { fn() { a; }; }; let closure = newClosure(99); closure;")
	if err != nil {
		t.Fatalf("vm error: %s", err)
	}

	closure, ok := vm.stack[vm.stackPointer].(*object.Closure)
	if !ok {
		t.Fatalf("expected stored closure result, got=%T", vm.stack[vm.stackPointer])
	}

	if len(closure.Free) != 1 {
		t.Fatalf("wrong number of free vars: got=%d want=1", len(closure.Free))
	}

	if closure.Free[0].Type() != object.ENCRYPTED_OBJ {
		t.Fatalf("closure free var stored decrypted: got=%s", closure.Free[0].Type())
	}
}

func TestArrayAndHashElementsRemainEncryptedAtRest(t *testing.T) {
	vm, err := runEncryptedVM("let array = [1, 2]; let hash = {" + "\"a\"" + ": 3}; [array, hash];")
	if err != nil {
		t.Fatalf("vm error: %s", err)
	}

	result, ok := vm.stack[vm.stackPointer].(*object.Array)
	if !ok {
		t.Fatalf("expected stored array result, got=%T", vm.stack[vm.stackPointer])
	}

	storedArray, ok := result.Elements[0].(*object.Array)
	if !ok {
		t.Fatalf("expected nested array, got=%T", result.Elements[0])
	}
	if storedArray.Elements[0].Type() != object.ENCRYPTED_OBJ {
		t.Fatalf("array element stored decrypted: got=%s", storedArray.Elements[0].Type())
	}

	storedHash, ok := result.Elements[1].(*object.Hash)
	if !ok {
		t.Fatalf("expected nested hash, got=%T", result.Elements[1])
	}
	for _, pair := range storedHash.Pairs {
		if pair.Key.Type() != object.ENCRYPTED_OBJ {
			t.Fatalf("hash key stored decrypted: got=%s", pair.Key.Type())
		}
		if pair.Value.Type() != object.ENCRYPTED_OBJ {
			t.Fatalf("hash value stored decrypted: got=%s", pair.Value.Type())
		}
	}
}

func TestBuiltinArgsDoNotOverwriteEncryptedStackStorage(t *testing.T) {
	vm, err := runEncryptedVM("len(\"four\")")
	if err != nil {
		t.Fatalf("vm error: %s", err)
	}

	storedArg := vm.stack[0]
	if storedArg == nil {
		t.Fatalf("expected builtin call stack slot to retain prior storage")
	}
	if storedArg.Type() == object.STRING_OBJ {
		t.Fatalf("builtin arg slot overwritten with decrypted string object")
	}
}

func TestCleanupSensitiveDataWipesRuntimeBuffers(t *testing.T) {
	vm, err := runEncryptedVM("let secret = [1, 2, 3]; secret;")
	if err != nil {
		t.Fatalf("vm error: %s", err)
	}

	if vm.stackPointer == 0 {
		t.Fatalf("expected stack to have entries before cleanup")
	}

	vm.CleanupSensitiveData(true)

	if vm.stackPointer != 0 {
		t.Fatalf("stack pointer not reset: got=%d", vm.stackPointer)
	}

	for i, entry := range vm.stack {
		if entry != nil {
			t.Fatalf("stack entry %d not cleared", i)
		}
	}

	for i, c := range vm.constants {
		if c != nil {
			t.Fatalf("constant entry %d not cleared", i)
		}
	}

	for i, g := range vm.globals {
		if g != nil {
			t.Fatalf("global entry %d not cleared", i)
		}
	}
}

func TestCleanupSensitiveDataCanPreserveGlobals(t *testing.T) {
	vm, err := runEncryptedVM("let secret = 42; secret;")
	if err != nil {
		t.Fatalf("vm error: %s", err)
	}

	if vm.globals[0] == nil {
		t.Fatalf("expected global to be populated before cleanup")
	}

	vm.CleanupSensitiveData(false)

	if vm.globals[0] == nil {
		t.Fatalf("global should have been preserved when clearGlobals=false")
	}
}

func TestCleanupSensitiveDataWipesCompiledFunctionInstructions(t *testing.T) {
	compiled := &object.CompiledFunction{Instructions: []byte{1, 2, 3}}
	vm := New(&compiler.ByteCode{
		Instructions: []byte{0},
		Constants:    []object.Object{compiled},
	})

	vm.CleanupSensitiveData(true)

	if compiled.Instructions != nil {
		t.Fatalf("compiled function instructions not cleared")
	}
}

func TestCleanupRuntimeSensitiveDataCanPreserveConstants(t *testing.T) {
	compiled := &object.CompiledFunction{Instructions: []byte{1, 2, 3}}
	vm := New(&compiler.ByteCode{
		Instructions: []byte{0},
		Constants:    []object.Object{compiled},
	})
	vm.stack = []object.Object{&object.Encrypted{EncType: object.INTEGER_OBJ, Value: []byte{1}}}
	vm.stackPointer = 1

	vm.CleanupRuntimeSensitiveData(false, false)

	if vm.stackPointer != 0 {
		t.Fatalf("stack pointer not reset: got=%d", vm.stackPointer)
	}
	if vm.constants[0] == nil {
		t.Fatalf("constant should have been preserved when clearConstants=false")
	}
	if compiled.Instructions == nil {
		t.Fatalf("compiled function instructions should be preserved when clearConstants=false")
	}
}

func TestFramesGrowBeyondInitialCapacity(t *testing.T) {
	mainClosure := &object.Closure{Fn: &object.CompiledFunction{Instructions: []byte{}}}
	vm := &VM{
		frames:     make([]*Frame, 1),
		frameIndex: 1,
	}
	vm.frames[0] = NewFrame(mainClosure, 0)

	nextClosure := &object.Closure{Fn: &object.CompiledFunction{Instructions: []byte{}}}
	vm.pushFrame(NewFrame(nextClosure, 0))

	if got := len(vm.frames); got < 2 {
		t.Fatalf("frames did not grow enough: got capacity %d", got)
	}

	if got := vm.frameIndex; got != 2 {
		t.Fatalf("wrong frame index after growth: got=%d, want=2", got)
	}
}

func TestCallClosureReservesStackForLocals(t *testing.T) {
	vm := New(&compiler.ByteCode{Instructions: []byte{}})
	vm.stack = make([]object.Object, 1)
	vm.stackPointer = 1

	closure := &object.Closure{Fn: &object.CompiledFunction{NumLocals: 4}}
	if err := vm.callClosure(closure, 0); err != nil {
		t.Fatalf("callClosure failed: %s", err)
	}

	if got := len(vm.stack); got < 5 {
		t.Fatalf("stack did not reserve local slots: got capacity %d", got)
	}

	if got := vm.stackPointer; got != 5 {
		t.Fatalf("wrong stack pointer after local reservation: got=%d, want=5", got)
	}
}

func TestClosures(t *testing.T) {
	tests := []vmTestCase{
		{input: "let newClosure = fn(a) { fn() { a; }; }; let closure = newClosure(99); closure();", expected: 99},
		{input: "let newAdder = fn(a, b) { fn(c) { a + b + c }; }; let adder = newAdder(1, 2); adder(8);", expected: 11},
		{input: "let newAdder = fn(a, b) { let c = a + b; fn(d) { c + d }; }; let adder = newAdder(1, 2); adder(8);", expected: 11},
		{
			input: `
					let newAdderOuter = fn(a, b) { let c = a + b; fn(d) { let e = d + c; fn(f) { e + f; }; }; };
					let newAdderInner = newAdderOuter(1, 2); let adder = newAdderInner(3); adder(8);
				`,
			expected: 14,
		},
		{
			input: `
						let a = 1; let newAdderOuter = fn(b) { fn(c) { fn(d) { a + b + c + d }; }; };
						let newAdderInner = newAdderOuter(2); let adder = newAdderInner(3); adder(8);
					`,
			expected: 14,
		},
		{
			input: `
						let newClosure = fn(a, b) { let one = fn() { a; };
						let two = fn() { b; }; fn() { one() + two(); }; };
						let closure = newClosure(9, 90); closure();
					`,
			expected: 99,
		},
	}

	runVMTests(t, tests)
}

func TestRecursiveFunctions(t *testing.T) {
	tests := []vmTestCase{
		{input: "let countDown = fn(x) { if (x == 0) { return 0; } else { countDown(x - 1); } }; countDown(1);", expected: 0},
		{
			input: `
					let countDown = fn(x) { if (x == 0) { return 0; } else { countDown(x - 1); } };
					let wrapper = fn() { countDown(1);}; wrapper();
				`,
			expected: 0,
		},
		{
			input: `
					let wrapper = fn() {

						let countDown = fn(x) {
							if (x == 0) {
								return 0;
							} else {
								countDown(x - 1);
							}
						};

						countDown(1);
					};

					wrapper();
					`,
			expected: 0,
		},
	}

	runVMTests(t, tests)
}

func TestRecursiveFibonacci(t *testing.T) {
	tests := []vmTestCase{
		{
			input: `
		let fibonacci = fn(x) {
			if (x == 0) {
				return 0;
			} else {
				if (x == 1) {
					return 1;
				} else {
					fibonacci(x - 1) + fibonacci(x - 2);
				}
			}
		};
		fibonacci(15);
		`,
			expected: 610,
		},
	}

	runVMTests(t, tests)
}

func TestPhase3LoopStructEnumFeatures(t *testing.T) {
	tests := []vmTestCase{
		{
			input: `
			let sum = 0;
			for (let i = 0; i < 4; i = i + 1) {
				sum = sum + i;
			}
			sum;
			`,
			expected: 6,
		},
		{
			input: `
			let out = 0;
			for (let i = 0; i < 10; i = i + 1) {
				if (i == 5) { break; }
				out = out + i;
			}
			out;
			`,
			expected: 10,
		},
		{
			input: `
			let out = 0;
			for (let i = 0; i < 5; i = i + 1) {
				if (i == 2) { continue; }
				out = out + i;
			}
			out;
			`,
			expected: 8,
		},
		{
			input: `
			struct Point { x; y; }
			let p = Point { x: 10, y: 20 };
			p.x;
			`,
			expected: 10,
		},
		{
			input: `
			struct Point { x; y; }
			let p = Point { x: 10, y: 20 };
			p.y = 99;
			p.y;
			`,
			expected: 99,
		},
		{
			input: `
			enum Color { Red, Blue }
			let c = Color.Red;
			if (c) { 1 } else { 0 };
			`,
			expected: 1,
		},
	}

	runVMTests(t, tests)
}
