package compiler

import (
	"strings"
	"testing"

	"mutant/code"
	"mutant/lexer"
	"mutant/object"
	"mutant/parser"
)

// compileForAssignTest compiles input and returns the compiler's error, if any.
func compileForAssignTest(t *testing.T, input string) error {
	t.Helper()
	return New().Compile(parser.New(lexer.New(input)).ParseProgram())
}

// Assignment used to branch on two of SymbolScope's five values, so a write to
// a captured variable was emitted as OpSetLocal against the free index -- a
// position in the closure's capture list, not a frame slot. Writing free 0 hit
// local 0, which is normally the first parameter, and the program went on with
// a plausible wrong value and no diagnostic. Tier 1 turned each of these into a
// compile error, because there was nowhere correct to write.
//
// There is now: a captured local lives in a cell that the frame slot and every
// closure over it point at, so each of these compiles again -- and this time to
// a write the enclosing frame can see. The assertion is on the opcodes rather
// than on the answers, which belong in parity/ where both engines are run; what
// is checked here is that the write goes through the cell and not to a slot.
func TestAssigningToACapturedVariableWritesThroughItsCell(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			// The natural accumulator: the write used to reach local 0 of the
			// callback's own frame, so the outer acc stayed 0.
			"accumulating over a callback",
			`let probe = fn() {
  let acc = 0;
  each([1, 2, 3], fn(x) { acc = acc + x; });
  return acc;
};`,
		},
		{
			// The loudest shape. probe(42) returned 7: the write to free 0
			// landed on parameter 0 and destroyed the argument.
			"the write lands on a parameter",
			`let probe = fn(x) {
  let acc = 0;
  let inner = fn(p) { acc = 7; return p; };
  return inner(x);
};`,
		},
		{
			// Two captures over two parameters: probe2(10, 20) returned
			// [777, 888]. The free index is positional, so both arguments went.
			"two captures corrupt two parameters",
			`let probe2 = fn(a, b) {
  let one = 0;
  let two = 0;
  let inner = fn() { one = 777; two = 888; return 0; };
  inner();
  return [a, b];
};`,
		},
		{
			// Not an integer-only defect; the type of the value never mattered.
			"a captured string",
			`let probe = fn() {
  let s = "a";
  each([1], fn(x) { s = "b"; });
  return s;
};`,
		},
		{
			// Two levels deep: the capture is itself a free variable in the
			// middle function. This is the case a fix that only understood one
			// level would miss, and the reason OpCaptureFree exists -- the
			// middle function passes the owner's cell along rather than boxing
			// a second one.
			"captured through two levels",
			`let probe = fn() {
  let acc = 0;
  let mid = fn() {
    let inner = fn() { acc = 5; return 0; };
    inner();
    return 0;
  };
  mid();
  return acc;
};`,
		},
		{
			// The index write-back path resolves the container the same way the
			// plain identifier path does, so it had the same defect.
			"writing through an index into a captured container",
			`let probe = fn() {
  let arr = [1, 2, 3];
  each([1], fn(x) { arr[0] = 9; });
  return arr;
};`,
		},
		{
			// And so did the field write-back path.
			"writing through a field on a captured struct",
			`struct Point { x; y; };
let probe = fn() {
  let p = Point { x: 1, y: 2 };
  each([1], fn(n) { p.x = 9; });
  return p;
};`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New()
			if err := c.Compile(parser.New(lexer.New(tc.src)).ParseProgram()); err != nil {
				t.Fatalf("Compile failed on a write to a captured variable: %s", err)
			}
			emitted := emittedOpcodes(t, c.ByteCode())
			if !emitted[code.OpSetFree] {
				t.Error("no OpSetFree: the write did not go through the captured cell")
			}
			if !emitted[code.OpCaptureLocal] {
				t.Error("no OpCaptureLocal: the variable was captured by value, not boxed")
			}
			if emitted[code.OpSetLocal] && !emitted[code.OpSetLocalCell] {
				t.Error("a plain OpSetLocal survived for what should be a boxed slot")
			}
		})
	}
}

// A read of a captured variable emitted before anything captured it has to be
// rewritten too, and that is the ordering problem the whole design turns on: the
// capture is discovered while the *inner* literal is compiled, by which time the
// enclosing function has already emitted its own accessors. Here `acc` is read
// and written before the closure that captures it exists.
//
// The assertions name slot 0, because the same function also holds `bump` in
// slot 1 -- which nothing captures and which must therefore keep its plain
// accessors. Boxing exactly the captured slots and no others is the point of
// learning them from the symbol table instead of boxing every local.
func TestAccessorsEmittedBeforeTheCaptureAreRewritten(t *testing.T) {
	src := `let probe = fn() {
  let acc = 1;
  acc = acc + 1;
  let bump = fn() { acc = acc + 1; };
  bump();
  return acc;
};`

	c := New()
	if err := c.Compile(parser.New(lexer.New(src)).ParseProgram()); err != nil {
		t.Fatalf("Compile: %s", err)
	}
	slots := slotAccessors(t, c.ByteCode())

	if !slots[code.OpGetLocalCell][0] || !slots[code.OpSetLocalCell][0] {
		t.Error("the accessors emitted before the capture were left as plain local reads and writes")
	}
	if slots[code.OpGetLocal][0] || slots[code.OpSetLocal][0] {
		t.Error("a plain local accessor survived for slot 0, which is boxed")
	}
	if !slots[code.OpSetLocal][1] || !slots[code.OpGetLocal][1] {
		t.Error("slot 1 holds bump, which nothing captures, and must not have been boxed")
	}
}

// slotAccessors reports which local slots each local-accessor opcode names.
// Presence alone is not enough for the boxing question: a function almost
// always has some slots boxed and some not, and the interesting assertion is
// about one slot rather than about the function.
func slotAccessors(t *testing.T, bytecode *ByteCode) map[code.Opcode]map[int]bool {
	t.Helper()
	accessors := map[code.Opcode]map[int]bool{}

	forEachInstruction(t, bytecode, func(op code.Opcode, operands []int) {
		switch op {
		case code.OpGetLocal, code.OpSetLocal, code.OpGetLocalCell, code.OpSetLocalCell, code.OpCaptureLocal:
			if len(operands) != 1 {
				return
			}
			if accessors[op] == nil {
				accessors[op] = map[int]bool{}
			}
			accessors[op][operands[0]] = true
		}
	})
	return accessors
}

// emittedOpcodes reports which opcodes appear anywhere in bytecode.
func emittedOpcodes(t *testing.T, bytecode *ByteCode) map[code.Opcode]bool {
	t.Helper()
	seen := map[code.Opcode]bool{}
	forEachInstruction(t, bytecode, func(op code.Opcode, _ []int) { seen[op] = true })
	return seen
}

// forEachInstruction decodes every stream in bytecode -- the main scope and
// every compiled function in the constant pool -- and calls visit once per
// instruction. It decodes by operand width rather than scanning bytes, because
// an operand can hold any value including one that equals an opcode.
func forEachInstruction(t *testing.T, bytecode *ByteCode, visit func(code.Opcode, []int)) {
	t.Helper()

	streams := []code.Instructions{bytecode.Instructions}
	for _, constant := range bytecode.Constants {
		if fn, ok := constant.(*object.CompiledFunction); ok {
			streams = append(streams, fn.Instructions)
		}
	}

	for _, ins := range streams {
		for ip := 0; ip < len(ins); {
			def, err := code.Lookup(ins[ip])
			if err != nil {
				t.Fatalf("undecodable opcode %d at offset %d", ins[ip], ip)
			}
			operands, read := code.ReadOperands(def, ins[ip+1:])
			visit(code.Opcode(ins[ip]), operands)
			ip += 1 + read
		}
	}
}

// Neither of these is storage, so neither was ever a meaningful assignment.
// Both used to compile: the builtin's registry ordinal and the closure's own
// marker were written as though they were frame slots.
func TestAssigningToSomethingThatIsNotStorageIsRefused(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			// Returned the builtin's Inspect string rather than 5.
			"a builtin",
			`let probe = fn() { len = 5; return len; };`,
			"builtin",
		},
		{
			// probe(42) returned 1: the function's own binding is FunctionScope,
			// whose index is not a slot at all.
			"the function's own name",
			`let f = fn(x) { f = 1; return x; };`,
			"function being defined",
		},
		{
			// The same name reached through a capture. It is a FreeScope symbol
			// at the point of assignment, so it looks exactly like the writes
			// that now succeed -- but its original is the enclosing function's
			// own binding, captured by value with OpCurrentClosure, and there is
			// no cell behind it. Refusing here keeps that from becoming an
			// opaque runtime complaint about a closure.
			"the enclosing function's own name, captured",
			`let f = fn(x) { let g = fn() { f = 1; return 0; }; g(); return x; };`,
			"function being defined",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := compileForAssignTest(t, tc.src)
			if err == nil {
				t.Fatalf("compiled; %s is not something that can be assigned to", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// The refusal is narrow on purpose. Globals and locals are the two scopes that
// were always emitted correctly, and every assignment form has to keep working
// in both -- otherwise the fix costs more than the defect did.
func TestAssignmentStillCompilesForGlobalsAndLocals(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"global identifier", `let acc = 0; acc = acc + 1; acc;`},
		{"local identifier", `let probe = fn() { let acc = 0; acc = acc + 1; return acc; };`},
		{"global index", `let arr = [1, 2, 3]; arr[1] = 9; arr;`},
		{"local index", `let probe = fn() { let arr = [1, 2, 3]; arr[1] = 9; return arr; };`},
		{"global hash index", `let h = {"a": 1}; h["a"] = 2; h;`},
		{"global field", `struct Point { x; y; }; let p = Point { x: 1, y: 2 }; p.x = 9; p;`},
		{
			"local field",
			`struct Point { x; y; };
let probe = fn() { let p = Point { x: 1, y: 2 }; p.x = 9; return p; };`,
		},
		{
			// A capture that is only ever read is untouched by any of this.
			"a captured variable that is only read",
			`let probe = fn() {
  let base = 10;
  let inner = fn(x) { return x + base; };
  return inner(1);
};`,
		},
		{
			// Row D, and the reason the corpus was never affected: a for loop
			// does not capture, so the accumulator stays local.
			"accumulating in a for loop",
			`let probe = fn() {
  let acc = 0;
  for (let i = 0; i < 3; i = i + 1) { acc = acc + i; }
  return acc;
};`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := compileForAssignTest(t, tc.src); err != nil {
				t.Fatalf("Compile failed on an assignment that was always correct: %s", err)
			}
		})
	}
}
